package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig

	nonceMu sync.Mutex
	seen    map[[16]byte]int64 // nonce -> timestamp (unix)
}

// MemoryAccount برای ذخیره اطلاعات کاربر
// باید protocol.Account interface رو implement کنه
type MemoryAccount struct {
	Id string
}

// Equals implements protocol.Account
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

// ToProto implements protocol.Account
func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(userID).String()

	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found")
}

func (h *Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn net.Conn, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	peek4, err := reader.Peek(4)
	if err == nil && len(peek4) == 4 {
		magic := binary.BigEndian.Uint32(peek4[0:4])
		if magic == reflex.ReflexMagic {
			return h.handleReflexMagic(reader, conn, dispatcher, ctx)
		}
	}

	peek5, err := reader.Peek(5)
	if err == nil && len(peek5) == 5 {
		if h.isHTTPPostLike(peek5) {
			return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
		}
	}

	return h.handleFallback(ctx, reader, conn)
}

func (h *Handler) isHTTPPostLike(peeked []byte) bool {
	return len(peeked) >= 5 && string(peeked[:5]) == "POST "
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (interface{}, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0),
		seen:    make(map[[16]byte]int64),
	}

	// تبدیل config به handler
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	// تنظیم fallback اگر وجود داشته باشه
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}

func (h *Handler) handleReflexMagic(reader *bufio.Reader, conn net.Conn, dispatcher routing.Dispatcher, ctx context.Context) error {
	// خواندن ۴ بایت magic
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	clientHS, err := readClientHandshake(reader)
	if err != nil {
		return errors.New("reflex: failed to read client handshake").Base(err)
	}

	return h.processHandshake(reader, conn, dispatcher, ctx, clientHS)
}

func (h *Handler) validateReplay(ts int64, nonce [16]byte) error {
	now := time.Now().Unix()

	// 1) timestamp window: ±120s
	if ts < now-120 || ts > now+120 {
		return errors.New("reflex: timestamp out of window").AtWarning()
	}

	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()

	if h.seen == nil {
		h.seen = make(map[[16]byte]int64)
	}

	const ttl int64 = 300
	for k, t0 := range h.seen {
		if t0 < now-ttl {
			delete(h.seen, k)
		}
	}

	if _, ok := h.seen[nonce]; ok {
		return errors.New("reflex: replay detected (nonce reused)").AtWarning()
	}

	h.seen[nonce] = now
	return nil
}

func (h *Handler) processHandshake(reader *bufio.Reader, conn net.Conn, dispatcher routing.Dispatcher, ctx context.Context, clientHS reflex.ClientHandshake) error {
	_ = reader
	_ = dispatcher
	_ = ctx

	// 1) کلید موقت سرور
	serverPrivateKey, serverPublicKey := reflex.GenerateKeyPair()

	// 2) shared key
	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)

	// 3) session key
	sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))
	// 4) auth

	if err := h.validateReplay(clientHS.Timestamp, clientHS.Nonce); err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		return h.handleFallback(ctx, reader, conn)
	}

	_ = reflex.ServerHandshake{
		PublicKey:   serverPublicKey,
		PolicyGrant: []byte{},
	}

	payload := fmt.Sprintf(`{"serverPublicKey":"%x"}`, serverPublicKey[:])
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + payload
	_, _ = conn.Write([]byte(resp))

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn net.Conn,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	_ = ctx
	_ = dispatcher
	_ = user

	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return errors.New("reflex: NewSession failed").Base(err).AtError()
	}

	for {
		frame, err := session.ReadFrame(reader)
		if err != nil {
			return err
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			// فعلاً echo برای تست Step3
			if err := session.WriteFrame(conn, reflex.FrameTypeData, frame.Payload); err != nil {
				return err
			}
			continue

		case reflex.FrameTypePadding:
			continue

		case reflex.FrameTypeTiming:
			continue

		case reflex.FrameTypeClose:
			return nil

		default:
			return errors.New("reflex: unknown frame type").AtWarning()
		}
	}
}
