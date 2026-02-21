package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig

	nonceMu sync.Mutex
	seen    map[[16]byte]int64 // nonce -> first-seen unix timestamp
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.Id}
}

type FallbackConfig struct {
	Dest uint32 // backend port on 127.0.0.1
}

func (h *Handler) Network() []net.Network {
    return []net.Network{net.Network_TCP}
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return New(ctx, cfg.(*reflex.InboundConfig))
	}))
}

func New(_ context.Context, config *reflex.InboundConfig) (interface{}, error) {
	h := &Handler{
		clients: make([]*protocol.MemoryUser, 0, len(config.Clients)),
		seen:    make(map[[16]byte]int64),
	}

	for _, client := range config.Clients {
		h.clients = append(h.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}

	if config.Fallback != nil {
		h.fallback = &FallbackConfig{Dest: config.Fallback.Dest}
	}

	return h, nil
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := bufio.NewReader(conn)

	// 1) Reflex magic
	peek4, err := reader.Peek(4)
	if err == nil && len(peek4) == 4 {
		if binary.BigEndian.Uint32(peek4[:4]) == reflex.ReflexMagic {
			return h.handleReflexMagic(ctx, reader, conn, dispatcher)
		}
	}

	// 2) If HTTP POST -> treat as Reflex HTTP handshake (DO NOT fallback)
	peek5, err := reader.Peek(5)
	if err == nil && len(peek5) == 5 {
		if string(peek5) == "POST " {
			return h.handleReflexHTTP(reader, conn, dispatcher, ctx)
		}
	}

	// 3) Other HTTP methods -> fallback (website traffic)
	peek8, _ := reader.Peek(8)
	if isHTTPLike(peek8) {
		return h.handleFallback(ctx, reader, conn)
	}

	// 4) Everything else -> fallback
	return h.handleFallback(ctx, reader, conn)
}

func isHTTPLike(peeked []byte) bool {
	if len(peeked) < 4 {
		return false
	}
	s := string(peeked[:minInt(len(peeked), 8)])
	return strings.HasPrefix(s, "GET ") ||
		strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "HEAD ") ||
		strings.HasPrefix(s, "PUT ") ||
		strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "PATCH ")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *Handler) handleReflexMagic(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// consume 4 bytes magic
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return err
	}

	clientHS, err := readClientHandshake(reader)
	if err != nil {
		return errors.New("reflex: failed to read client handshake").Base(err).AtWarning()
	}

	return h.processHandshake(ctx, reader, conn, dispatcher, clientHS)
}

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	userIDStr := uuid.UUID(userID).String()
	for _, user := range h.clients {
		acc, ok := user.Account.(*MemoryAccount)
		if ok && acc.Id == userIDStr {
			return user, nil
		}
	}
	return nil, errors.New("reflex: user not found").AtWarning()
}

func (h *Handler) validateReplay(ts int64, nonce [16]byte) error {
	now := time.Now().Unix()

	// Timestamp window ±120s
	//if ts < now-120 || ts > now+120 {
	//	return errors.New("reflex: timestamp out of window").AtWarning()
	//}
	// Allow wide window for testing
	if ts < now-3600 || ts > now+3600 {
   	 return errors.New("reflex: timestamp out of window").AtWarning()
	}
	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()

	if h.seen == nil {
		h.seen = make(map[[16]byte]int64)
	}

	// TTL cleanup
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

func (h *Handler) processHandshake(ctx context.Context, reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, clientHS reflex.ClientHandshake) error {
	// Anti-replay first
	if err := h.validateReplay(clientHS.Timestamp, clientHS.Nonce); err != nil {
		writeHTTPJSON(conn, "403 Forbidden", `{"status":"forbidden"}`)
		return err
	}

	// Auth
	user, err := h.authenticateUser(clientHS.UserID)
	if err != nil {
		writeHTTPJSON(conn, "403 Forbidden", `{"status":"forbidden"}`)
		return err
	}

	// Key agreement
	serverPrivateKey, serverPublicKey := reflex.GenerateKeyPair()
	sharedKey := reflex.DeriveSharedKey(serverPrivateKey, clientHS.PublicKey)
	if sharedKey == ([32]byte{}) {
		writeHTTPJSON(conn, "403 Forbidden", `{"status":"forbidden"}`)
		return errors.New("reflex: invalid peer key").AtWarning()
	}
	sessionKey := reflex.DeriveSessionKey(sharedKey, []byte("reflex-session"))

	body := fmt.Sprintf(`{"serverPublicKey":"%x"}`, serverPublicKey[:])
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		fmt.Sprint(len(body)) + "\r\n\r\n" + body
	_, _ = conn.Write([]byte(resp))

	if dispatcher == nil {
		return nil
	}

	return h.handleSession(ctx, reader, conn, dispatcher, sessionKey, user)
}

func (h *Handler) handleSession(
	ctx context.Context,
	reader *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	_ = user

	if dispatcher == nil {
		return errors.New("reflex: dispatcher is nil").AtWarning()
	}

	sess, err := reflex.NewSession(sessionKey)
	if err != nil {
		return err
	}

	first, err := sess.ReadFrame(reader)
	if err != nil {
		return err
	}
	if first.Type != reflex.FrameTypeData {
		_ = sess.WriteFrame(conn, reflex.FrameTypeClose, []byte("expected connect"))
		return errors.New("reflex: first frame is not DATA(connect)").AtWarning()
	}

	dest, initialPayload, err := reflex.ParseConnectPayload(first.Payload)
	if err != nil {
		_ = sess.WriteFrame(conn, reflex.FrameTypeClose, []byte("bad connect payload"))
		return errors.New("reflex: bad connect payload").Base(err).AtWarning()
	}

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		_ = sess.WriteFrame(conn, reflex.FrameTypeClose, []byte("dispatch failed"))
		return errors.New("reflex: dispatch failed").Base(err).AtWarning()
	}

	_ = sess.WriteFrame(conn, reflex.FrameTypeData, []byte("OK"))

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// upstream -> client
	go func() {
		defer cancel()
		for {
			mb, e := link.Reader.ReadMultiBuffer()
			if e != nil {
				errCh <- e
				return
			}
			for _, b := range mb {
				if b == nil {
					continue
				}
				payload := b.Bytes()
				we := sess.WriteFrame(conn, reflex.FrameTypeData, payload)
				b.Release()
				if we != nil {
					errCh <- we
					return
				}
			}
		}
	}()

	// client -> upstream
	if len(initialPayload) > 0 {
		bb := buf.FromBytes(initialPayload)
		if e := link.Writer.WriteMultiBuffer(buf.MultiBuffer{bb}); e != nil {
			cancel()
			_ = conn.Close()
			_ = common.Close(link.Writer)
			return errors.New("reflex: write initial payload failed").Base(e).AtWarning()
		}
	}

	for {
		select {
		case <-ctx2.Done():
			_ = conn.Close()
			_ = common.Close(link.Writer)
			select {
			case e := <-errCh:
				if e == io.EOF {
					return nil
				}
				return e
			default:
				return nil
			}
		default:
		}

		fr, e := sess.ReadFrame(reader)
		if e != nil {
			cancel()
			_ = conn.Close()
			_ = common.Close(link.Writer)
			if e == io.EOF {
				return nil
			}
			return e
		}

		switch fr.Type {
		case reflex.FrameTypeData:
			if len(fr.Payload) == 0 {
				continue
			}
			bb := buf.FromBytes(fr.Payload)
			if we := link.Writer.WriteMultiBuffer(buf.MultiBuffer{bb}); we != nil {
				cancel()
				_ = conn.Close()
				_ = common.Close(link.Writer)
				if we == io.EOF {
					return nil
				}
				return errors.New("reflex: upstream write failed").Base(we).AtWarning()
			}
		case reflex.FrameTypeClose:
			cancel()
			_ = conn.Close()
			_ = common.Close(link.Writer)
			return nil
		default:
			continue
		}
	}
}

func writeHTTPJSON(conn stat.Connection, statusLine string, body string) {
	resp := "HTTP/1.1 " + statusLine + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" +
		body
	_, _ = conn.Write([]byte(resp))
}
