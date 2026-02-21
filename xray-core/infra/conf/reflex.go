package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

type ReflexUserConfig struct {
	ID     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

type ReflexInboundConfig struct {
	Clients  []ReflexUserConfig    `json:"clients"`
	Fallback *ReflexFallbackConfig `json:"fallback"`
}

func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	out := &reflex.InboundConfig{}

	for _, u := range c.Clients {
		// validate UUID like other protocols do
		uid, err := uuid.ParseString(u.ID)
		if err != nil {
			return nil, errors.New("Reflex clients: invalid id").Base(err)
		}

		out.Clients = append(out.Clients, &reflex.User{
			Id:     uid.String(),
			Policy: u.Policy,
		})
	}

	if c.Fallback != nil {
		out.Fallback = &reflex.Fallback{Dest: c.Fallback.Dest}
	}

	return out, nil
}

type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	ID      string `json:"id"`
}

func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	out := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
	}

	if c.ID != "" {
		uid, err := uuid.ParseString(c.ID)
		if err != nil {
			return nil, errors.New("Reflex outbound: invalid id").Base(err)
		}
		out.Id = uid.String()
	}

	return out, nil
}
