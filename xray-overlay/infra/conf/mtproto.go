package conf

import (
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mtproto"
)

// Registered here rather than in xray.go, so this overlay never conflicts with upstream.
func init() {
	inboundConfigLoader.cache["mtproto"] = func() interface{} { return new(MTProtoServerConfig) }
}

type MTProtoClientConfig struct {
	Email  string `json:"email"`
	Level  byte   `json:"level"`
	Secret string `json:"secret"`
	AdTag  string `json:"adTag"`
}

type MTProtoServerConfig struct {
	Clients []*MTProtoClientConfig `json:"clients"`
	Domain  string                 `json:"domain"`
	Target  string                 `json:"target"`
	// The inbound's sponsored channel, for users without their own.
	AdTag    string `json:"adTag"`
	PublicIP string `json:"publicIp"`
}

func (c *MTProtoServerConfig) Build() (proto.Message, error) {
	if c.Domain == "" {
		return nil, errors.New(`MTProto: "domain" is required`)
	}

	config := &mtproto.ServerConfig{
		Users:    make([]*protocol.User, len(c.Clients)),
		Domain:   c.Domain,
		Target:   c.Target,
		AdTag:    c.AdTag,
		PublicIp: c.PublicIP,
	}
	for i, client := range c.Clients {
		config.Users[i] = &protocol.User{
			Email:   client.Email,
			Level:   uint32(client.Level),
			Account: serial.ToTypedMessage(&mtproto.Account{Secret: client.Secret, AdTag: client.AdTag}),
		}
	}
	return config, nil
}
