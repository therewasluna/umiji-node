package mtproto

import (
	"bytes"
	"encoding/hex"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

const secretSize = 16

// MemoryAccount is an account type converted from Account.
type MemoryAccount struct {
	Secret []byte
	// AdTag is this user's own sponsored channel, or nil to use the inbound's.
	AdTag []byte
}

// AsAccount implements protocol.AsAccount.
func (a *Account) AsAccount() (protocol.Account, error) {
	secret, err := hex.DecodeString(a.GetSecret())
	if err != nil || len(secret) != secretSize {
		return nil, errors.New("mtproto secret must be 32 hex characters")
	}
	adTag, err := parseAdTag(a.GetAdTag())
	if err != nil {
		return nil, err
	}
	return &MemoryAccount{Secret: secret, AdTag: adTag}, nil
}

// parseAdTag returns nil for an empty value, which means no tag.
func parseAdTag(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	tag, err := hex.DecodeString(value)
	if err != nil || len(tag) != adTagSize {
		return nil, errors.New("mtproto adTag must be 32 hex characters")
	}
	return tag, nil
}

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	account, ok := another.(*MemoryAccount)
	return ok && bytes.Equal(a.Secret, account.Secret)
}

// ToProto implements protocol.Account.ToProto().
func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Secret: hex.EncodeToString(a.Secret), AdTag: hex.EncodeToString(a.AdTag)}
}
