package mtproto

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	mathrand "math/rand/v2"

	"golang.org/x/crypto/cryptobyte"

	"github.com/xtls/xray-core/common/errors"
)

// Fake TLS: the client's hello is real-looking TLS whose random field is an
// HMAC of the hello, keyed with the user's secret. The reply proves the server
// knows the secret the same way. No real TLS keys are ever negotiated.
const (
	recordHandshake  = 0x16
	recordCCS        = 0x14
	recordAppData    = 0x17
	recordHeaderSize = 5
	maxRecordPayload = 16384 - recordHeaderSize

	randomOffset = recordHeaderSize + 1 + 3 + 2 // type, uint24 length, version
	randomSize   = 32
	// The last 4 bytes of the random carry a timestamp XORed into the digest.
	digestSize = randomSize - 4

	noiseMinSize = 2500
	noiseMaxSize = 4700
)

type clientHello struct {
	record      []byte
	random      [randomSize]byte
	sessionID   []byte
	cipherSuite uint16
	sni         string
}

// readHelloRecord returns every byte it consumed, so a connection that turns
// out not to be ours can be replayed to the fronting target unchanged.
func readHelloRecord(r *bufio.Reader) ([]byte, error) {
	record := make([]byte, recordHeaderSize)
	n, err := io.ReadFull(r, record)
	record = record[:n]
	if err != nil || record[0] != recordHandshake {
		return record, err
	}

	size := int(binary.BigEndian.Uint16(record[3:recordHeaderSize]))
	if size > maxRecordPayload {
		return record, nil
	}

	record = append(record, make([]byte, size)...)
	n, err = io.ReadFull(r, record[recordHeaderSize:])
	return record[:recordHeaderSize+n], err
}

// parseClientHello returns nil for anything that is not one complete TLS hello.
func parseClientHello(record []byte) *clientHello {
	if len(record) < recordHeaderSize || record[0] != recordHandshake ||
		int(binary.BigEndian.Uint16(record[3:recordHeaderSize])) != len(record)-recordHeaderSize {
		return nil
	}

	message := cryptobyte.String(record[recordHeaderSize:])
	var (
		messageType uint8
		body        cryptobyte.String
		version     uint16
		random      []byte
		sessionID   cryptobyte.String
		suites      cryptobyte.String
		compression cryptobyte.String
		extensions  cryptobyte.String
	)
	if !message.ReadUint8(&messageType) || messageType != 1 ||
		!message.ReadUint24LengthPrefixed(&body) ||
		!body.ReadUint16(&version) ||
		!body.ReadBytes(&random, randomSize) ||
		!body.ReadUint8LengthPrefixed(&sessionID) || len(sessionID) > 32 ||
		!body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&extensions) {
		return nil
	}

	hello := &clientHello{record: record, sessionID: sessionID}
	copy(hello.random[:], random)

	for !suites.Empty() {
		var suite uint16
		if !suites.ReadUint16(&suite) {
			return nil
		}
		// A real server never picks a GREASE value, so echoing one is a fingerprint.
		if hello.cipherSuite == 0 && suite&0x0f0f != 0x0a0a {
			hello.cipherSuite = suite
		}
	}
	if hello.cipherSuite == 0 {
		return nil
	}

	for !extensions.Empty() {
		var (
			extensionType uint16
			extension     cryptobyte.String
		)
		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&extension) {
			return nil
		}
		if extensionType != 0 {
			continue
		}
		var (
			names    cryptobyte.String
			nameType uint8
			name     cryptobyte.String
		)
		if !extension.ReadUint16LengthPrefixed(&names) || !names.ReadUint8(&nameType) ||
			nameType != 0 || !names.ReadUint16LengthPrefixed(&name) {
			return nil
		}
		hello.sni = string(name)
	}
	return hello
}

// zeroedRecord is the hello with its random blanked, which is what gets signed.
func (h *clientHello) zeroedRecord() []byte {
	zeroed := append([]byte(nil), h.record...)
	clear(zeroed[randomOffset : randomOffset+randomSize])
	return zeroed
}

// buildServerHello returns the ServerHello, ChangeCipherSpec and exactly one
// ApplicationData record. Telegram clients sign over those three and reject more.
func buildServerHello(hello *clientHello, secret []byte) ([]byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("failed to generate key share").Base(err)
	}

	body := []byte{3, 3}
	body = append(body, make([]byte, randomSize)...)
	body = append(body, byte(len(hello.sessionID)))
	body = append(body, hello.sessionID...)
	body = binary.BigEndian.AppendUint16(body, hello.cipherSuite)
	body = append(body,
		0x00,       // no compression
		0x00, 0x2e, // 46 bytes of extensions
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
		0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // key_share: x25519, 32 bytes
	)
	body = append(body, key.PublicKey().Bytes()...)

	reply := make([]byte, 0, recordHeaderSize*3+4+len(body)+1+noiseMaxSize)
	reply = appendRecordHeader(reply, recordHandshake, 4+len(body))
	reply = append(reply, 0x02, 0x00, byte(len(body)>>8), byte(len(body)))
	reply = append(reply, body...)
	reply = appendRecordHeader(reply, recordCCS, 1)
	reply = append(reply, 0x01)

	noiseSize := noiseMinSize + mathrand.IntN(noiseMaxSize-noiseMinSize)
	reply = appendRecordHeader(reply, recordAppData, noiseSize)
	noiseStart := len(reply)
	reply = reply[:noiseStart+noiseSize]
	if _, err := rand.Read(reply[noiseStart:]); err != nil {
		return nil, errors.New("failed to generate noise").Base(err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(hello.random[:])
	mac.Write(reply)
	copy(reply[randomOffset:], mac.Sum(nil))
	return reply, nil
}

func appendRecordHeader(out []byte, recordType byte, size int) []byte {
	return append(out, recordType, 3, 3, byte(size>>8), byte(size))
}

// recordReader exposes the payload of the client's ApplicationData records as a stream.
type recordReader struct {
	r    *bufio.Reader
	left int
}

func (r *recordReader) Read(p []byte) (int, error) {
	for r.left == 0 {
		var header [recordHeaderSize]byte
		if _, err := io.ReadFull(r.r, header[:]); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		switch header[0] {
		case recordAppData:
			r.left = size
		case recordCCS:
			if _, err := r.r.Discard(size); err != nil {
				return 0, err
			}
		default:
			return 0, errors.New("unexpected TLS record type ", header[0])
		}
	}
	if len(p) > r.left {
		p = p[:r.left]
	}
	n, err := r.r.Read(p)
	r.left -= n
	return n, err
}
