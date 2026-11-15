package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Obfuscated2: a 64-byte frame opens each direction of the stream. Bytes 8-39
// are key material, 40-55 the IV, and the rest (protocol tag, DC) is encrypted.
// https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
const (
	frameSize     = 64
	frameKeyStart = 8
	frameIVStart  = 40
	frameTagStart = 56
	frameDCStart  = 60

	defaultDC = 2
)

// shortcut: fixed IPv4 addresses, so IPv6-only nodes can't reach Telegram. Fetch
// help.getConfig and try several addresses if Telegram ever moves these.
var dcAddresses = map[int]net.Address{
	1:   net.ParseAddress("149.154.175.50"),
	2:   net.ParseAddress("149.154.167.51"),
	3:   net.ParseAddress("149.154.175.100"),
	4:   net.ParseAddress("149.154.167.91"),
	5:   net.ParseAddress("149.154.171.5"),
	203: net.ParseAddress("91.105.192.100"),
}

func isProtocolTag(tag []byte) bool {
	return tag[0] == tag[1] && tag[1] == tag[2] && tag[2] == tag[3] &&
		(tag[0] == 0xdd || tag[0] == 0xee || tag[0] == 0xef)
}

func newStream(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // the key is always 32 bytes
	}
	return cipher.NewCTR(block, iv)
}

// reversedKeyMaterial gives the key and IV of the opposite direction.
func reversedKeyMaterial(frame *[frameSize]byte) (key, iv []byte) {
	reversed := slices.Clone(frame[frameKeyStart:frameTagStart])
	slices.Reverse(reversed)
	return reversed[:frameIVStart-frameKeyStart], reversed[frameIVStart-frameKeyStart:]
}

func mixSecret(key, secret []byte) []byte {
	sum := sha256.Sum256(append(slices.Clone(key), secret...))
	return sum[:]
}

// openClientFrame derives both client stream ciphers and reads what the client asked for.
func openClientFrame(frame *[frameSize]byte, secret []byte) (decrypt, encrypt cipher.Stream, tag []byte, dc int, err error) {
	decrypt = newStream(mixSecret(frame[frameKeyStart:frameIVStart], secret), frame[frameIVStart:frameTagStart])
	key, iv := reversedKeyMaterial(frame)
	encrypt = newStream(mixSecret(key, secret), iv)

	var plain [frameSize]byte
	decrypt.XORKeyStream(plain[:], frame[:])
	tag = slices.Clone(plain[frameTagStart:frameDCStart])
	if !isProtocolTag(tag) {
		return nil, nil, nil, 0, errors.New("invalid protocol tag")
	}
	return decrypt, encrypt, tag, int(int16(binary.LittleEndian.Uint16(plain[frameDCStart:]))), nil
}

// newDCFrame opens a fresh stream to Telegram. Only the tag and DC differ from random.
func newDCFrame(tag []byte, dc int) (wire [frameSize]byte, encrypt, decrypt cipher.Stream, err error) {
	for {
		if _, err = rand.Read(wire[:]); err != nil {
			return wire, nil, nil, errors.New("failed to generate frame").Base(err)
		}
		if isValidFrameStart(wire[:8]) {
			break
		}
	}
	copy(wire[frameTagStart:], tag)
	binary.LittleEndian.PutUint16(wire[frameDCStart:], uint16(int16(dc)))

	encrypt = newStream(wire[frameKeyStart:frameIVStart], wire[frameIVStart:frameTagStart])
	key, iv := reversedKeyMaterial(&wire)
	decrypt = newStream(key, iv)

	var encrypted [frameSize]byte
	encrypt.XORKeyStream(encrypted[:], wire[:])
	copy(wire[frameTagStart:], encrypted[frameTagStart:])
	return wire, encrypt, decrypt, nil
}

// isValidFrameStart rejects openings Telegram would read as another transport.
func isValidFrameStart(start []byte) bool {
	if start[0] == 0xef {
		return false
	}
	switch binary.LittleEndian.Uint32(start) {
	case 0x44414548, // HEAD
		0x54534f50, // POST
		0x20544547, // GET
		0x4954504f, // OPTI
		0x02010316, // TLS
		0xdddddddd,
		0xeeeeeeee:
		return false
	}
	return binary.LittleEndian.Uint32(start[4:]) != 0
}

// dcDestination keeps a media DC's negative sign in the id sent to Telegram,
// while both kinds of DC share an address.
func dcDestination(dc int) (net.Destination, int) {
	id := dc
	if id < 0 {
		id = -id
	}
	address, ok := dcAddresses[id]
	if !ok {
		address = dcAddresses[defaultDC]
		if dc < 0 {
			dc = -defaultDC
		} else {
			dc = defaultDC
		}
	}
	return net.TCPDestination(address, net.Port(443)), dc
}
