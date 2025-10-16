package wire

import "fmt"

type BitcoinNet uint32

const (
	// MainNet represents the main bitcoin network.
	MainNet BitcoinNet = 0xd9b4bef9

	// TestNet represents the regression test network.
	TestNet BitcoinNet = 0xdab5bffa

	// TestNet3 represents the test network (version 3).
	TestNet3 BitcoinNet = 0x0709110b

	// TestNet4 represents the test network (version 4).
	TestNet4 BitcoinNet = 0x283f161c

	// SigNet represents the public default SigNet. For custom signets,
	// see CustomSignetParams.
	SigNet BitcoinNet = 0x40CF030A

	// SimNet represents the simulation test network.
	SimNet BitcoinNet = 0x12141c16
)

var bnStrings = map[BitcoinNet]string{
	MainNet:  "MainNet",
	TestNet:  "TestNet",
	TestNet3: "TestNet3",
	TestNet4: "TestNet4",
	SigNet:   "SigNet",
	SimNet:   "SimNet",
}

func (n BitcoinNet) String() string {
	if s, ok := bnStrings[n]; ok {
		return s
	}
	return fmt.Sprintf("Unknown BitcoinNet (%d)", uint32(n))
}

const (
	// ProtocolVersion is the latest protocol version this package supports.
	ProtocolVersion uint32 = 70016

	// MultipleAddressVersion is the protocol version which added multiple
	// addresses per message (pver >= MultipleAddressVersion).
	MultipleAddressVersion uint32 = 209

	// NetAddressTimeVersion is the protocol version which added the
	// timestamp field (pver >= NetAddressTimeVersion).
	NetAddressTimeVersion uint32 = 31402

	// BIP0031Version is the protocol version AFTER which a pong message
	// and nonce field in ping were added (pver > BIP0031Version).
	BIP0031Version uint32 = 60000

	// BIP0035Version is the protocol version which added the mempool
	// message (pver >= BIP0035Version).
	BIP0035Version uint32 = 60002

	// BIP0037Version is the protocol version which added new connection
	// bloom filtering related messages and extended the version message
	// with a relay flag (pver >= BIP0037Version).
	BIP0037Version uint32 = 70001

	// RejectVersion is the protocol version which added a new reject
	// message.
	RejectVersion uint32 = 70002

	// BIP0111Version is the protocol version which added the SFNodeBloom
	// service flag.
	BIP0111Version uint32 = 70011

	// SendHeadersVersion is the protocol version which added a new
	// sendheaders message.
	SendHeadersVersion uint32 = 70012

	// FeeFilterVersion is the protocol version which added a new
	// feefilter message.
	FeeFilterVersion uint32 = 70013

	// AddrV2Version is the protocol version which added two new messages.
	// sendaddrv2 is sent during the version-verack handshake and signals
	// support for sending and receiving the addrv2 message. In the future,
	// new messages that occur during the version-verack handshake will not
	// come with a protocol version bump.
	AddrV2Version uint32 = 70016
)
