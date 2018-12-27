package wtower

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/lnwire"
)

// WTMessageType is an enum that encompasses all possible message types
// we'll pass to the watchtower.
type MessageType uint16

const (
	WatchNewChannelMsg   MessageType = 700
	AddRevocationDataMsg             = 702
	PingMsg                          = 703
	PongMsg                          = 704
	InitMsg                          = 705
	StatesMsg                        = 706
)

type PubKey [btcec.PubKeyBytesLenCompressed]byte

func (pKey PubKey) FromPublicKey(publicKey *btcec.PublicKey) {
	compressedLen := btcec.PubKeyBytesLenCompressed
	copy(pKey[:compressedLen], publicKey.SerializeCompressed())
}

func (t MessageType) String() string {
	switch t {
	case WatchNewChannelMsg:
		return "WatchNewChannel"
	case AddRevocationDataMsg:
		return "AddRevocationData"
	case PingMsg:
		return "Ping"
	case PongMsg:
		return "Pong"
	case InitMsg:
		return "Init"
	case StatesMsg:
		return "Intervals"
	default:
		return "<unknown>"
	}
}

// UnknownMessage is an implementation of the error interface that allows the
// creation of an error in response to an unknown message.
type UnknownMessage struct {
	messageType MessageType
}

// Error returns a human readable string describing the error.
//
// This is part of the error interface.
func (u *UnknownMessage) Error() string {
	return fmt.Sprintf("unable to parse message of unknown type: %v",
		u.messageType)
}

type Serializable = lnwire.Serializable

type Message interface {
	Serializable
	// MsgType returns a MessageType that uniquely identifies the message to
	// be encoded.
	MsgType() MessageType
	// MaxMessagePayload is the maximum serialized length that a particular
	// message type can take.
	MaxPayloadLength(uint32) uint32
}
