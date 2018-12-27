package wtower

import (
	"encoding/binary"
	"encoding/json"
	"github.com/btcsuite/btcd/wire"
	"io"
)

type StatesMessage struct {
	Intervals    []uint64
	ChannelPoint wire.OutPoint
}

func NewStatesMessage(intervals []uint64, chanPoint wire.OutPoint) *StatesMessage {
	return &StatesMessage{
		Intervals:    intervals,
		ChannelPoint: chanPoint,
	}
}

var _ Message = (*StatesMessage)(nil)

func (s *StatesMessage) Encode(w io.Writer, pver uint32) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	msgLen := uint16(len(b))

	var bLen [2]byte
	binary.BigEndian.PutUint16(bLen[:], msgLen)
	if _, err := w.Write(bLen[:]); err != nil {
		return err
	}

	w.Write(b[:])
	return nil
}

func (s *StatesMessage) Decode(r io.Reader, pver uint32) error {
	var bLen [2]byte
	if _, err := io.ReadFull(r, bLen[:]); err != nil {
		return err
	}
	msgLen := binary.BigEndian.Uint16(bLen[:])

	b := make([]byte, msgLen)
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	return json.Unmarshal(b[:], s)
}

func (s *StatesMessage) MsgType() MessageType {
	return StatesMsg
}

func (s *StatesMessage) MaxPayloadLength(uint32) uint32 {
	return MaxMessagePayload
}
