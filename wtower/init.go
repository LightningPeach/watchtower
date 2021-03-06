package wtower

import (
	"encoding/binary"
	"encoding/json"
	"io"
)

type InitMessage struct {
}

func NewInitMessage() *InitMessage {
	return &InitMessage{}
}

var _ Message = (*InitMessage)(nil)

func (p *InitMessage) Encode(w io.Writer, pver uint32) error {
	b, err := json.Marshal(p)
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

func (p *InitMessage) Decode(r io.Reader, pver uint32) error {
	var bLen [2]byte
	if _, err := io.ReadFull(r, bLen[:]); err != nil {
		return err
	}
	msgLen := binary.BigEndian.Uint16(bLen[:])

	b := make([]byte, msgLen)
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	return json.Unmarshal(b[:], p)
}

func (p *InitMessage) MsgType() MessageType {
	return InitMsg
}

func (p *InitMessage) MaxPayloadLength(uint32) uint32 {
	return MaxMessagePayload
}
