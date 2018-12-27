package wtower

import (
	"encoding/binary"
	"encoding/json"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnwallet"
	"io"
)

type AddRevocationDataMessage struct {
	Height          uint64
	FundingOutpoint wire.OutPoint
	EncryptedData   []byte
}

func NewAddRevocationDataMessage(height uint64, fundingOutpoint wire.OutPoint,
	revocationData *lnwallet.RevocationData) (*AddRevocationDataMessage, error) {

	encryptedData, err := revocationData.Encrypt(0)
	if err != nil {
		return nil, err
	}
	revocationDataMessage := &AddRevocationDataMessage{
		Height:          height,
		FundingOutpoint: fundingOutpoint,
		EncryptedData:   encryptedData,
	}
	return revocationDataMessage, nil
}

var _ Message = (*AddRevocationDataMessage)(nil)

func (ar *AddRevocationDataMessage) Encode(w io.Writer, pver uint32) error {
	b, err := json.Marshal(ar)
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

func (ar *AddRevocationDataMessage) Decode(r io.Reader, pver uint32) error {
	var bLen [2]byte
	if _, err := io.ReadFull(r, bLen[:]); err != nil {
		return err
	}
	msgLen := binary.BigEndian.Uint16(bLen[:])

	b := make([]byte, msgLen)
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	return json.Unmarshal(b[:], ar)
}

func (ar *AddRevocationDataMessage) MsgType() MessageType {
	return AddRevocationDataMsg
}

func (ar *AddRevocationDataMessage) MaxPayloadLength(uint32) uint32 {
	return MaxMessagePayload
}
