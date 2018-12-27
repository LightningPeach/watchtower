package wtower

import (
	"encoding/binary"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/shachain"
	"io"
)

// WatchNewChannelMessage is a struct sent by client to server, that contains
// only necessary information of corresponding channeldb.OpenChannel.
type WatchNewChannelMessage struct {
	IdentityPub              *btcec.PublicKey
	FundingOutpoint          wire.OutPoint
	ChainHash                chainhash.Hash
	LocalMultiSigKey         *btcec.PublicKey
	LocalRevocationBasePoint *btcec.PublicKey
	LocalPaymentBasePoint    *btcec.PublicKey
	LocalHtlcBasePoint       *btcec.PublicKey

	RemoteMultiSigKey      *btcec.PublicKey
	RemotePaymentBasePoint *btcec.PublicKey
	RemoteDelayBasePoint   *btcec.PublicKey
	RemoteHtlcBasePoint    *btcec.PublicKey

	FundingTxn     *wire.MsgTx
	IsInitiator    bool
	RemoteCsvDelay uint16
}

func OpenChanFromWatchNewChan(watchNewChannel WatchNewChannelMessage,
	db *channeldb.DB) *channeldb.OpenChannel {

	var b [32]byte
	revocationProducer, _ := shachain.NewRevocationProducerFromBytes(b[:])

	return &channeldb.OpenChannel{
		LocalChanCfg: channeldb.ChannelConfig{
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: watchNewChannel.LocalMultiSigKey,
			},
			RevocationBasePoint: keychain.KeyDescriptor{
				PubKey: watchNewChannel.LocalRevocationBasePoint,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: watchNewChannel.LocalPaymentBasePoint,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: watchNewChannel.LocalHtlcBasePoint,
			},
		},
		RemoteChanCfg: channeldb.ChannelConfig{
			CsvDelay: watchNewChannel.RemoteCsvDelay,
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: watchNewChannel.RemoteMultiSigKey,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: watchNewChannel.RemotePaymentBasePoint,
			},
			DelayBasePoint: keychain.KeyDescriptor{
				PubKey: watchNewChannel.RemoteDelayBasePoint,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: watchNewChannel.RemoteHtlcBasePoint,
			},
		},
		IsInitiator:        watchNewChannel.IsInitiator,
		FundingTxn:         watchNewChannel.FundingTxn,
		IdentityPub:        watchNewChannel.IdentityPub,
		FundingOutpoint:    watchNewChannel.FundingOutpoint,
		RevocationProducer: revocationProducer,
		RevocationStore:    shachain.NewRevocationStore(),
		ChainHash:          watchNewChannel.ChainHash,
		Db:                 db,
	}
}

// NewWatchNewChannelMessage strips out redundant fields of corresponding
// channeldb.OpenChannel and saves the rest in WatchNewChannelMessage struct.
func NewWatchNewChannelMessage(newChan *channeldb.OpenChannel) *WatchNewChannelMessage {
	watchNewChannelMessage := &WatchNewChannelMessage{
		IdentityPub: &btcec.PublicKey{
			X: newChan.IdentityPub.X,
			Y: newChan.IdentityPub.Y,
		},
		FundingOutpoint: newChan.FundingOutpoint,
		ChainHash:       newChan.ChainHash,

		LocalMultiSigKey: &btcec.PublicKey{
			X: newChan.LocalChanCfg.MultiSigKey.PubKey.X,
			Y: newChan.LocalChanCfg.MultiSigKey.PubKey.Y,
		},
		LocalRevocationBasePoint: &btcec.PublicKey{
			X: newChan.LocalChanCfg.RevocationBasePoint.PubKey.X,
			Y: newChan.LocalChanCfg.RevocationBasePoint.PubKey.Y,
		},
		LocalPaymentBasePoint: &btcec.PublicKey{
			X: newChan.LocalChanCfg.PaymentBasePoint.PubKey.X,
			Y: newChan.LocalChanCfg.PaymentBasePoint.PubKey.Y,
		},
		LocalHtlcBasePoint: &btcec.PublicKey{
			X: newChan.LocalChanCfg.HtlcBasePoint.PubKey.X,
			Y: newChan.LocalChanCfg.HtlcBasePoint.PubKey.Y,
		},

		RemoteMultiSigKey: &btcec.PublicKey{
			X: newChan.RemoteChanCfg.MultiSigKey.PubKey.X,
			Y: newChan.RemoteChanCfg.MultiSigKey.PubKey.Y,
		},
		RemotePaymentBasePoint: &btcec.PublicKey{
			X: newChan.RemoteChanCfg.PaymentBasePoint.PubKey.X,
			Y: newChan.RemoteChanCfg.PaymentBasePoint.PubKey.Y,
		},
		RemoteDelayBasePoint: &btcec.PublicKey{
			X: newChan.RemoteChanCfg.DelayBasePoint.PubKey.X,
			Y: newChan.RemoteChanCfg.DelayBasePoint.PubKey.Y,
		},
		RemoteHtlcBasePoint: &btcec.PublicKey{
			X: newChan.RemoteChanCfg.HtlcBasePoint.PubKey.X,
			Y: newChan.RemoteChanCfg.HtlcBasePoint.PubKey.Y,
		},
		FundingTxn:     newChan.FundingTxn,
		IsInitiator:    newChan.IsInitiator,
		RemoteCsvDelay: newChan.RemoteChanCfg.CsvDelay,
	}
	return watchNewChannelMessage
}

var _ Message = (*WatchNewChannelMessage)(nil)

func (wc *WatchNewChannelMessage) Encode(w io.Writer, pver uint32) error {
	b, err := json.Marshal(wc)
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

func (wc *WatchNewChannelMessage) Decode(r io.Reader, pver uint32) error {
	var bLen [2]byte
	if _, err := io.ReadFull(r, bLen[:]); err != nil {
		return err
	}
	msgLen := binary.BigEndian.Uint16(bLen[:])

	b := make([]byte, msgLen)
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	return json.Unmarshal(b[:], wc)
}

func (wc *WatchNewChannelMessage) MsgType() MessageType {
	return WatchNewChannelMsg
}

func (wc *WatchNewChannelMessage) MaxPayloadLength(uint32) uint32 {
	return MaxMessagePayload
}
