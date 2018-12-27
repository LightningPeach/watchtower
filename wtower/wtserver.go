package wtower

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"net"
	"sync"
)

type ServerConfig struct {
	Db        *channeldb.DB
	ChainHash chainhash.Hash
	PublishTx func(tx *wire.MsgTx) error
}

type WTServer struct {
	mu                sync.RWMutex
	cfg               *ServerConfig
	breachInfoReqChan chan *lnwallet.BreachInfoReq
	WatchtowerPeers   map[string]*WtPeer
	Listeners         []net.Addr
	ParseAddr         func(address string) (net.Addr, error)
	Net               wire.BitcoinNet
	ConnMgr           *connmgr.ConnManager

	// WatchNewChannel creates new channel watcher and saves related data to db.
	WatchNewChannel func(*channeldb.OpenChannel, *btcec.PublicKey) ([]uint64, error)

	// SaveEncryptedRevocation inserts encrypted revocation data to chainwatcher's
	// revocationData map and saves it to database for future recovery.
	SaveEncryptedRevocation func(uint64, wire.OutPoint,
		[]byte, *btcec.PublicKey) error

	LightningChannelFromOutPoint func(outPoint wire.OutPoint) (*lnwallet.LightningChannel, error)

	quit chan struct{}
}

func NewServer(cfg *ServerConfig, listeners []net.Addr) *WTServer {
	return &WTServer{
		cfg:               cfg,
		breachInfoReqChan: make(chan *lnwallet.BreachInfoReq, 1),
		WatchtowerPeers:   make(map[string]*WtPeer),
		Listeners:         listeners,
		quit:              make(chan struct{}),
	}
}

func (wts *WTServer) IsServer() bool {
	// Node is a watchtower server iff it has at least one
	// interface/port to listen for watchtower peer connections.
	return len(wts.Listeners) > 0
}

func (wts *WTServer) IsClient() bool {
	// Node can be either a watchtower server or a watchtower client.
	return !wts.IsServer()
}

func (wts *WTServer) Start() error {
	wts.ConnMgr.Start()
	peers, err := wts.cfg.Db.FetchPeers(wts.cfg.ChainHash, wts.ParseAddr)
	if err != nil {
		return err
	}
	for pubHex, addr := range peers {
		go func() {
			pubkeyHex, err := hex.DecodeString(pubHex)
			if err != nil {
				return
			}
			pubKey, err := btcec.ParsePubKey(pubkeyHex, btcec.S256())
			if err != nil {
				return
			}

			watchtowerAddr := &lnwire.NetAddress{
				IdentityKey: pubKey,
				Address:     addr,
				ChainNet:    wts.Net,
			}
			connReq := &connmgr.ConnReq{
				Addr:      watchtowerAddr,
				Permanent: true,
			}

			// Add this peer so it will show up as inactive in case
			// we fail to connect.
			wts.mu.RLock()
			wts.WatchtowerPeers[pubHex] = &WtPeer{
				connReq:    connReq,
				remotePub:  pubKey,
				pubString:  pubHex,
				remoteAddr: addr.String(),
				server:     wts,
				quit:       make(chan struct{}),
			}
			wts.mu.RUnlock()

			wts.ConnMgr.Connect(connReq)
		}()
	}
	return nil
}

func (wts *WTServer) Stop() {
	// TODO(ys): clean up
	wts.ConnMgr.Stop()
}

func (wts *WTServer) SendAllWatchNewChannelMessages(peer *WtPeer) error {
	dbChannels, err := wts.cfg.Db.FetchAllOpenChannels()
	if err != nil {
		return err
	}

	log.Infof("SendAllWatchNewChannelMessages: fetched %v channels from DB",
		len(dbChannels))

	for _, dbChannel := range dbChannels {
		msg := NewWatchNewChannelMessage(dbChannel)
		if err := peer.writeMessage(msg); err != nil {
			return err
		}
	}

	return nil
}

func (wts *WTServer) OutboundPeerConnected(connReq *connmgr.ConnReq, conn net.Conn) {
	// TODO(ys): add error channel
	brontideConn := conn.(*brontide.Conn)

	peer, _ := NewPeer(wts, brontideConn, connReq)
	if err := peer.Start(); err != nil {
		log.Error(err)
		return
	}
	wts.AddPeer(peer)
	log.Infof("new outbound connected: %v", peer)
	wts.SendAllWatchNewChannelMessages(peer)
}

func (wts *WTServer) InboundPeerConnected(conn net.Conn) {
	// TODO(ys): add error channel
	brontideConn := conn.(*brontide.Conn)

	connReq := &connmgr.ConnReq{
		Addr: conn.RemoteAddr(),
	}
	peer, _ := NewPeer(wts, brontideConn, connReq)
	if err := peer.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Infof("new inbound connected: %v", peer)
}

// AddPeer creates new WtPeer, saves it to bd and map.
func (wts *WTServer) AddPeer(peer *WtPeer) error {
	address := peer.conn.RemoteAddr()
	pubKey := peer.conn.RemotePub()
	wts.cfg.Db.SavePeer(address, pubKey, wts.cfg.ChainHash)
	wts.mu.RLock()
	wts.WatchtowerPeers[peer.PubString()] = peer
	wts.mu.RUnlock()
	return nil
}

// findWatchtowerConnection is an internal method that retrieves the specified
// watchtower connection from the server's internal state using.
func (wts *WTServer) FindWatchtowerPeer(pubKey *btcec.PublicKey) (*WtPeer, error) {
	pubStr := hex.EncodeToString(pubKey.SerializeCompressed())
	wts.mu.RLock()
	// If will only stop trying to connect if this peer is connected and
	// online. If connection is being established, we will still proceed
	// with current request.
	peer, ok := wts.WatchtowerPeers[pubStr]
	if !ok {
		return nil, fmt.Errorf("wtPeer does not exist")
	}
	wts.mu.RUnlock()
	return peer, nil
}

func (wts *WTServer) GetBreachInfoReqChan() <-chan *lnwallet.BreachInfoReq {
	return wts.breachInfoReqChan
}

func (wts *WTServer) PublishTx(tx *wire.MsgTx) error {
	return wts.cfg.PublishTx(tx)
}

// ProcessBreachInfoReq passes breachInfoReq to breachArbiter, generates
// revocation data and justiceTx there and then passes this data back.
func (wts *WTServer) ProcessBreachInfoReq(breachInfoReq *lnwallet.BreachInfoReq) {
	wts.breachInfoReqChan <- breachInfoReq
}

// SendNewWatchNewChannel transforms *channeldb.OpenChannel into
// WatchNewChannelMessage and send it to watchtower server.
func (wts *WTServer) SendNewWatchNewChannel(newChan *channeldb.OpenChannel) error {
	msg := NewWatchNewChannelMessage(newChan)
	return wts.SendToPeers(msg)
}

func (wts *WTServer) SendToPeers(msg Message) error {
	peers := wts.Peers(true, false)
	for _, peer := range peers {
		err := peer.writeMessage(msg)
		if err != nil {
			return err
		}
	}
	log.Infof("Sent %v to %d recipient(s)", msg.MsgType(), len(peers))
	return nil
}

func (wts *WTServer) Peers(active, inactive bool) []*WtPeer {
	wts.mu.RLock()
	defer wts.mu.RUnlock()

	var peers []*WtPeer

	for _, peer := range wts.WatchtowerPeers {
		if (peer.IsActive() && active) || (!peer.IsActive() && inactive) {
			peers = append(peers, peer)
		}
	}

	return peers
}

// SendNewAddRevocationData signs revData with pubkey and sends it to
// watchtower server.
func (wts *WTServer) SendNewAddRevocationData(height uint64,
	fundingOutpoint wire.OutPoint, revData *lnwallet.RevocationData) error {

	msg, err := NewAddRevocationDataMessage(
		height, fundingOutpoint, revData,
	)
	if err != nil {
		return err
	}
	return wts.SendToPeers(msg)
}

func (wts *WTServer) AddWatchtower(addr *lnwire.NetAddress) error {

	if wts.IsServer() {
		return fmt.Errorf("only watchtower clients can initiate outbound " +
			"connections: this node is a server")
	}

	peer, err := wts.FindWatchtowerPeer(addr.IdentityKey)
	if err == nil && peer.IsActive() {
		return fmt.Errorf("already connected to peer: %v", peer)
	}

	connReq := &connmgr.ConnReq{
		Addr:      addr,
		Permanent: true,
	}
	go wts.ConnMgr.Connect(connReq)

	return nil
}

func (wts *WTServer) DisconnectWatchtower(pubKey *btcec.PublicKey) error {

	// If we can't find peer that means it is not connected, so we return
	// immediately without error.
	peer, err := wts.FindWatchtowerPeer(pubKey)
	if err != nil {
		return nil
	}
	// Otherwise, we disconnect it and remove it from map.
	peer.Disconnect(errors.New("requested by user"), false)

	return nil
}
