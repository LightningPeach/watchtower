package wtower

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrWtPeerExiting = fmt.Errorf("wtpeer exiting")
)

const (
	// pingInterval is the interval at which ping messages are sent.
	pingInterval = 1 * time.Minute

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute

	// writeMessageTimeout is the timeout used when writing a message to peer.
	writeMessageTimeout = 50 * time.Second
)

// TODO(ys): add startTime
// TODO(ys): add bytes sent
// TODO(ys): add bytes received
// WtPeer is an active peer, either a watchtower server or a watchtower client.
// This struct is responsible for exchanging of all messages related to
// watchtower activity after establishing connection between two nodes
// lightning.
type WtPeer struct {
	// MUST be used atomically.
	started    int32
	disconnect int32

	// The following fields are only meant to be used *atomically*
	bytesReceived uint64
	bytesSent     uint64

	server *WTServer
	conn   *brontide.Conn

	// pingTime is a rough estimate of the RTT (round-trip-time) between us
	// and the connected peer. This time is expressed in micro seconds.
	// To be used atomically.
	pingTime int64

	// pingLastSend is the Unix time expressed in nanoseconds when we sent
	// our last ping message. To be used atomically.
	pingLastSend int64

	connReq *connmgr.ConnReq

	remotePub *btcec.PublicKey

	remoteAddr string

	// Hexed remote pubkey.
	pubString string

	// writeBuf is a buffer that we'll re-use in order to encode wire
	// messages to write out directly on the socket. By re-using this
	// buffer, we avoid needing to allocate more memory each time a new
	// message is to be sent to a peer.
	writeBuf [lnwire.MaxMessagePayload]byte

	quit chan struct{}
	wg   sync.WaitGroup
}

func NewPeer(server *WTServer, conn *brontide.Conn, connReq *connmgr.ConnReq) (*WtPeer, error) {
	pubKeyBytes := conn.RemotePub().SerializeCompressed()
	pubString := hex.EncodeToString(pubKeyBytes)

	return &WtPeer{
		server:     server,
		conn:       conn,
		connReq:    connReq,
		remotePub:  conn.RemotePub(),
		pubString:  pubString,
		remoteAddr: conn.RemoteAddr().String(),
		quit:       make(chan struct{}),
	}, nil
}

// Start starts all helper goroutines the WtPeer needs for normal operations.
func (wp *WtPeer) Start() error {
	if atomic.AddInt32(&wp.started, 1) != 1 {
		return nil
	}

	log.Infof("Peer %v starting", wp)

	// Exchange init message. It should be very first between two nodes.
	if err := wp.sendInitMsg(); err != nil {
		return fmt.Errorf("unable to send init msg: %v", err)
	}

	// Before we launch any of the helper goroutines off the peer struct,
	// we'll first ensure proper adherence to the p2p protocol. The init
	// message MUST be sent before any other message.
	readErr := make(chan error, 1)
	msgChan := make(chan Message, 1)
	wp.wg.Add(1)
	go func() {
		defer wp.wg.Done()

		msg, err := wp.readNextMessage()
		if err != nil {
			readErr <- err
			msgChan <- nil
			return
		}
		readErr <- nil
		msgChan <- msg
	}()

	select {
	// In order to avoid blocking indefinitely, we'll give the other peer
	// an upper timeout of 15 seconds to respond before we bail out early.
	case <-time.After(time.Second * 15):
		return fmt.Errorf("peer did not complete handshake within 15 " +
			"seconds")
	case err := <-readErr:
		if err != nil {
			return fmt.Errorf("unable to read init msg: %v", err)
		}
	}
	msg := <-msgChan
	msgType := msg.MsgType()
	if msgType != InitMsg {
		return fmt.Errorf("first received message was %v, not InitMsg", msgType)
	}

	wp.wg.Add(2)
	go wp.readHandler()
	go wp.pingHandler()

	return nil
}

// sendInitMsg sends init message to remote peer.
func (wp *WtPeer) sendInitMsg() error {
	msg := NewInitMessage()
	return wp.writeMessage(msg)
}

// readNextMessage reads, and returns the next message on the wire.
func (wp *WtPeer) readNextMessage() (Message, error) {
	noiseConn := wp.conn

	// First we'll read the next _full_ message. We do this rather than
	// reading incrementally from the stream as the Lightning wire protocol
	// is message oriented and allows nodes to pad on additional data to
	// the message stream.
	rawMsg, err := noiseConn.ReadNextMessage()
	atomic.AddUint64(&wp.bytesReceived, uint64(len(rawMsg)))
	if err != nil {
		return nil, err
	}

	// Next, create a new io.Reader implementation from the raw message,
	// and use this to decode the message directly from.
	msgReader := bytes.NewReader(rawMsg)
	nextMsg, err := ReadMessage(msgReader, 0)
	if err != nil {
		return nil, err
	}

	return nextMsg, nil
}

// MaxMessagePayload is the maximum bytes a message can be regardless of other
// individual limits imposed by messages themselves.
const MaxMessagePayload = 65535 // 65KB

// ReadMessage reads, validates, and parses the next Lightning message from r
// for the provided protocol version.
func ReadMessage(r io.Reader, pver uint32) (Message, error) {
	// First, we'll read out the first two bytes of the message so we can
	// create the proper empty message.
	var mType [2]byte
	if _, err := io.ReadFull(r, mType[:]); err != nil {
		return nil, err
	}

	msgType := MessageType(binary.BigEndian.Uint16(mType[:]))

	// Now that we know the target message type, we can create the proper
	// empty message type and decode the message into it.
	msg, err := makeEmptyMessage(msgType)
	if err != nil {
		return nil, err
	}
	if err := msg.Decode(r, pver); err != nil {
		return nil, err
	}

	return msg, nil
}

// makeEmptyMessage creates a new empty message of the proper concrete type
// based on the passed message type.
func makeEmptyMessage(msgType MessageType) (Message, error) {
	var msg Message

	switch msgType {
	case WatchNewChannelMsg:
		msg = &WatchNewChannelMessage{}
	case AddRevocationDataMsg:
		msg = &AddRevocationDataMessage{}
	case PingMsg:
		msg = &PingMessage{}
	case PongMsg:
		msg = &PongMessage{}
	case InitMsg:
		msg = &InitMessage{}
	case StatesMsg:
		msg = &StatesMessage{}
	default:
		return nil, &UnknownMessage{msgType}
	}

	return msg, nil
}

// writeMessage writes the target lnwire.Message to the remote peer.
func (wp *WtPeer) writeMessage(msg Message) error {
	// Simply exit if we're shutting down or didn't start peer properly.
	if !wp.IsActive() {
		wp.Disconnect(ErrWtPeerExiting, true)
		return ErrWtPeerExiting
	}

	// We'll re-slice of static write buffer to allow this new message to
	// utilize all available space. We also ensure we cap the capacity of
	// this new buffer to the static buffer which is sized for the largest
	// possible protocol message.
	b := bytes.NewBuffer(wp.writeBuf[0:0:len(wp.writeBuf)])

	// With the temp buffer created and sliced properly (length zero, full
	// capacity), we'll now encode the message directly into this buffer.
	n, err := WriteMessage(b, msg, 0)
	atomic.AddUint64(&wp.bytesSent, uint64(n))

	wp.conn.SetWriteDeadline(time.Now().Add(writeMessageTimeout))

	// Finally, write the message itself in a single swoop.
	_, err = wp.conn.Write(b.Bytes())
	if err != nil {
		log.Errorf("writeMessage error: %v", err)
	}
	return err
}

// WriteMessage writes a lightning Message to w including the necessary header
// information and returns the number of bytes written.
func WriteMessage(w io.Writer, msg Message, pver uint32) (int, error) {
	totalBytes := 0

	// Encode the message payload itself into a temporary buffer.
	// TODO(ys): create buffer pool
	var bw bytes.Buffer
	if err := msg.Encode(&bw, pver); err != nil {
		return totalBytes, err
	}
	payload := bw.Bytes()
	lenp := len(payload)

	// Enforce maximum overall message payload.
	if lenp > MaxMessagePayload {
		return totalBytes, fmt.Errorf("message payload is too large - "+
			"encoded %d bytes, but maximum message payload is %d bytes",
			lenp, MaxMessagePayload)
	}

	// Enforce maximum message payload on the message type.
	mpl := msg.MaxPayloadLength(pver)
	if uint32(lenp) > mpl {
		return totalBytes, fmt.Errorf("message payload is too large - "+
			"encoded %d bytes, but maximum message payload of "+
			"type %v is %d bytes", lenp, msg.MsgType(), mpl)
	}

	// With the initial sanity checks complete, we'll now write out the
	// message type itself.
	var mType [2]byte
	binary.BigEndian.PutUint16(mType[:], uint16(msg.MsgType()))
	n, err := w.Write(mType[:])
	totalBytes += n
	if err != nil {
		return totalBytes, err
	}

	// With the message type written, we'll now write out the raw payload
	// itself.
	n, err = w.Write(payload)
	totalBytes += n

	return totalBytes, err
}

// readHandler is responsible for reading messages off the wire in series, then
// properly dispatching the handling of the message to the proper subsystem.
//
// NOTE: This method MUST be run as a goroutine.
func (wp *WtPeer) readHandler() {
	defer wp.wg.Done()

	// We'll stop the timer after a new messages is received, and also
	// reset it after we process the next message.
	idleTimer := time.AfterFunc(idleTimeout, func() {
		err := fmt.Errorf("peer %s did not answer for %s -- disconnecting",
			wp, idleTimeout)
		wp.Disconnect(err, true)
	})

out:
	for atomic.LoadInt32(&wp.disconnect) == 0 {
		nextMsg, err := wp.readNextMessage()
		if err != nil {
			log.Infof("Unable to read message from %s: %v", wp, err)

			switch err.(type) {
			// UnknownMessage is not a critical error and could mean that
			// peer uses newer version.
			case *UnknownMessage:
				idleTimer.Reset(idleTimeout)
				continue

			// Disconnect otherwise.
			default:
				break out
			}
		}

		identityKey := wp.RemotePub()
		switch msg := nextMsg.(type) {
		case *PongMessage:
			pingSendTime := atomic.LoadInt64(&wp.pingLastSend)
			delay := (time.Now().UnixNano() - pingSendTime) / 1000
			atomic.StoreInt64(&wp.pingTime, delay)

		case *PingMessage:
			pongBytes := make([]byte, msg.NumPongBytes)
			wp.writeMessage(NewPongMessage(pongBytes))

		case *WatchNewChannelMessage:
			log.Infof("Received WatchNewChannelMessage from %s", wp)
			if wp.server.IsClient() {
				log.Errorf("Clients should not receive " +
					"WatchNewChannelMessage, skipping...")
			}
			openChannel := OpenChanFromWatchNewChan(*msg, wp.server.cfg.Db)
			// Since it may be message sent by peer after reconnecting, we
			// will also retrieved info regarding states saved for this
			// channel.
			var states []uint64
			states, err = wp.server.WatchNewChannel(openChannel, identityKey)
			// Now that we got sorted states, we will try to transform them into
			// intervals of consecutive states. This should reduce the amount of
			// data we need to transfer to peer.

			// intervals will store the first (on every even position) and the
			// last (on every odd position) states for each interval. Intervals
			// are picked in such a way, that the last state of one interval
			// and the first state of the next interval have at least one
			// other state between them that we have no information about, and
			// for each interval from A to B, we have information about every
			// state number not lower than A and not higher than B.
			var intervals []uint64
			numStates := uint64(len(states))
			// If we have no states we will not be able to add new intervals.
			if len(states) != 0 {
				// startInd corresponds to A from explanation above.
				startInd := uint64(0)
				for i := uint64(1); i < numStates; i++ {
					// If these are not two consecutive numbers, state on
					// position i - 1 corresponds to B from explanation above.
					if states[i] > states[i-1]+1 {
						// Save current interval
						intervals = append(intervals, states[startInd])
						intervals = append(intervals, states[i-1])
						// and update starting position for the new one.
						startInd = i
					}
				}
				// Save the last interval.
				intervals = append(intervals, states[startInd])
				intervals = append(intervals, states[numStates-1])
			}
			if numStates == 0 {
				log.Infof("No saved states found for %s", wp)
			} else {
				chanPoint := openChannel.FundingOutpoint
				log.Infof("Latest state for %s, %s is %d, total number of "+
					"states: %d", wp, chanPoint, states[numStates-1], numStates)
			}
			statesMsg := NewStatesMessage(
				intervals, openChannel.FundingOutpoint,
			)
			err := wp.writeMessage(statesMsg)
			if err != nil {
				log.Errorf("StatesMessage error: %v", err)
			}

		case *AddRevocationDataMessage:
			log.Infof("Received AddRevocationDataMessage from %s", wp)
			err = wp.server.SaveEncryptedRevocation(
				msg.Height,
				msg.FundingOutpoint,
				msg.EncryptedData,
				identityKey,
			)
		case *StatesMessage:
			log.Infof("Received StatesMessage from %s", wp)
			if wp.server.IsServer() {
				log.Errorf("Servers should not receive StatesMessage, " +
					"skipping...")
				break
			}
			intervals := msg.Intervals
			chanPoint := msg.ChannelPoint
			var (
				buffer         bytes.Buffer
				savedStatesNum uint64 = 0
				sendStates     uint64 = 0
				lChannel       *lnwallet.LightningChannel
			)
			lChannel, err = wp.server.LightningChannelFromOutPoint(
				chanPoint,
			)
			if err != nil {
				break
			}
			// Create array to mark states not saved on watchtower server.
			totalStates := lChannel.RevDataLatestHeight() + 1
			savedStates := make([]bool, totalStates)

			for i := 0; i+1 < len(intervals); i += 2 {
				// Add string representation of current interval to buffer.
				// Separate with comma if it is not the first interval.
				if i > 0 {
					buffer.WriteString(fmt.Sprint(", "))
				}
				left, right := intervals[i], intervals[i+1]
				if left == right {
					buffer.WriteString(fmt.Sprintf("%d", left))
				} else {
					buffer.WriteString(fmt.Sprintf("%d-%d", left, right))
				}
				// Update saved states and their number.
				for height := left; height <= right; height++ {
					savedStatesNum++
					savedStates[height] = true
				}
			}

			// Then we will send revocation data for states that we did not
			// receive in this message. These are indicated by false on
			// corresponding position of savedStates array.
			for height := uint64(0); height < totalStates; height++ {
				if !savedStates[height] {
					revData, err := lChannel.GenerateRevDataAtHeight(height)
					if err != nil {
						log.Errorf("Failed to generate revocation data at "+
							"height %d.", height)
						continue
					}
					err2 := wp.server.SendNewAddRevocationData(
						height, chanPoint, revData,
					)
					if err2 != nil {
						log.Errorf("Failed to send revocation data at "+
							"height %d.", height)
					} else {
						sendStates++
					}
				}
			}

			if len(intervals) == 0 {
				buffer.WriteString("None")
			}
			log.Infof("%s has following state(s) saved for %v: %s. "+
				"Total: %d.", wp, chanPoint, buffer.String(), savedStatesNum)
			log.Infof("Successfully sent information about %d states back "+
				"watchtower to server.", sendStates)

		default:
			err = fmt.Errorf("unknown message %v received from peer "+
				"%v", uint16(msg.MsgType()), wp)
		}
		if err != nil {
			log.Errorf("%v", err)
		}
		idleTimer.Reset(idleTimeout)
	}

	wp.Disconnect(errors.New("read handler closed"), true)

	log.Tracef("readHandler for peer %v done", wp)
}

// pingHandler is responsible for periodically sending ping messages to the
// remote peer in order to keep the connection alive and/or determine if the
// connection is still active.
//
// NOTE: This method MUST be run as a goroutine.
func (wp *WtPeer) pingHandler() {
	defer wp.wg.Done()

	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	// TODO(ys): make dynamic in order to create fake cover traffic
	const numPingBytes = 16

out:
	for {
		select {
		case <-pingTicker.C:
			now := time.Now().UnixNano()
			atomic.StoreInt64(&wp.pingLastSend, now)
			wp.writeMessage(NewPingMessage(numPingBytes))
		case <-wp.quit:
			break out
		}
	}
}

// TODO(ys): return error and process
// Disconnect closes the connection to peer and removes it from the database
// if reconnect is set to false (it is so when it has been manually
// initialized), otherwise this function was launched as a result of an error
// of some kind, so we try to reconnect to peer without removing any data
// from db.
func (wp *WtPeer) Disconnect(reason error, reconnect bool) {
	if !atomic.CompareAndSwapInt32(&wp.disconnect, 0, 1) {
		return
	}

	log.Infof("Disconnecting %s, reason: %v", wp, reason)

	// We won't try to reconnect or clean up if we are a server.
	if wp.server.IsServer() {
		return
	}

	if reconnect {
		select {
		case <-time.After(10 * time.Second):
			watchtowerAddr := &lnwire.NetAddress{
				IdentityKey: wp.conn.RemotePub(),
				Address:     wp.conn.RemoteAddr(),
				ChainNet:    wp.server.Net,
			}

			if err := wp.server.AddWatchtower(watchtowerAddr); err != nil {
				log.Errorf("(addwatchtower): error reconnecting to "+
					"watchtower: %v", err)
			}
		case <-wp.server.quit:
			return
		}
	} else {
		// Ensure that the TCP connection is properly closed before continuing.
		// It can be nil in case we fetched this connection from the database,
		// but were never able to actually astablish a connection with peer.
		if wp.conn != nil {
			wp.conn.Close()
		}

		close(wp.quit)
		wp.server.mu.RLock()
		delete(wp.server.WatchtowerPeers, wp.PubString())
		wp.server.ConnMgr.Remove(wp.connReq.ID())
		wp.server.mu.RUnlock()
		wp.server.cfg.Db.DeletePeer(
			wp.RemotePub(), wp.server.cfg.ChainHash,
		)
	}
}

// String returns the string representation of this peer.
func (wp *WtPeer) String() string {
	return fmt.Sprintf("%s(%s)", wp.PubString(), wp.RemoteAddr())
}

// Active returns true for peers with currently established connection, and
// false for temporarily. In second case watchtower client tries to reconnect
// periodically.
func (wp *WtPeer) IsActive() bool {
	return atomic.LoadInt32(&wp.disconnect) == 0 &&
		atomic.LoadInt32(&wp.started) == 1
}

func (wp *WtPeer) RemotePub() *btcec.PublicKey {
	return wp.remotePub
}

func (wp *WtPeer) RemoteAddr() string {
	return wp.remoteAddr
}

func (wp *WtPeer) PubString() string {
	return wp.pubString
}

// PingTime returns the estimated ping time to the peer in microseconds.
func (wp *WtPeer) PingTime() int64 {
	return atomic.LoadInt64(&wp.pingTime)
}
