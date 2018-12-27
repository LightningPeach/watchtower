package contractcourt

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"bytes"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwallet"
)

const (
	// minCommitPointPollTimeout is the minimum time we'll wait before
	// polling the database for a channel's commitpoint.
	minCommitPointPollTimeout = 1 * time.Second

	// maxCommitPointPollTimeout is the maximum time we'll wait before
	// polling the database for a channel's commitpoint.
	maxCommitPointPollTimeout = 10 * time.Minute
)

// LocalUnilateralCloseInfo encapsulates all the informnation we need to act
// on a local force close that gets confirmed.
type LocalUnilateralCloseInfo struct {
	*chainntnfs.SpendDetail
	*lnwallet.LocalForceCloseSummary
	*channeldb.ChannelCloseSummary
}

// CooperativeCloseInfo encapsulates all the informnation we need to act
// on a cooperative close that gets confirmed.
type CooperativeCloseInfo struct {
	*channeldb.ChannelCloseSummary
}

// ChainEventSubscription is a struct that houses a subscription to be notified
// for any on-chain events related to a channel. There are three types of
// possible on-chain events: a cooperative channel closure, a unilateral
// channel closure, and a channel breach. The fourth type: a force close is
// locally initiated, so we don't provide any event stream for said event.
type ChainEventSubscription struct {
	// ChanPoint is that channel that chain events will be dispatched for.
	ChanPoint wire.OutPoint

	// RemoteUnilateralClosure is a channel that will be sent upon in the
	// event that the remote party's commitment transaction is confirmed.
	RemoteUnilateralClosure chan *lnwallet.UnilateralCloseSummary

	// LocalUnilateralClosure is a channel that will be sent upon in the
	// event that our commitment transaction is confirmed.
	LocalUnilateralClosure chan *LocalUnilateralCloseInfo

	// CooperativeClosure is a signal that will be sent upon once a
	// cooperative channel closure has been detected confirmed.
	CooperativeClosure chan *CooperativeCloseInfo

	// ContractBreach is a channel that will be sent upon if we detect a
	// contract breach. The struct sent across the channel contains all the
	// material required to bring the cheating channel peer to justice.
	ContractBreach chan *lnwallet.BreachRetribution

	// Cancel cancels the subscription to the event stream for a particular
	// channel. This method should be called once the caller no longer needs to
	// be notified of any on-chain events for a particular channel.
	Cancel func()
}

// chainWatcherConfig encapsulates all the necessary functions and interfaces
// needed to watch and act on on-chain events for a particular channel.
type chainWatcherConfig struct {
	// chanState is a snapshot of the persistent state of the channel that
	// we're watching. In the event of an on-chain event, we'll query the
	// database to ensure that we act using the most up to date state.
	chanState *channeldb.OpenChannel

	// notifier is a reference to the channel notifier that we'll use to be
	// notified of output spends and when transactions are confirmed.
	notifier chainntnfs.ChainNotifier

	// pCache is a reference to the shared preimage cache. We'll use this
	// to see if we can settle any incoming HTLC's during a remote
	// commitment close event.
	pCache WitnessBeacon

	// signer is the main signer instances that will be responsible for
	// signing any HTLC and commitment transaction generated by the state
	// machine.
	signer lnwallet.Signer

	// contractBreach is a method that will be called by the watcher if it
	// detects that a contract breach transaction has been confirmed. Only
	// when this method returns with a non-nil error it will be safe to mark
	// the channel as pending close in the database.
	contractBreach func(*lnwallet.BreachRetribution) error

	// isOurAddr is a function that returns true if the passed address is
	// known to us.
	isOurAddr func(btcutil.Address) bool

	// PublishTx reliably broadcasts a transaction to the network. Once
	// this function exits without an error, then they transaction MUST
	// continually be rebroadcast if needed.
	publishTx func(*wire.MsgTx) error

	// db provides access to the channel's justiceTxs provided by its participant(s),
	// allowing the chain watcher to broadcast justice transaction immediately after detecting
	// breach transaction published by counterparty.
	db *channeldb.DB
}

// chainWatcher is a system that's assigned to every active channel. The duty
// of this system is to watch the chain for spends of the channels chan point.
// If a spend is detected then with chain watcher will notify all subscribers
// that the channel has been closed, and also give them the materials necessary
// to sweep the funds of the channel on chain eventually.
type chainWatcher struct {
	started int32 // To be used atomically.
	stopped int32 // To be used atomically.

	quit chan struct{}
	wg   sync.WaitGroup

	cfg chainWatcherConfig

	// stateHintObfuscator is a 48-bit state hint that's used to obfuscate
	// the current state number on the commitment transactions.
	stateHintObfuscator [lnwallet.StateHintSize]byte

	// All the fields below are protected by this mutex.
	sync.Mutex

	// clientID is an ephemeral counter used to keep track of each
	// individual client subscription.
	clientID uint64

	// clientSubscriptions is a map that keeps track of all the active
	// client subscriptions for events related to this channel.
	clientSubscriptions map[uint64]*ChainEventSubscription

	// encryptedData is a map where key corresponds to channel's height, and
	// value corresponds to encoded revocation data on this height for
	// chainWatcher's channel. The data is encoded using breach transaction's
	// hash, so watchtower can decode it no sooner than it appears on-chain.
	encryptedData map[uint64][]byte
}

// newChainWatcher returns a new instance of a chainWatcher for a channel given
// the chan point to watch, and also a notifier instance that will allow us to
// detect on chain events.
func newChainWatcher(cfg chainWatcherConfig) (*chainWatcher, error) {
	// In order to be able to detect the nature of a potential channel
	// closure we'll need to reconstruct the state hint bytes used to
	// obfuscate the commitment state number encoded in the lock time and
	// sequence fields.
	var stateHint [lnwallet.StateHintSize]byte
	chanState := cfg.chanState
	if chanState.IsInitiator {
		stateHint = lnwallet.DeriveStateHintObfuscator(
			chanState.LocalChanCfg.PaymentBasePoint.PubKey,
			chanState.RemoteChanCfg.PaymentBasePoint.PubKey,
		)
	} else {
		stateHint = lnwallet.DeriveStateHintObfuscator(
			chanState.RemoteChanCfg.PaymentBasePoint.PubKey,
			chanState.LocalChanCfg.PaymentBasePoint.PubKey,
		)
	}

	return &chainWatcher{
		cfg:                 cfg,
		stateHintObfuscator: stateHint,
		quit:                make(chan struct{}),
		clientSubscriptions: make(map[uint64]*ChainEventSubscription),
		encryptedData:       make(map[uint64][]byte),
	}, nil
}

func (c *chainWatcher) AppendRevocationData(height uint64,
	encryptedData []byte, clientPubKey *btcec.PublicKey) error {

	c.Lock()
	c.encryptedData[height] = encryptedData
	c.Unlock()

	return c.cfg.db.SaveEncryptedRevocation(c.cfg.chanState.FundingOutpoint,
		height, c.cfg.chanState.ChainHash, encryptedData, clientPubKey)
}

// Start starts all goroutines that the chainWatcher needs to perform its
// duties.
func (c *chainWatcher) Start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	chanState := c.cfg.chanState
	log.Debugf("Starting chain watcher for ChannelPoint(%v)",
		chanState.FundingOutpoint)

	// First, we'll register for a notification to be dispatched if the
	// funding output is spent.
	fundingOut := &chanState.FundingOutpoint

	// As a height hint, we'll try to use the opening height, but if the
	// channel isn't yet open, then we'll use the height it was broadcast
	// at.
	heightHint := c.cfg.chanState.ShortChanID().BlockHeight
	if heightHint == 0 {
		heightHint = chanState.FundingBroadcastHeight
	}

	localKey := chanState.LocalChanCfg.MultiSigKey.PubKey.SerializeCompressed()
	remoteKey := chanState.RemoteChanCfg.MultiSigKey.PubKey.SerializeCompressed()
	multiSigScript, err := lnwallet.GenMultiSigScript(
		localKey, remoteKey,
	)
	if err != nil {
		return err
	}
	pkScript, err := lnwallet.WitnessScriptHash(multiSigScript)
	if err != nil {
		return err
	}

	spendNtfn, err := c.cfg.notifier.RegisterSpendNtfn(
		fundingOut, pkScript, heightHint,
	)
	if err != nil {
		return err
	}

	// With the spend notification obtained, we'll now dispatch the
	// closeObserver which will properly react to any changes.
	c.wg.Add(1)
	go c.closeObserver(spendNtfn)

	return nil
}

// Stop signals the close observer to gracefully exit.
func (c *chainWatcher) Stop() error {
	if !atomic.CompareAndSwapInt32(&c.stopped, 0, 1) {
		return nil
	}

	close(c.quit)

	c.wg.Wait()

	return nil
}

// SubscribeChannelEvents returns an active subscription to the set of channel
// events for the channel watched by this chain watcher. Once clients no longer
// require the subscription, they should call the Cancel() method to allow the
// watcher to regain those committed resources.
func (c *chainWatcher) SubscribeChannelEvents() *ChainEventSubscription {

	c.Lock()
	clientID := c.clientID
	c.clientID++
	c.Unlock()

	log.Debugf("New ChainEventSubscription(id=%v) for ChannelPoint(%v)",
		clientID, c.cfg.chanState.FundingOutpoint)

	sub := &ChainEventSubscription{
		ChanPoint:               c.cfg.chanState.FundingOutpoint,
		RemoteUnilateralClosure: make(chan *lnwallet.UnilateralCloseSummary, 1),
		LocalUnilateralClosure:  make(chan *LocalUnilateralCloseInfo, 1),
		CooperativeClosure:      make(chan *CooperativeCloseInfo, 1),
		ContractBreach:          make(chan *lnwallet.BreachRetribution, 1),
		Cancel: func() {
			c.Lock()
			delete(c.clientSubscriptions, clientID)
			c.Unlock()
			return
		},
	}

	c.Lock()
	c.clientSubscriptions[clientID] = sub
	c.Unlock()

	return sub
}

func createSingleJusticeTx(localPaymentBasePoint, remoteHtlcPubkey,
	localHtlcPubkey, revocationPubKey, delayPubKey *btcec.PublicKey,
	remoteDelay uint32, revData *lnwallet.RevocationData,
	breachTx *wire.MsgTx) (*wire.MsgTx, error) {

	commitPoint := revData.CommitPoint

	txn := wire.NewMsgTx(2)

	// We begin by adding the output to which our funds will be deposited.
	// First, calculate the total amount.
	var breachAmount int64 = 0
	for _, txOut := range breachTx.TxOut {
		breachAmount += txOut.Value
	}
	txn.AddTxOut(&wire.TxOut{
		PkScript: revData.PkScript,
		Value:    breachAmount - revData.Fee,
	})
	// Next, we add all of the spendable outputs as inputs to the
	// transaction.
	txHash := breachTx.TxHash()
	for _, txInInfo := range revData.TxInInfo {
		var err error
		prevIndex := txInInfo.PreviousOutpointIndex
		newTxIn := wire.TxIn{
			PreviousOutPoint: *wire.NewOutPoint(
				&txHash,
				prevIndex,
			),
		}

		// verifyWitnessScript returns nil if hashed witnessScript of
		// our new transaction input matches pkScript of corresponding
		// breached output. Since it is known which output current
		// input revokes, we only need to pass the witnessScript.
		// TODO(ys): redundant? Can't publish anyway with invalid witness
		verifyWitnessScript := func(witnessScript []byte) error {
			expectedScript, err := lnwallet.WitnessScriptHash(witnessScript)
			if err != nil {
				return err
			}
			// Breached output's script.
			previousScript := breachTx.TxOut[prevIndex].PkScript
			if bytes.Compare(expectedScript, previousScript) != 0 {
				return fmt.Errorf("witness script's hash does not " +
					"match output's pkScript")
			}
			return nil
		}

		// Witness stack differs depending on witness type.
		// For each input, client must send correct witness type, as
		// well as correct signature, on which justice transaction
		// will be based on.
		witnessType := txInInfo.WitnessType
		switch witnessType {
		case lnwallet.HtlcOfferedRevoke:
			newTxIn.Witness = wire.TxWitness(make([][]byte, 3))
			newTxIn.Witness[0] = txInInfo.Sig
			newTxIn.Witness[1] = revocationPubKey.SerializeCompressed()
			newTxIn.Witness[2], err = lnwallet.ReceiverHTLCScript(
				txInInfo.RefundTimeout, localHtlcPubkey,
				remoteHtlcPubkey, revocationPubKey,
				txInInfo.RHash[:],
			)
			if err != nil {
				return nil, err
			}
			if err := verifyWitnessScript(newTxIn.Witness[2]); err != nil {
				return nil, err
			}
		case lnwallet.HtlcAcceptedRevoke:
			newTxIn.Witness = wire.TxWitness(make([][]byte, 3))
			newTxIn.Witness[0] = txInInfo.Sig
			newTxIn.Witness[1] = revocationPubKey.SerializeCompressed()
			newTxIn.Witness[2], err = lnwallet.SenderHTLCScript(
				remoteHtlcPubkey, localHtlcPubkey,
				revocationPubKey, txInInfo.RHash[:],
			)
			if err != nil {
				return nil, err
			}
			if err := verifyWitnessScript(newTxIn.Witness[2]); err != nil {
				return nil, err
			}
		case lnwallet.CommitmentRevoke:
			newTxIn.Witness = wire.TxWitness(make([][]byte, 3))
			newTxIn.Witness[0] = txInInfo.Sig
			newTxIn.Witness[1] = []byte{1}
			newTxIn.Witness[2], err = lnwallet.CommitScriptToSelf(
				remoteDelay, delayPubKey, revocationPubKey,
			)
			if err != nil {
				return nil, err
			}
			if err := verifyWitnessScript(newTxIn.Witness[2]); err != nil {
				return nil, err
			}
		case lnwallet.CommitmentNoDelay:
			newTxIn.Witness = wire.TxWitness(make([][]byte, 2))
			newTxIn.Witness[0] = txInInfo.Sig
			newTxIn.Witness[1] = lnwallet.TweakPubKeyWithTweak(
				localPaymentBasePoint,
				lnwallet.SingleTweakBytes(commitPoint, localPaymentBasePoint),
			).SerializeCompressed()
		default:
			return nil, fmt.Errorf("invalid witnessType: %v", witnessType)
		}
		txn.TxIn = append(txn.TxIn, &newTxIn)
	}
	btx := btcutil.NewTx(txn)
	if err := blockchain.CheckTransactionSanity(btx); err != nil {
		return nil, err
	}

	return txn, nil
}

// punishSecondLevelTxOnSpend waits for confirmed second level transaction
// in spend channel and then creates and publishes corresponding punishing
// transaction.
//
// NOTE: This MUST be run as a goroutine.
func (c *chainWatcher) punishSecondLevelTxOnSpend(pkScript []byte, fee int64,
	spend <-chan *chainntnfs.SpendDetail, secondLevelSig []byte,
	secondLevelScript []byte) {

	select {
	case commitSpend, ok := <-spend:
		if !ok {
			return
		}

		spendTx := commitSpend.SpendingTx
		txn := wire.NewMsgTx(2)
		amount := spendTx.TxOut[0].Value

		// We begin by adding the output to which our funds will be deposited.
		txn.AddTxOut(&wire.TxOut{
			PkScript: pkScript,
			Value:    amount - fee,
		})

		txHash := spendTx.TxHash()
		txn.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *wire.NewOutPoint(
				&txHash,
				0,
			),
		})

		// Before signing the transaction, check to ensure that it meets some
		// basic validity requirements.
		btx := btcutil.NewTx(txn)
		if err := blockchain.CheckTransactionSanity(btx); err != nil {
			log.Errorf("%v", err)
			return
		}

		txn.TxIn[0].Witness = wire.TxWitness(make([][]byte, 3))
		txn.TxIn[0].Witness[0] = secondLevelSig
		txn.TxIn[0].Witness[1] = []byte{1}
		txn.TxIn[0].Witness[2] = secondLevelScript

		err := c.cfg.publishTx(txn)
		if err != nil {
			log.Errorf("Could not publish transaction", txn)
		}

	case <-c.quit:
		return
	}
}

// dispatchContractBreachWtServer composes and publishes revocation transaction
// that moves funds from breached outputs to address controlled by cheated
// party.
func (c *chainWatcher) dispatchContractBreachWtServer(
	revData *lnwallet.RevocationData, breachTx *wire.MsgTx,
	spendingTx *wire.MsgTx, spendingHeight uint32) error {

	commitPoint := revData.CommitPoint

	revocationBasePoint := c.cfg.chanState.LocalChanCfg.RevocationBasePoint.PubKey
	localPaymentBasePoint := c.cfg.chanState.LocalChanCfg.PaymentBasePoint.PubKey
	localHtlcBasePoint := c.cfg.chanState.LocalChanCfg.HtlcBasePoint.PubKey

	delayBasePoint := c.cfg.chanState.RemoteChanCfg.DelayBasePoint.PubKey
	remoteHtlcBasePoint := c.cfg.chanState.RemoteChanCfg.HtlcBasePoint.PubKey
	remoteDelay := uint32(c.cfg.chanState.RemoteChanCfg.CsvDelay)

	remoteHtlcPubkey := lnwallet.TweakPubKey(remoteHtlcBasePoint, commitPoint)
	localHtlcPubkey := lnwallet.TweakPubKey(localHtlcBasePoint, commitPoint)
	revocationPubKey := lnwallet.DeriveRevocationPubkey(revocationBasePoint, commitPoint)
	delayPubKey := lnwallet.TweakPubKey(delayBasePoint, commitPoint)

	justiceTx, err := createSingleJusticeTx(localPaymentBasePoint,
		remoteHtlcPubkey, localHtlcPubkey, revocationPubKey,
		delayPubKey, remoteDelay, revData, breachTx)

	// If we got single justiceTx without any errors we then try to publish it.
	if err == nil {
		err = c.cfg.publishTx(justiceTx)
		// If we can publish single justiceTx without error, we exit this
		// method as our objective is complete.
		if err == nil {
			return nil
		}
	} else {
		return fmt.Errorf("could not generate justice tx "+
			"for breach transaction %v: %v", breachTx.TxHash(), err)
	}

	// If at any point we had a problem publishing a single justiceTx, we
	// then try to create n (n being number of outputs in justiceTx) separate
	// justice transaction, each of which spend one of the breached outputs.
	for i, txIn := range justiceTx.TxIn {

		txInInfo := revData.TxInInfo[i]
		// Since this transaction has only 1 input, the total amount
		// equals to value of i-th output of spending transaction.
		prevIndex := txInInfo.PreviousOutpointIndex
		amount := spendingTx.TxOut[prevIndex].Value

		// Fee was explicitly sent by client.
		txFee := txInInfo.IndividualSigsAndFees.RegularFee

		sweepAmt := amount - txFee

		// With the fee calculated, we can now create the transaction using the
		// information gathered above and the provided retribution information.
		txn := wire.NewMsgTx(2)

		// We begin by adding the output to which our funds will be deposited.
		txn.AddTxOut(&wire.TxOut{
			PkScript: justiceTx.TxOut[0].PkScript,
			Value:    sweepAmt,
		})

		// Next, we add spendable output as input to the transaction.
		txn.AddTxIn(&wire.TxIn{
			PreviousOutPoint: txIn.PreviousOutPoint,
		})

		// Apply witness.
		txn.TxIn[0].Witness = justiceTx.TxIn[i].Witness
		txn.TxIn[0].Witness[0] = txInInfo.IndividualSigsAndFees.RegularSig

		// Check to ensure that tx meets some basic validity requirements.
		btx := btcutil.NewTx(txn)
		if err := blockchain.CheckTransactionSanity(btx); err != nil {
			log.Errorf("%v", err)
			continue
		}

		// If we got single justiceTx without any errors we then try to publish it.
		err = c.cfg.publishTx(txn)

		if err != nil {
			if err == lnwallet.ErrDoubleSpend {
				// If we cannot publish this 1-to-1 transaction because of
				// double spend it could mean that channel's counterparty has
				// sent HTLC to the second level. If this is the case, we will
				// create and broadcast 1-to-1 revocation transaction that
				// punishes it.
				spendNtfn, err := c.cfg.notifier.RegisterSpendNtfn(
					&txIn.PreviousOutPoint, []byte{}, spendingHeight,
				)

				// If we cannot register spend notifier, we will not be able
				// to revoke second level transaction.
				if err != nil {
					log.Errorf("RegisterSpendNtfn: %v", err)
					continue
				}

				pkScript := justiceTx.TxOut[0].PkScript
				fee := txInInfo.IndividualSigsAndFees.SecondLevelFee
				secondLevelSig := txInInfo.IndividualSigsAndFees.SecondLevelSig
				secondLevelScript, err := lnwallet.SecondLevelHtlcScript(
					revocationPubKey, delayPubKey, remoteDelay,
				)
				if err != nil {
					log.Warnf("%+v", err)
					continue
				}
				go c.punishSecondLevelTxOnSpend(
					pkScript, fee, spendNtfn.Spend,
					secondLevelSig, secondLevelScript,
				)
			} else {
				log.Errorf("Unexpected error: %v", err)
			}
		}
	}

	return nil
}

// closeObserver is a dedicated goroutine that will watch for any closes of the
// channel that it's watching on chain. In the event of an on-chain event, the
// close observer will assembled the proper materials required to claim the
// funds of the channel on-chain (if required), then dispatch these as
// notifications to all subscribers.
func (c *chainWatcher) closeObserver(spendNtfn *chainntnfs.SpendEvent) {
	defer c.wg.Done()

	log.Infof("Close observer for ChannelPoint(%v) active",
		c.cfg.chanState.FundingOutpoint)

	select {
	// We've detected a spend of the channel onchain! Depending on
	// the type of spend, we'll act accordingly , so we'll examine
	// the spending transaction to determine what we should do.
	//
	// TODO(Roasbeef): need to be able to ensure this only triggers
	// on confirmation, to ensure if multiple txns are broadcast, we
	// act on the one that's timestamped
	case commitSpend, ok := <-spendNtfn.Spend:
		// If the channel was closed, then this means that the
		// notifier exited, so we will as well.
		if !ok {
			return
		}

		// Otherwise, the remote party might have broadcast a
		// prior revoked state...!!!
		commitTxBroadcast := commitSpend.SpendingTx

		// Decode the state hint encoded within the commitment
		// transaction to determine if this is a revoked state
		// or not.
		obfuscator := c.stateHintObfuscator
		broadcastStateNum := lnwallet.GetStateNumHint(
			commitTxBroadcast, obfuscator,
		)

		// TODO(ys): maybe add a better this-is-WT check
		c.Lock()
		ciphertext, ok := c.encryptedData[broadcastStateNum]
		c.Unlock()
		if ok {
			tx := commitSpend.SpendingTx
			txHash := tx.TxHash()
			revData := &lnwallet.RevocationData{}
			err := revData.Decrypt(txHash[:], ciphertext, 0)
			if err != nil {
				log.Errorf("%v", err)
				return
			}
			err = c.dispatchContractBreachWtServer(
				revData, tx, commitTxBroadcast, uint32(commitSpend.SpendingHeight),
			)
			if err != nil {
				log.Error("%v", err)
			} else {
				log.Infof("Successfully Published justice for ChannelPoint(%v)",
					c.cfg.chanState.FundingOutpoint)
			}
			return
		}

		localCommit, remoteCommit, err := c.cfg.chanState.LatestCommitments()
		if err != nil {
			log.Errorf("Unable to fetch channel state for "+
				"chan_point=%v", c.cfg.chanState.FundingOutpoint)
			return
		}

		// We'll not retrieve the latest sate of the revocation
		// store so we can populate the information within the
		// channel state object that we have.
		//
		// TODO(roasbeef): mutation is bad mkay
		_, err = c.cfg.chanState.RemoteRevocationStore()
		if err != nil {
			log.Errorf("Unable to fetch revocation state for "+
				"chan_point=%v", c.cfg.chanState.FundingOutpoint)
			return
		}

		// If this is our commitment transaction, then we can
		// exit here as we don't have any further processing we
		// need to do (we can't cheat ourselves :p).
		commitmentHash := localCommit.CommitTx.TxHash()
		isOurCommitment := commitSpend.SpenderTxHash.IsEqual(
			&commitmentHash,
		)
		if isOurCommitment {
			if err := c.dispatchLocalForceClose(
				commitSpend, *localCommit,
			); err != nil {
				log.Errorf("unable to handle local"+
					"close for chan_point=%v: %v",
					c.cfg.chanState.FundingOutpoint, err)
			}
			return
		}

		// Next, we'll check to see if this is a cooperative
		// channel closure or not. This is characterized by
		// having an input sequence number that's finalized.
		// This won't happen with regular commitment
		// transactions due to the state hint encoding scheme.
		if commitTxBroadcast.TxIn[0].Sequence == wire.MaxTxInSequenceNum {
			err := c.dispatchCooperativeClose(commitSpend)
			if err != nil {
				log.Errorf("unable to handle co op close: %v", err)
			}
			return
		}

		log.Warnf("Unprompted commitment broadcast for "+
			"ChannelPoint(%v) ", c.cfg.chanState.FundingOutpoint)

		remoteStateNum := remoteCommit.CommitHeight

		remoteChainTip, err := c.cfg.chanState.RemoteCommitChainTip()
		if err != nil && err != channeldb.ErrNoPendingCommit {
			log.Errorf("unable to obtain chain tip for "+
				"ChannelPoint(%v): %v",
				c.cfg.chanState.FundingOutpoint, err)
			return
		}

		switch {
		// If state number spending transaction matches the
		// current latest state, then they've initiated a
		// unilateral close. So we'll trigger the unilateral
		// close signal so subscribers can clean up the state
		// as necessary.
		case broadcastStateNum == remoteStateNum:
			err := c.dispatchRemoteForceClose(
				commitSpend, *remoteCommit,
				c.cfg.chanState.RemoteCurrentRevocation,
			)
			if err != nil {
				log.Errorf("unable to handle remote "+
					"close for chan_point=%v: %v",
					c.cfg.chanState.FundingOutpoint, err)
			}

		// We'll also handle the case of the remote party
		// broadcasting their commitment transaction which is
		// one height above ours. This case can arise when we
		// initiate a state transition, but the remote party
		// has a fail crash _after_ accepting the new state,
		// but _before_ sending their signature to us.
		case broadcastStateNum == remoteStateNum+1 &&
			remoteChainTip != nil:

			err := c.dispatchRemoteForceClose(
				commitSpend, remoteChainTip.Commitment,
				c.cfg.chanState.RemoteNextRevocation,
			)
			if err != nil {
				log.Errorf("unable to handle remote "+
					"close for chan_point=%v: %v",
					c.cfg.chanState.FundingOutpoint, err)
			}

		// This is the case that somehow the commitment broadcast is
		// actually greater than even one beyond our best known state
		// number. This should ONLY happen in case we experienced some
		// sort of data loss.
		case broadcastStateNum > remoteStateNum+1:
			log.Warnf("Remote node broadcast state #%v, "+
				"which is more than 1 beyond best known "+
				"state #%v!!! Attempting recovery...",
				broadcastStateNum, remoteStateNum)

			// If we are lucky, the remote peer sent us the correct
			// commitment point during channel sync, such that we
			// can sweep our funds. If we cannot find the commit
			// point, there's not much we can do other than wait
			// for us to retrieve it. We will attempt to retrieve
			// it from the peer each time we connect to it.
			// TODO(halseth): actively initiate re-connection to
			// the peer?
			var commitPoint *btcec.PublicKey
			backoff := minCommitPointPollTimeout
			for {
				commitPoint, err = c.cfg.chanState.DataLossCommitPoint()
				if err == nil {
					break
				}

				log.Errorf("Unable to retrieve commitment "+
					"point for channel(%v) with lost "+
					"state: %v. Retrying in %v.",
					c.cfg.chanState.FundingOutpoint,
					err, backoff)

				select {
				// Wait before retrying, with an exponential
				// backoff.
				case <-time.After(backoff):
					backoff = 2 * backoff
					if backoff > maxCommitPointPollTimeout {
						backoff = maxCommitPointPollTimeout
					}

				case <-c.quit:
					return
				}
			}

			log.Infof("Recovered commit point(%x) for "+
				"channel(%v)! Now attempting to use it to "+
				"sweep our funds...",
				commitPoint.SerializeCompressed(),
				c.cfg.chanState.FundingOutpoint)

			// Since we don't have the commitment stored for this
			// state, we'll just pass an empty commitment. Note
			// that this means we won't be able to recover any HTLC
			// funds.
			// TODO(halseth): can we try to recover some HTLCs?
			err = c.dispatchRemoteForceClose(
				commitSpend, channeldb.ChannelCommitment{},
				commitPoint,
			)
			if err != nil {
				log.Errorf("unable to handle remote "+
					"close for chan_point=%v: %v",
					c.cfg.chanState.FundingOutpoint, err)
			}

		// If the state number broadcast is lower than the
		// remote node's current un-revoked height, then
		// THEY'RE ATTEMPTING TO VIOLATE THE CONTRACT LAID OUT
		// WITHIN THE PAYMENT CHANNEL.  Therefore we close the
		// signal indicating a revoked broadcast to allow
		// subscribers to swiftly dispatch justice!!!
		case broadcastStateNum < remoteStateNum:
			err := c.dispatchContractBreach(
				commitSpend, remoteCommit,
				broadcastStateNum,
			)
			if err != nil {
				log.Errorf("unable to handle channel "+
					"breach for chan_point=%v: %v",
					c.cfg.chanState.FundingOutpoint, err)
			}
		}

		// Now that a spend has been detected, we've done our
		// job, so we'll exit immediately.
		return

	// The chainWatcher has been signalled to exit, so we'll do so now.
	case <-c.quit:
		return
	}
}

// toSelfAmount takes a transaction and returns the sum of all outputs that pay
// to a script that the wallet controls. If no outputs pay to us, then we
// return zero. This is possible as our output may have been trimmed due to
// being dust.
func (c *chainWatcher) toSelfAmount(tx *wire.MsgTx) btcutil.Amount {
	var selfAmt btcutil.Amount
	for _, txOut := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			// Doesn't matter what net we actually pass in.
			txOut.PkScript, &chaincfg.TestNet3Params,
		)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if c.cfg.isOurAddr(addr) {
				selfAmt += btcutil.Amount(txOut.Value)
			}
		}
	}

	return selfAmt
}

// dispatchCooperativeClose processed a detect cooperative channel closure.
// We'll use the spending transaction to locate our output within the
// transaction, then clean up the database state. We'll also dispatch a
// notification to all subscribers that the channel has been closed in this
// manner.
func (c *chainWatcher) dispatchCooperativeClose(commitSpend *chainntnfs.SpendDetail) error {
	broadcastTx := commitSpend.SpendingTx

	log.Infof("Cooperative closure for ChannelPoint(%v): %v",
		c.cfg.chanState.FundingOutpoint, spew.Sdump(broadcastTx))

	// If the input *is* final, then we'll check to see which output is
	// ours.
	localAmt := c.toSelfAmount(broadcastTx)

	// Once this is known, we'll mark the state as fully closed in the
	// database. We can do this as a cooperatively closed channel has all
	// its outputs resolved after only one confirmation.
	closeSummary := &channeldb.ChannelCloseSummary{
		ChanPoint:               c.cfg.chanState.FundingOutpoint,
		ChainHash:               c.cfg.chanState.ChainHash,
		ClosingTXID:             *commitSpend.SpenderTxHash,
		RemotePub:               c.cfg.chanState.IdentityPub,
		Capacity:                c.cfg.chanState.Capacity,
		CloseHeight:             uint32(commitSpend.SpendingHeight),
		SettledBalance:          localAmt,
		CloseType:               channeldb.CooperativeClose,
		ShortChanID:             c.cfg.chanState.ShortChanID(),
		IsPending:               true,
		RemoteCurrentRevocation: c.cfg.chanState.RemoteCurrentRevocation,
		RemoteNextRevocation:    c.cfg.chanState.RemoteNextRevocation,
		LocalChanConfig:         c.cfg.chanState.LocalChanCfg,
	}

	// Attempt to add a channel sync message to the close summary.
	chanSync, err := lnwallet.ChanSyncMsg(c.cfg.chanState)
	if err != nil {
		log.Errorf("ChannelPoint(%v): unable to create channel sync "+
			"message: %v", c.cfg.chanState.FundingOutpoint, err)
	} else {
		closeSummary.LastChanSyncMsg = chanSync
	}

	// Create a summary of all the information needed to handle the
	// cooperative closure.
	closeInfo := &CooperativeCloseInfo{
		ChannelCloseSummary: closeSummary,
	}

	// With the event processed, we'll now notify all subscribers of the
	// event.
	c.Lock()
	for _, sub := range c.clientSubscriptions {
		select {
		case sub.CooperativeClosure <- closeInfo:
		case <-c.quit:
			c.Unlock()
			return fmt.Errorf("exiting")
		}
	}
	c.Unlock()

	return nil
}

// dispatchLocalForceClose processes a unilateral close by us being confirmed.
func (c *chainWatcher) dispatchLocalForceClose(
	commitSpend *chainntnfs.SpendDetail,
	localCommit channeldb.ChannelCommitment) error {

	log.Infof("Local unilateral close of ChannelPoint(%v) "+
		"detected", c.cfg.chanState.FundingOutpoint)

	forceClose, err := lnwallet.NewLocalForceCloseSummary(
		c.cfg.chanState, c.cfg.signer, c.cfg.pCache,
		commitSpend.SpendingTx, localCommit,
	)
	if err != nil {
		return err
	}

	// As we've detected that the channel has been closed, immediately
	// creating a close summary for future usage by related sub-systems.
	chanSnapshot := forceClose.ChanSnapshot
	closeSummary := &channeldb.ChannelCloseSummary{
		ChanPoint:               chanSnapshot.ChannelPoint,
		ChainHash:               chanSnapshot.ChainHash,
		ClosingTXID:             forceClose.CloseTx.TxHash(),
		RemotePub:               &chanSnapshot.RemoteIdentity,
		Capacity:                chanSnapshot.Capacity,
		CloseType:               channeldb.LocalForceClose,
		IsPending:               true,
		ShortChanID:             c.cfg.chanState.ShortChanID(),
		CloseHeight:             uint32(commitSpend.SpendingHeight),
		RemoteCurrentRevocation: c.cfg.chanState.RemoteCurrentRevocation,
		RemoteNextRevocation:    c.cfg.chanState.RemoteNextRevocation,
		LocalChanConfig:         c.cfg.chanState.LocalChanCfg,
	}

	// If our commitment output isn't dust or we have active HTLC's on the
	// commitment transaction, then we'll populate the balances on the
	// close channel summary.
	if forceClose.CommitResolution != nil {
		closeSummary.SettledBalance = chanSnapshot.LocalBalance.ToSatoshis()
		closeSummary.TimeLockedBalance = chanSnapshot.LocalBalance.ToSatoshis()
	}
	for _, htlc := range forceClose.HtlcResolutions.OutgoingHTLCs {
		htlcValue := btcutil.Amount(htlc.SweepSignDesc.Output.Value)
		closeSummary.TimeLockedBalance += htlcValue
	}

	// Attempt to add a channel sync message to the close summary.
	chanSync, err := lnwallet.ChanSyncMsg(c.cfg.chanState)
	if err != nil {
		log.Errorf("ChannelPoint(%v): unable to create channel sync "+
			"message: %v", c.cfg.chanState.FundingOutpoint, err)
	} else {
		closeSummary.LastChanSyncMsg = chanSync
	}

	// With the event processed, we'll now notify all subscribers of the
	// event.
	closeInfo := &LocalUnilateralCloseInfo{
		commitSpend, forceClose, closeSummary,
	}
	c.Lock()
	for _, sub := range c.clientSubscriptions {
		select {
		case sub.LocalUnilateralClosure <- closeInfo:
		case <-c.quit:
			c.Unlock()
			return fmt.Errorf("exiting")
		}
	}
	c.Unlock()

	return nil
}

// dispatchRemoteForceClose processes a detected unilateral channel closure by
// the remote party. This function will prepare a UnilateralCloseSummary which
// will then be sent to any subscribers allowing them to resolve all our funds
// in the channel on chain. Once this close summary is prepared, all registered
// subscribers will receive a notification of this event. The commitPoint
// argument should be set to the per_commitment_point corresponding to the
// spending commitment.
//
// NOTE: The remoteCommit argument should be set to the stored commitment for
// this particular state. If we don't have the commitment stored (should only
// happen in case we have lost state) it should be set to an empty struct, in
// which case we will attempt to sweep the non-HTLC output using the passed
// commitPoint.
func (c *chainWatcher) dispatchRemoteForceClose(
	commitSpend *chainntnfs.SpendDetail,
	remoteCommit channeldb.ChannelCommitment,
	commitPoint *btcec.PublicKey) error {

	log.Infof("Unilateral close of ChannelPoint(%v) "+
		"detected", c.cfg.chanState.FundingOutpoint)

	// First, we'll create a closure summary that contains all the
	// materials required to let each subscriber sweep the funds in the
	// channel on-chain.
	uniClose, err := lnwallet.NewUnilateralCloseSummary(
		c.cfg.chanState, c.cfg.signer, c.cfg.pCache, commitSpend,
		remoteCommit, commitPoint,
	)
	if err != nil {
		return err
	}

	// With the event processed, we'll now notify all subscribers of the
	// event.
	c.Lock()
	for _, sub := range c.clientSubscriptions {
		select {
		case sub.RemoteUnilateralClosure <- uniClose:
		case <-c.quit:
			c.Unlock()
			return fmt.Errorf("exiting")
		}
	}
	c.Unlock()

	return nil
}

// dispatchContractBreach processes a detected contract breached by the remote
// party. This method is to be called once we detect that the remote party has
// broadcast a prior revoked commitment state. This method will prepare all the
// materials required to bring the cheater to justice, then notify all
// registered subscribers of this event.
func (c *chainWatcher) dispatchContractBreach(spendEvent *chainntnfs.SpendDetail,
	remoteCommit *channeldb.ChannelCommitment,
	broadcastStateNum uint64) error {

	log.Warnf("Remote peer has breached the channel contract for "+
		"ChannelPoint(%v). Revoked state #%v was broadcast!!!",
		c.cfg.chanState.FundingOutpoint, broadcastStateNum)

	if err := c.cfg.chanState.MarkBorked(); err != nil {
		return fmt.Errorf("unable to mark channel as borked: %v", err)
	}

	var (
		commitTxBroadcast = spendEvent.SpendingTx
		spendHeight       = uint32(spendEvent.SpendingHeight)
	)

	// Create a new breach retribution struct which contains all the data
	// needed to swiftly bring the cheating peer to justice.
	//
	// TODO(roasbeef): move to same package
	retribution, err := lnwallet.NewBreachRetribution(
		c.cfg.chanState, broadcastStateNum, commitTxBroadcast,
		spendHeight,
	)
	if err != nil {
		return fmt.Errorf("unable to create breach retribution: %v", err)
	}

	// Nil the curve before printing.
	if retribution.RemoteOutputSignDesc != nil &&
		retribution.RemoteOutputSignDesc.DoubleTweak != nil {
		retribution.RemoteOutputSignDesc.DoubleTweak.Curve = nil
	}
	if retribution.LocalOutputSignDesc != nil &&
		retribution.LocalOutputSignDesc.DoubleTweak != nil {
		retribution.LocalOutputSignDesc.DoubleTweak.Curve = nil
	}

	log.Debugf("Punishment breach retribution created: %v",
		newLogClosure(func() string {
			return spew.Sdump(retribution)
		}))

	// Hand the retribution info over to the breach arbiter.
	if err := c.cfg.contractBreach(retribution); err != nil {
		log.Errorf("unable to hand breached contract off to "+
			"breachArbiter: %v", err)
		return err
	}

	// With the event processed, we'll now notify all subscribers of the
	// event.
	c.Lock()
	for _, sub := range c.clientSubscriptions {
		select {
		case sub.ContractBreach <- retribution:
		case <-c.quit:
			c.Unlock()
			return fmt.Errorf("quitting")
		}
	}
	c.Unlock()

	// At this point, we've successfully received an ack for the breach
	// close. We now construct and persist  the close summary, marking the
	// channel as pending force closed.
	//
	// TODO(roasbeef): instead mark we got all the monies?
	// TODO(halseth): move responsibility to breach arbiter?
	settledBalance := remoteCommit.LocalBalance.ToSatoshis()
	closeSummary := channeldb.ChannelCloseSummary{
		ChanPoint:               c.cfg.chanState.FundingOutpoint,
		ChainHash:               c.cfg.chanState.ChainHash,
		ClosingTXID:             *spendEvent.SpenderTxHash,
		CloseHeight:             spendHeight,
		RemotePub:               c.cfg.chanState.IdentityPub,
		Capacity:                c.cfg.chanState.Capacity,
		SettledBalance:          settledBalance,
		CloseType:               channeldb.BreachClose,
		IsPending:               true,
		ShortChanID:             c.cfg.chanState.ShortChanID(),
		RemoteCurrentRevocation: c.cfg.chanState.RemoteCurrentRevocation,
		RemoteNextRevocation:    c.cfg.chanState.RemoteNextRevocation,
		LocalChanConfig:         c.cfg.chanState.LocalChanCfg,
	}

	// Attempt to add a channel sync message to the close summary.
	chanSync, err := lnwallet.ChanSyncMsg(c.cfg.chanState)
	if err != nil {
		log.Errorf("ChannelPoint(%v): unable to create channel sync "+
			"message: %v", c.cfg.chanState.FundingOutpoint, err)
	} else {
		closeSummary.LastChanSyncMsg = chanSync
	}

	if err := c.cfg.chanState.CloseChannel(&closeSummary); err != nil {
		return err
	}

	log.Infof("Breached channel=%v marked pending-closed",
		c.cfg.chanState.FundingOutpoint)

	return nil
}
