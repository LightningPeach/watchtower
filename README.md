## Lightning Network Daemon

[![Build Status](https://img.shields.io/travis/lightningnetwork/lnd.svg)](https://travis-ci.org/lightningnetwork/lnd)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/lightningnetwork/lnd/blob/master/LICENSE)
[![Irc](https://img.shields.io/badge/chat-on%20freenode-brightgreen.svg)](https://webchat.freenode.net/?channels=lnd)
[![Godoc](https://godoc.org/github.com/lightningnetwork/lnd?status.svg)](https://godoc.org/github.com/lightningnetwork/lnd)

<img src="logo.png">

The Lightning Network Daemon (`lnd`) - is a complete implementation of a
[Lightning Network](https://lightning.network) node and currently deployed on
`testnet3` - the Bitcoin Test Network.  `lnd` has several pluggable back-end
chain services including [`btcd`](https://github.com/btcsuite/btcd) (a
full-node), [`bitcoind`](https://github.com/bitcoin/bitcoin), and
[`neutrino`](https://github.com/lightninglabs/neutrino) (a new experimental light client). The project's codebase uses the
[btcsuite](https://github.com/btcsuite/) set of Bitcoin libraries, and also
exports a large set of isolated re-usable Lightning Network related libraries
within it.  In the current state `lnd` is capable of:
* Creating channels.
* Closing channels.
* Completely managing all channel states (including the exceptional ones!).
* Maintaining a fully authenticated+validated channel graph.
* Performing path finding within the network, passively forwarding incoming payments.
* Sending outgoing [onion-encrypted payments](https://github.com/lightningnetwork/lightning-onion)
through the network.
* Updating advertised fee schedules.
* Automatic channel management ([`autopilot`](https://github.com/lightningnetwork/lnd/tree/master/autopilot)).

This implementation is a fork that supports watchtower with the help of the following commands and arguments:
* Specify interface/port to listen for watchtower peer connections after `--wtlisten` (ex. lnd [...] --wtlisten=0.0.0.0:4127).
* Connect to watchtower via addwatchtower command with \<pubkey\>@host  (ex. lncli [...] `addwatchtower` 03dabbe004ae828badd773f17ddaba7a84f8bb36e2b4029485bfa049fe0c99f09c@localhost:4127).
* If needed, clients can also send previous revocation data to watchtower on specified height interval using `sendrevdatatowt`. 
* `listwatchtowers` returns information regarding watchtowers this node established connections with.
* Use `disconnectwatchtower` to disconnect from watchtower defined by pubkey (ex. lncli [...] disconnectwatchtower --node_key=03dabbe004ae828badd773f17ddaba7a84f8bb36e2b4029485bfa049fe0c99f09c).

## Lightning Network Specification Compliance
`lnd` _fully_ conforms to the [Lightning Network specification
(BOLTs)](https://github.com/lightningnetwork/lightning-rfc). BOLT stands for:
Basis of Lightning Technology. The specifications are currently being drafted
by several groups of implementers based around the world including the
developers of `lnd`. The set of specification documents as well as our
implementation of the specification are still a work-in-progress. With that
said, the current status of `lnd`'s BOLT compliance is:

  - [X] BOLT 1: Base Protocol
  - [X] BOLT 2: Peer Protocol for Channel Management
  - [X] BOLT 3: Bitcoin Transaction and Script Formats
  - [X] BOLT 4: Onion Routing Protocol
  - [X] BOLT 5: Recommendations for On-chain Transaction Handling
  - [X] BOLT 7: P2P Node and Channel Discovery
  - [X] BOLT 8: Encrypted and Authenticated Transport
  - [X] BOLT 9: Assigned Feature Flags
  - [X] BOLT 10: DNS Bootstrap and Assisted Node Location
  - [X] BOLT 11: Invoice Protocol for Lightning Payments

## Developer Resources

The daemon has been designed to be as developer friendly as possible in order
to facilitate application development on top of `lnd`. Two primary RPC
interfaces are exported: an HTTP REST API, and a [gRPC](https://grpc.io/)
service. The exported API's are not yet stable, so be warned: they may change
drastically in the near future.

An automatically generated set of documentation for the RPC APIs can be found
at [api.lightning.community](https://api.lightning.community). A set of developer
resources including talks, articles, and example applications can be found at:
[dev.lightning.community](https://dev.lightning.community).

Finally, we also have an active
[Slack](https://join.slack.com/t/lightningcommunity/shared_invite/enQtMzQ0OTQyNjE5NjU1LWRiMGNmOTZiNzU0MTVmYzc1ZGFkZTUyNzUwOGJjMjYwNWRkNWQzZWE3MTkwZjdjZGE5ZGNiNGVkMzI2MDU4ZTE) where protocol developers, application developers, testers and users gather to
discuss various aspects of `lnd` and also Lightning in general.

## Installation
  In order to build from source, please see [the installation
  instructions](docs/INSTALL.md).

## Docker
  To run lnd from Docker, please see the main [Docker instructions](docs/DOCKER.md)
  
## IRC
  * irc.freenode.net
  * channel #lnd
  * [webchat](https://webchat.freenode.net/?channels=lnd)

## Security

The developers of `lnd` take security _very_ seriously. The disclosure of
security vulnerabilities helps us secure the health of `lnd`, privacy of our
users, and also the health of the Lightning Network as a whole.  If you find
any issues regarding security or privacy, please disclose the information
responsibly by sending an email to security at lightning dot engineering,
preferably [encrypted using our designated PGP key
(`91FE464CD75101DA6B6BAB60555C6465E5BCB3AF`) which can be found
here](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x555C6465E5BCB3AF).

## Further reading
* [Step-by-step send payment guide with docker](https://github.com/lightningnetwork/lnd/tree/master/docker)
* [Contribution guide](https://github.com/lightningnetwork/lnd/blob/master/docs/code_contribution_guidelines.md)
