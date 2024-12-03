# Arch-Network Node

## Building

### Earthly (Recommended)
This is the recommended way of building this repo as all dependencies are self-contained.

#### Pre-Requisites
- [Earthly](https://earthly.dev/get-earthly)

#### Build
To build the repo, run:
```shell
earthly +local
```
The built binary will be available at: `./arch-node`

### Local Build

#### Pre-Requisites
- [Rust](https://www.rust-lang.org/tools/install)
- make
- clang/llvm
- libssl-dev/openssl-dev
- pkg-config

##### Ubuntu/Debian
```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt-get update
sudo apt-get install make clang libssl-dev pkg-config
```

##### macOS
```shell
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install other dependencies
brew install make llvm openssl pkg-config
```

#### Build
To build the repo, run:
```shell
cargo build --release
```
The built binary will be available at: `./target/release/arch-node`

## Network Setup

### 1. Generate Peer IDs
Before starting any nodes, generate peer IDs for each node (boot node, leader, and validators):

For bootnode:
```shell
cargo run -p bootnode -- --generate-peer-id -d ./.arch-data/bootnode
```

For leader and validators:
```shell
cargo run -p validator -- --generate-peer-id -d ./.arch-data/<node_type>
```
Replace `<node_type>` with leader, validator1, validator2, etc.

### 2. Start the Boot Node
```shell 
cargo run -p bootnode -- -n localnet -d ./.arch-data/bootnode --p2p-bind-port 19001 --leader-peer-id "<LEADER_PEER_ID>"
```
Note the boot node's address, which will be in the format: `/ip4/<IP>/tcp/19001/p2p/<PEER_ID>`

### 3. Start the Leader Node
```shell
cargo run -p validator -- -n localnet -d ./.arch-data/leader -b "<BOOTNODE_ADDRESS>" --p2p-bind-port 29001 --rpc-bind-port 9001 --monitor-bind-port 8080
```

### 4. Start Validator Nodes
For each validator node, run:
```shell
cargo run -p validator -- -n localnet -d ./.arch-data/validator<N> -b "<BOOTNODE_ADDRESS>" --p2p-bind-port <UNIQUE_PORT> --rpc-bind-port <UNIQUE_PORT> --monitor-bind-port <UNIQUE_PORT>
```
Replace `<N>` with the validator number, and use unique ports for each validator.

## Network Modes
- `localnet`: For local development and testing
- `devnet`: Development network
- `testnet`: Test network
- `mainnet`: Main network (use with caution)

## Port Configuration
- Boot Node: Default P2P port 19001
- Leader/Validators:
  - P2P port: 29001 (default)
  - RPC port: 9001 (default)
  - Monitor port: 8080 (default)

Ensure each node uses unique ports if running multiple on the same machine.

## Network Requirements
For `devnet`, `testnet`, and `mainnet`:
- Nodes must be publicly reachable from the internet
- If behind NAT, forward the P2P port (default 29001) to your node's private IP
- Ensure no firewalls block incoming TCP connections to the P2P port

## Monitoring
Access the monitoring endpoint at `http://<IP>:<MONITOR_PORT>`. Default is `127.0.0.1:8080`.

## Security Notes
- Use strong, unique passwords for each node's private key
- Keep your Bitcoin RPC credentials secure
- Regularly update your nodes to the latest version

## Troubleshooting
- Ensure all nodes use the same network mode
- Verify that the boot node address is correct for all nodes
- Check firewall and port forwarding settings if nodes can't connect

For additional help, consult the project documentation or contact the development team.