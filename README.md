# Network Event Monitoring System

An SNMP-based distributed network monitoring system that has 2 main components:
1. **Server** - The system that listens for traps from the node agents and queries nodes to get the current status of a node.
2. **Node Agents** - The client machine that sends traps (notification messages when an event occurs) to the server and GET responses when queried by the server.

## Requirements
* Python 3.12
* pysnmp
* cryptography
* psutil
* python-mibs
* Ensure UDP ports 5161 and 5162 are open.


## Features
Built using PySNMP for SNMPv2c trap listening and GET operations

### 1. Server (Trap Listener)
* Receives SNMPv2c traps on UDP port 5162
* Resolves OIDs using MIBs.
* Decrypts secure payloads using Fernet (AES-128)
* Logs all traps to traps.log
* Uses JSON parsing.
* Sends GET requests to query the node agents to get the node's current status.
* Simple CLI menu with options to display all the traps, trap history by node, get current status of a node or shut down the server.

### 2. Node Agent
Runs on each monitored machine.
* Sends traps to server that trigger for:
    * Node startup 
    * Node shutdown 
    * Load state changes
    * Process count spikes
    * Periodic heartbeat 
* Tracks Latency, Packet loss, Sequence numbers
* Retries on failure
* Listens for GET Requests on UDP port 5161 and responds with system info (sysDescr, sysName, etc...) and encrypted JSON metrics containing information like CPU load (1m, 5m, 15m), Process count, Uptime, Hostname and IP etc...
* Encrypts payload using Fernet


### 3. Security
* Uses Fernet symmetric encryption (AES-128) and encrypts:
    * Trap payloads
    * GET response metrics
* Protects against:
    * Tampering
    * Unauthorized inspection


## Setup steps

1. Open your terminal and run `git clone https://github.com/ananya97br/network-event-monitoring-system.git` to clone the repository.

2. Navigate to the appropriate directory and run `uv sync` to install the required dependencies.

## Usage

1. On the machine which you want to run the trap listener, run `uv run -- server.py`

2. On node agents, run `SERVER_HOST="<server-ip-address>" uv run -- node_agent.py`
<br>
Replace `server-ip-address` with your server machine's ip address.








