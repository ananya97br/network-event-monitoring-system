"""
Network Event Monitoring System - Node Agent

This module runs on each monitored machine and performs three main tasks:

1. Collects current system status such as CPU load, uptime, IP address,
   and number of running processes.

2. Detects important events (high CPU load, process spikes, heartbeat, etc.)
   and securely sends them to the central monitoring server using SNMP traps.

3. Responds to SNMP GET requests so the server can directly query standard
   system information such as hostname, uptime, location, and interface count.

The agent uses:
- psutil and os modules for system monitoring
- SNMPv2c for communication
- Fernet encryption to protect event details
- asyncio for non-blocking background execution
"""
import asyncio
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone

from cryptography.fernet import Fernet

import psutil
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto import api
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    NotificationType,
    ObjectIdentity,
    OctetString,
    TimeTicks,
    SnmpEngine,
    UdpTransportTarget,
    send_notification,
)

# ─── Configuration ────────────────────────────────────────────────────────────
SERVER_HOST                = os.getenv("SERVER_HOST", "127.0.0.1")
TRAP_PORT                  = 5162
STATUS_PORT                = 5161
COMMUNITY                  = "public"
POLL_INTERVAL_SECONDS      = 5
HEARTBEAT_INTERVAL_SECONDS = 60
LOAD_HIGH_FACTOR           = 1.0
PROCESS_DELTA_THRESHOLD    = 20

# ─── Symmetric encryption (Fernet / AES-128) ─────────────────────────────────
# Must match the key in server.py exactly.
FERNET_KEY = b"x81EKjn14CbZmChtM_G1A0zFprkP7CGi_OcEX32ZBxw="
_fernet = Fernet(FERNET_KEY)


def encrypt(plaintext: str) -> str:
    """Encrypt a UTF-8 string → URL-safe base64 ciphertext string."""
    return _fernet.encrypt(plaintext.encode()).decode()


# ─── Enterprise OIDs ──────────────────────────────────────────────────────────
TRAP_OID          = "1.3.6.1.4.1.53864.1.0"
EVENT_TYPE_OID    = "1.3.6.1.4.1.53864.1.1"
EVENT_TIME_OID    = "1.3.6.1.4.1.53864.1.2"
EVENT_DETAILS_OID = "1.3.6.1.4.1.53864.1.3"

# Standard MIB OIDs the GET responder handles
SYS_DESCR_OID    = "1.3.6.1.2.1.1.1.0"
SYS_NAME_OID     = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION_OID = "1.3.6.1.2.1.1.6.0"
SYS_CONTACT_OID  = "1.3.6.1.2.1.1.4.0"
SYS_UPTIME_OID   = "1.3.6.1.2.1.1.3.0"
IF_NUMBER_OID    = "1.3.6.1.2.1.2.1.0"

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("node-agent")

STARTED_AT = time.time()

# ─── System helpers ───────────────────────────────────────────────────────────
def _hostname() -> str:
    return socket.gethostname()

def _local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()

def collect_status() -> dict:
    cpu_count = os.cpu_count() or 1
    if hasattr(os, 'getloadavg'):
        load1, load5, load15 = os.getloadavg()  # Unix/macOS only
    else:
        # Windows fallback: use current CPU utilization as a proxy
        cpu_percent = psutil.cpu_percent(interval=1)
        load1 = load5 = load15 = (cpu_percent / 100) * cpu_count
    process_count = len([p for p in os.listdir("/proc") if p.isdigit()])
    return {
        "node":           _hostname(),
        "ip":             _local_ip(),
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int(time.time() - STARTED_AT),
        "cpu_count":      cpu_count,
        "load_1m":        round(load1,  3),
        "load_5m":        round(load5,  3),
        "load_15m":       round(load15, 3),
        "load_state":     "high" if load1 >= (cpu_count * LOAD_HIGH_FACTOR) else "normal",
        "process_count":  process_count,
    }

# ─── SNMP trap sender ─────────────────────────────────────────────────────────
async def send_trap(event_type: str, details: dict) -> None:
    # Convert the event details dictionary into a JSON string
    details_json = json.dumps(details, sort_keys=True)

    # Encrypt the JSON string before sending for security
    encrypted_details = encrypt(details_json)

    # Calculate how long the program has been running in centiseconds
    # SNMP TimeTicks use 1 tick = 1/100 second
    uptime_ticks = int((time.time() - STARTED_AT) * 100)

    try:
        # Send an SNMP trap notification asynchronously
        error_indication, error_status, error_index, var_binds = await send_notification(

            # Create SNMP engine object
            SnmpEngine(),

            # Set SNMP community string, mpModel=1 means SNMPv2c
            CommunityData(COMMUNITY, mpModel=1),

            # Create UDP transport target using server IP and trap port
            # timeout=2 seconds, retries=1 if sending fails
            await UdpTransportTarget.create(
                (SERVER_HOST, TRAP_PORT),
                timeout=2,
                retries=1
            ),

            # SNMP context information
            ContextData(),

            # Specify that this is a trap message
            "trap",

            # Build the trap packet with OID and data values
            NotificationType(ObjectIdentity(TRAP_OID)).add_varbinds(

                # Standard SNMP system uptime
                (ObjectIdentity("1.3.6.1.2.1.1.3.0"), TimeTicks(uptime_ticks)),

                # Custom OID containing event type
                (ObjectIdentity(EVENT_TYPE_OID), OctetString(event_type)),

                # Custom OID containing current UTC timestamp
                (ObjectIdentity(EVENT_TIME_OID),
                 OctetString(datetime.now(timezone.utc).isoformat())),

                # Custom OID containing encrypted event details
                (ObjectIdentity(EVENT_DETAILS_OID),
                 OctetString(encrypted_details)),
            ),
        )

        # If network or transport-level error occurred
        if error_indication:
            log.error("Trap send failed (%s): %s", event_type, error_indication)

        # If SNMP protocol-level error occurred
        elif error_status:
            log.error("Trap send failed (%s): %s",
                      event_type,
                      error_status.prettyPrint())

        # Trap successfully sent
        else:
            log.info("Trap sent: %s", event_type)

    # Catch any unexpected exception during sending
    except Exception as exc:
        log.exception("Trap send exception (%s): %s", event_type, exc)

# ─── SNMP GET responder (port 5161) ───────────────────────────────────────────
def _build_get_response(req_msg, pMod, status: dict) -> bytes:
    req_pdu = pMod.apiMessage.get_pdu(req_msg)

    # Encrypt the JSON payload before putting it in the GET response
    details_json      = json.dumps(status, sort_keys=True)
    encrypted_details = encrypt(details_json)
    uptime_ticks      = int((time.time() - STARTED_AT) * 100)  # centiseconds

    oid_values = {
        SYS_DESCR_OID:     pMod.OctetString(f"Node agent on {status['node']} running Python"),
        SYS_NAME_OID:      pMod.OctetString(status["node"]),
        SYS_LOCATION_OID:  pMod.OctetString(status.get("ip", "unknown")),
        SYS_CONTACT_OID:   pMod.OctetString("node-agent"),
        SYS_UPTIME_OID:    pMod.TimeTicks(uptime_ticks),
        IF_NUMBER_OID:     pMod.Integer(0),
        EVENT_TYPE_OID:    pMod.OctetString("getResponse"),
        EVENT_TIME_OID:    pMod.OctetString(status["timestamp"]),
        EVENT_DETAILS_OID: pMod.OctetString(encrypted_details),  # encrypted
    }

    resp_pdu = pMod.GetResponsePDU()
    pMod.apiPDU.set_defaults(resp_pdu)
    pMod.apiPDU.set_request_id(resp_pdu, pMod.apiPDU.get_request_id(req_pdu))

    var_binds = []
    for req_oid, _ in pMod.apiPDU.get_varbinds(req_pdu):
        oid_str = req_oid.prettyPrint()
        if oid_str in oid_values:
            var_binds.append((req_oid, oid_values[oid_str]))
        else:
            var_binds.append((req_oid, pMod.NoSuchObject("")))

    pMod.apiPDU.set_varbinds(resp_pdu, var_binds)

    resp_msg = pMod.Message()
    pMod.apiMessage.set_defaults(resp_msg)
    pMod.apiMessage.set_community(
        resp_msg, pMod.apiMessage.get_community(req_msg)
    )
    pMod.apiMessage.set_pdu(resp_msg, resp_pdu)

    return encoder.encode(resp_msg)


def make_get_responder():
    def callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
        while wholeMsg:
            msgVer = int(api.decodeMessageVersion(wholeMsg))
            if msgVer != api.SNMP_VERSION_2C:
                log.warning("GET responder: dropped non-SNMPv2c message")
                return

            pMod = api.PROTOCOL_MODULES[msgVer]
            req_msg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
            req_pdu = pMod.apiMessage.get_pdu(req_msg)

            if not req_pdu.isSameTypeWith(pMod.GetRequestPDU()):
                return

            community = pMod.apiMessage.get_community(req_msg).prettyPrint()
            if community != COMMUNITY:
                log.warning(
                    "GET responder: wrong community '%s' from %s",
                    community, transportAddress
                )
                return

            log.info("GET request from %s", transportAddress[0])
            status = collect_status()

            try:
                resp_bytes = _build_get_response(req_msg, pMod, status)
                transportDispatcher.send_message(
                    resp_bytes, transportDomain, transportAddress
                )
                log.info("GET-Response sent to %s", transportAddress[0])
            except Exception as exc:
                log.exception("GET-Response build/send failed: %s", exc)

        return wholeMsg

    return callback
#------------------------------------------------------------------------------
#Changes made by Aditya Badde
"""
Network Event Monitoring System - Node Agent

This module runs on each monitored machine and performs three main tasks:

1. Collects system status (CPU, uptime, IP, processes)
2. Detects events and sends SNMP traps to server
3. Responds to SNMP GET requests from server
"""

def run_get_responder():
    # Create a new asyncio event loop (separate from main thread loop)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Create SNMP dispatcher (handles incoming SNMP requests)
    dispatcher = AsyncioDispatcher()

    # Register UDP transport for SNMP (listens on all interfaces at STATUS_PORT)
    dispatcher.register_transport(
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(("0.0.0.0", STATUS_PORT))
    )

    # Register callback function to handle incoming SNMP GET requests
    dispatcher.register_recv_callback(make_get_responder())

    # Inform dispatcher that one job has started (keeps it running)
    dispatcher.job_started(1)

    # Log that SNMP GET responder is active
    log.info("GET responder listening on 0.0.0.0:%d (SNMPv2c)", STATUS_PORT)

    try:
        # Start dispatcher loop (blocking call)
        dispatcher.run_dispatcher()

    except Exception as exc:
        # Log any runtime error in responder
        log.error("GET responder error: %s", exc)

    finally:
        # Cleanly close dispatcher when exiting
        dispatcher.close_dispatcher()


# ─── Event monitor (traps) ────────────────────────────────────────────────────
async def monitor_events() -> None:
    # Collect initial system status snapshot
    previous = collect_status()

    # Send startup trap when node starts
    await send_trap("nodeStartup", previous)

    # Track last heartbeat timestamp
    last_heartbeat = 0.0

    while True:
        # Wait for next polling interval
        await asyncio.sleep(POLL_INTERVAL_SECONDS)

        # Get current system status
        current = collect_status()

        # ── Check for load state change ──
        if current["load_state"] != previous["load_state"]:
            await send_trap("loadStateChanged", {
                "previous_load_state": previous["load_state"],
                "current_load_state":  current["load_state"],
                "status": current,
            })

        # ── Check for process count change beyond threshold ──
        proc_delta = current["process_count"] - previous["process_count"]
        if abs(proc_delta) >= PROCESS_DELTA_THRESHOLD:
            await send_trap("processCountChanged", {
                "delta":                  proc_delta,
                "previous_process_count": previous["process_count"],
                "current_process_count":  current["process_count"],
                "status": current,
            })

        # ── Send periodic heartbeat trap ──
        now = time.time()
        if (now - last_heartbeat) >= HEARTBEAT_INTERVAL_SECONDS:
            await send_trap("heartbeat", current)
            last_heartbeat = now

        # Update previous state for next iteration
        previous = current


# ─── Main ─────────────────────────────────────────────────────────────────────
async def main() -> None:
    # Log startup details (trap destination + responder port)
    log.info(
        "Node agent started  |  traps -> %s:%d  |  GET responder -> 0.0.0.0:%d",
        SERVER_HOST, TRAP_PORT, STATUS_PORT,
    )

    import threading

    # Run SNMP GET responder in a separate daemon thread
    # (because dispatcher.run_dispatcher() is blocking)
    responder_thread = threading.Thread(target=run_get_responder, daemon=True)
    responder_thread.start()

    # Start monitoring system events asynchronously
    await monitor_events()


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        # Start asyncio event loop and run main function
        asyncio.run(main())

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully (currently incomplete log statement)
logging.info("Shutting down node agent...")
