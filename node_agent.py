"""
Network Event Monitoring System - Node Agent

Runs on each monitored machine and performs three tasks:
1. Collects system status (CPU, uptime, IP, processes)
2. Detects events and sends SNMP traps with retries to the server
3. Responds to SNMP GET requests from the server

Enhancements:
- Trap send retries (configurable MAX_TRAP_RETRIES)
- Sequence numbers in every trap for server-side packet loss detection
- Trap send latency logged per event
- Robust error handling for abrupt disconnections and edge cases
- nodeShutdown trap sent before exit on Ctrl+C
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

# Retry settings for trap sending
MAX_TRAP_RETRIES = 3
TRAP_RETRY_DELAY = 1.0

# ─── Symmetric encryption (Fernet / AES-128) ─────────────────────────────────
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

# ─── Sequence counter for packet-loss detection ───────────────────────────────
_trap_seq_lock = asyncio.Lock()
_trap_seq      = 0

async def _next_seq() -> int:
    global _trap_seq
    async with _trap_seq_lock:
        _trap_seq += 1
        return _trap_seq

# ─── Trap stats ───────────────────────────────────────────────────────────────
trap_send_latencies: list[float] = []
trap_send_failures:  int         = 0
trap_send_successes: int         = 0


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
    if hasattr(os, "getloadavg"):
        load1, load5, load15 = os.getloadavg()
    else:
        cpu_percent = psutil.cpu_percent(interval=1)
        load1 = load5 = load15 = (cpu_percent / 100) * cpu_count

    try:
        process_count = len([p for p in os.listdir("/proc") if p.isdigit()])
    except (PermissionError, FileNotFoundError):
        process_count = len(psutil.pids())

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


# ─── SNMP trap sender with retries ───────────────────────────────────────────
async def send_trap(event_type: str, details: dict) -> bool:
    """
    Send an SNMP trap with up to MAX_TRAP_RETRIES attempts.
    """
    global trap_send_failures, trap_send_successes

    seq          = await _next_seq()
    # Convert the event details dictionary into a JSON string
    details_json = json.dumps(details, sort_keys=True)
    # Encrypt the JSON string before sending for security
    encrypted    = encrypt(details_json)
    # Calculate how long the program has been running in centiseconds    
    # SNMP TimeTicks use 1 tick = 1/100 second
    uptime_ticks = int((time.time() - STARTED_AT) * 100)
    agent_ts     = datetime.now(timezone.utc).isoformat()

    for attempt in range(1, MAX_TRAP_RETRIES + 1):
        t0 = time.monotonic()
        try:
            # Create SNMP engine object
            engine    = SnmpEngine()
            transport = await UdpTransportTarget.create(
                (SERVER_HOST, TRAP_PORT),
                timeout=2,
                retries=1,
            )

            # Send an SNMP trap notification asynchronously
            error_indication, error_status, error_index, var_binds = await send_notification(
                engine,
                # Set SNMP community string, mpModel=1 means SNMPv2c
                CommunityData(COMMUNITY, mpModel=1),
                transport,
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
                    (ObjectIdentity(EVENT_TIME_OID), OctetString(agent_ts)),
                    # Custom OID containing encrypted event details
                    (ObjectIdentity(EVENT_DETAILS_OID), OctetString(encrypted)),
                ),
            )

            elapsed = time.monotonic() - t0

            # If network or transport-level error occurred
            if error_indication:
                log.warning("Trap send attempt %d/%d failed (%s): %s",attempt, MAX_TRAP_RETRIES, event_type, error_indication)
            # If SNMP protocol-level error occurred
            elif error_status:
                log.warning("Trap send attempt %d/%d SNMP error (%s): %s",attempt, MAX_TRAP_RETRIES, event_type,error_status.prettyPrint())
            else:
                trap_send_latencies.append(elapsed)
                trap_send_successes += 1
                log.info("Trap sent (seq=%d, attempt=%d, latency=%.0fms): %s",
                         seq, attempt, elapsed * 1000, event_type)
                try:
                    engine.close_dispatcher()
                except Exception:
                    pass
                return True

            try:
                engine.close_dispatcher()
            except Exception:
                pass

        except Exception as exc:
            log.warning("Trap send attempt %d/%d exception (%s): %s",
                        attempt, MAX_TRAP_RETRIES, event_type, exc)

        if attempt < MAX_TRAP_RETRIES:
            await asyncio.sleep(TRAP_RETRY_DELAY)

    trap_send_failures += 1
    log.error("Trap FAILED after %d attempts (seq=%d): %s",
              MAX_TRAP_RETRIES, seq, event_type)
    return False


# ─── SNMP GET responder (port 5161) ───────────────────────────────────────────
def _build_get_response(req_msg, pMod, status: dict) -> bytes:
    req_pdu = pMod.apiMessage.get_pdu(req_msg)

    # Encrypt the JSON payload before putting it in the GET response
    details_json      = json.dumps(status, sort_keys=True)
    encrypted_details = encrypt(details_json)
    uptime_ticks      = int((time.time() - STARTED_AT) * 100)

    oid_values = {
        SYS_DESCR_OID:     pMod.OctetString(f"Node agent on {status['node']} running Python"),
        SYS_NAME_OID:      pMod.OctetString(status["node"]),
        SYS_LOCATION_OID:  pMod.OctetString(status.get("ip", "unknown")),
        SYS_CONTACT_OID:   pMod.OctetString("node-agent"),
        SYS_UPTIME_OID:    pMod.TimeTicks(uptime_ticks),
        IF_NUMBER_OID:     pMod.Integer(0),
        EVENT_TYPE_OID:    pMod.OctetString("getResponse"),
        EVENT_TIME_OID:    pMod.OctetString(status["timestamp"]),
        EVENT_DETAILS_OID: pMod.OctetString(encrypted_details),
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

#-----------------------------------------------------------------------------------
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
    # Collect initial snapshot; retry if it fails
    for attempt in range(1, 4):
        try:
            previous = collect_status()
            break
        except Exception as exc:
            log.warning("collect_status attempt %d failed: %s", attempt, exc)
            if attempt == 3:
                log.error("Cannot collect initial status; aborting monitor.")
                return
            await asyncio.sleep(2)

    await send_trap("nodeStartup", previous)

    last_heartbeat = 0.0

    try:
        while True:
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

            try:
                current = collect_status()
            except Exception as exc:
                log.warning("collect_status failed during poll: %s", exc)
                continue

            # ── Load state change ──
            if current["load_state"] != previous["load_state"]:
                await send_trap("loadStateChanged", {
                    "previous_load_state": previous["load_state"],
                    "current_load_state":  current["load_state"],
                    "status": current,
                })

            # ── Process count spike ──
            proc_delta = current["process_count"] - previous["process_count"]
            if abs(proc_delta) >= PROCESS_DELTA_THRESHOLD:
                await send_trap("processCountChanged", {
                    "delta":                  proc_delta,
                    "previous_process_count": previous["process_count"],
                    "current_process_count":  current["process_count"],
                    "status": current,
                })

            # ── Heartbeat ──
            now = time.time()
            if (now - last_heartbeat) >= HEARTBEAT_INTERVAL_SECONDS:
                await send_trap("heartbeat", current)
                last_heartbeat = now

            previous = current

    except asyncio.CancelledError:
        # Ctrl+C cancels the task — send shutdown trap before propagating
        log.info("Shutdown detected — sending nodeShutdown trap...")
        try:
            await send_trap("nodeShutdown", collect_status())
        except Exception as exc:
            log.warning("nodeShutdown trap failed: %s", exc)
        raise  # re-raise so asyncio can clean up properly


# ─── Main ─────────────────────────────────────────────────────────────────────
async def main() -> None:
    log.info(
        "Node agent started  |  traps -> %s:%d  |  GET responder -> 0.0.0.0:%d",
        SERVER_HOST, TRAP_PORT, STATUS_PORT,
    )

    import threading
    responder_thread = threading.Thread(target=run_get_responder, daemon=True)
    responder_thread.start()

    try:
        await monitor_events()
    except asyncio.CancelledError:
        pass  # already handled inside monitor_events


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass  # clean exit; nodeShutdown trap already sent inside monitor_events
    finally:
        total   = trap_send_successes + trap_send_failures
        loss    = (trap_send_failures / total * 100) if total else 0.0
        avg_lat = (sum(trap_send_latencies) / len(trap_send_latencies) * 1000
                   if trap_send_latencies else 0.0)
        log.info(
            "Trap stats — sent: %d  failed: %d  loss: %.1f%%  avg_latency: %.0f ms",
            trap_send_successes, trap_send_failures, loss, avg_lat,
        )