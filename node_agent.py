import asyncio
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone

from cryptography.fernet import Fernet

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
    load1, load5, load15 = os.getloadavg()
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
    # Encrypt the JSON payload before sending
    details_json      = json.dumps(details, sort_keys=True)
    encrypted_details = encrypt(details_json)
    uptime_ticks      = int((time.time() - STARTED_AT) * 100)  # centiseconds
    try:
        error_indication, error_status, error_index, var_binds = await send_notification(
            SnmpEngine(),
            CommunityData(COMMUNITY, mpModel=1),
            await UdpTransportTarget.create((SERVER_HOST, TRAP_PORT), timeout=2, retries=1),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(TRAP_OID)).add_varbinds(
                (ObjectIdentity("1.3.6.1.2.1.1.3.0"), TimeTicks(uptime_ticks)),
                (ObjectIdentity(EVENT_TYPE_OID),       OctetString(event_type)),
                (ObjectIdentity(EVENT_TIME_OID),       OctetString(datetime.now(timezone.utc).isoformat())),
                (ObjectIdentity(EVENT_DETAILS_OID),    OctetString(encrypted_details)),  # encrypted
            ),
        )
        if error_indication:
            log.error("Trap send failed (%s): %s", event_type, error_indication)
        elif error_status:
            log.error("Trap send failed (%s): %s", event_type, error_status.prettyPrint())
        else:
            log.info("Trap sent: %s", event_type)
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


def run_get_responder():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    dispatcher = AsyncioDispatcher()
    dispatcher.register_transport(
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(("0.0.0.0", STATUS_PORT))
    )
    dispatcher.register_recv_callback(make_get_responder())
    dispatcher.job_started(1)
    log.info("GET responder listening on 0.0.0.0:%d (SNMPv2c)", STATUS_PORT)

    try:
        dispatcher.run_dispatcher()
    except Exception as exc:
        log.error("GET responder error: %s", exc)
    finally:
        dispatcher.close_dispatcher()

# ─── Event monitor (traps) ────────────────────────────────────────────────────
async def monitor_events() -> None:
    previous = collect_status()
    await send_trap("nodeStartup", previous)
    last_heartbeat = 0.0

    while True:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        current = collect_status()

        if current["load_state"] != previous["load_state"]:
            await send_trap("loadStateChanged", {
                "previous_load_state": previous["load_state"],
                "current_load_state":  current["load_state"],
                "status": current,
            })

        proc_delta = current["process_count"] - previous["process_count"]
        if abs(proc_delta) >= PROCESS_DELTA_THRESHOLD:
            await send_trap("processCountChanged", {
                "delta":                  proc_delta,
                "previous_process_count": previous["process_count"],
                "current_process_count":  current["process_count"],
                "status": current,
            })

        now = time.time()
        if (now - last_heartbeat) >= HEARTBEAT_INTERVAL_SECONDS:
            await send_trap("heartbeat", current)
            last_heartbeat = now

        previous = current

# ─── Main ─────────────────────────────────────────────────────────────────────
async def main() -> None:
    log.info(
        "Node agent started  |  traps -> %s:%d  |  GET responder -> 0.0.0.0:%d",
        SERVER_HOST, TRAP_PORT, STATUS_PORT,
    )

    import threading
    responder_thread = threading.Thread(target=run_get_responder, daemon=True)
    responder_thread.start()

    await monitor_events()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Node agent stopped")