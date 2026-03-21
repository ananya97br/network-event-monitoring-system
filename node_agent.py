import asyncio
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    NotificationType,
    ObjectIdentity,
    OctetString,
    SnmpEngine,
    UdpTransportTarget,
    send_notification,
)

SERVER_HOST               = os.getenv("SERVER_HOST", "127.0.0.1")
TRAP_PORT                 = int(os.getenv("TRAP_PORT", "5162"))
STATUS_PORT               = int(os.getenv("STATUS_PORT", "9161"))
COMMUNITY                 = os.getenv("COMMUNITY", "public")
POLL_INTERVAL_SECONDS     = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
HEARTBEAT_INTERVAL_SECONDS= int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "60"))
LOAD_HIGH_FACTOR          = float(os.getenv("LOAD_HIGH_FACTOR", "1.0"))
PROCESS_DELTA_THRESHOLD   = int(os.getenv("PROCESS_DELTA_THRESHOLD", "20"))

TRAP_OID          = "1.3.6.1.4.1.53864.1.0"
EVENT_TYPE_OID    = "1.3.6.1.4.1.53864.1.1"
EVENT_TIME_OID    = "1.3.6.1.4.1.53864.1.2"
EVENT_DETAILS_OID = "1.3.6.1.4.1.53864.1.3"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("node-agent")

STARTED_AT = time.time()


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
    process_count = len([pid for pid in os.listdir("/proc") if pid.isdigit()])
    return {
        "node":          _hostname(),
        "ip":            _local_ip(),
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "uptime_seconds":int(time.time() - STARTED_AT),
        "cpu_count":     cpu_count,
        "load_1m":       round(load1,  3),
        "load_5m":       round(load5,  3),
        "load_15m":      round(load15, 3),
        "load_state":    "high" if load1 >= (cpu_count * LOAD_HIGH_FACTOR) else "normal",
        "process_count": process_count,
    }


async def send_trap(event_type: str, details: dict) -> None:
    details_json = json.dumps(details, sort_keys=True)
    try:
        error_indication, error_status, error_index, var_binds = await send_notification(
            SnmpEngine(),
            CommunityData(COMMUNITY, mpModel=1),
            await UdpTransportTarget.create((SERVER_HOST, TRAP_PORT), timeout=2, retries=1),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(TRAP_OID)).add_varbinds(
                (ObjectIdentity(EVENT_TYPE_OID),    OctetString(event_type)),
                (ObjectIdentity(EVENT_TIME_OID),    OctetString(datetime.now(timezone.utc).isoformat())),
                (ObjectIdentity(EVENT_DETAILS_OID), OctetString(details_json)),
            ),
        )
        if error_indication:
            log.error("Trap send failed (%s): %s", event_type, error_indication)
            return
        if error_status:
            log.error("Trap send failed (%s): %s", event_type, error_status.prettyPrint())
            return
        log.info("Trap sent: %s", event_type)
    except Exception as exc:
        log.exception("Trap send exception (%s): %s", event_type, exc)


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


async def main() -> None:
    log.info("Node agent started. Traps -> %s:%d", SERVER_HOST, TRAP_PORT)
    await monitor_events()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Node agent stopped")