from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pyasn1.codec.ber import decoder
from pysnmp.proto import api
from pysnmp.smi import builder, view, compiler
from pysnmp.proto import rfc1902
from pysnmp.hlapi.v3arch.asyncio import (
    get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)

import logging
import threading
import asyncio
import os
import re
from collections import defaultdict
from datetime import datetime

# ─── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("traps.log"),
    ]
)
log = logging.getLogger("traps")

# ─── MIB / OID resolution setup ──────────────────────────────────────────────
_mib_builder = builder.MibBuilder()
compiler.add_mib_compiler(_mib_builder, sources=["https://mibs.pysnmp.com/asn1/@mib@"])
_mib_builder.load_modules(
    "SNMPv2-MIB", "SNMPv2-SMI", "SNMPv2-TC",
    "IF-MIB", "IP-MIB", "TCP-MIB", "UDP-MIB",
    "HOST-RESOURCES-MIB", "ENTITY-MIB",
)
_mib_view = view.MibViewController(_mib_builder)

def resolve_oid(oid_str: str) -> str:
    try:
        oid_obj = rfc1902.ObjectName(oid_str)
        mod_name, sym_name, suffix = _mib_view.get_node_location(oid_obj)
        suffix_str = ("." + ".".join(str(x) for x in suffix)) if suffix else ""
        return f"{mod_name}::{sym_name}{suffix_str}"
    except Exception:
        return oid_str


# ─── Generic trap type mapping (RFC 1157) ────────────────────────────────────
GENERIC_TRAP_TYPES = {
    # numeric keys
    "0": "coldStart",
    "1": "warmStart",
    "2": "linkDown",
    "3": "linkUp",
    "4": "authenticationFailure",
    "5": "egpNeighborLoss",
    "6": "enterpriseSpecific",
    # named keys (newer pysnmp prettyPrint)
    "coldStart":             "coldStart",
    "warmStart":             "warmStart",
    "linkDown":              "linkDown",
    "linkUp":                "linkUp",
    "authenticationFailure": "authenticationFailure",
    "egpNeighborLoss":       "egpNeighborLoss",
    "enterpriseSpecific":    "enterpriseSpecific",
}

# Standard trap OID → trap type name (used when send_notification sets the OID)
TRAP_OID_TO_TYPE = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
}

def decode_trap_type(generic: str) -> str:
    return GENERIC_TRAP_TYPES.get(str(generic).strip(), f"unknown({generic})")


# ─── Shared state (thread-safe via lock) ─────────────────────────────────────
trap_lock = threading.Lock()
all_traps = []
traps_by_node = defaultdict(list)


def store_trap(trap: dict):
    with trap_lock:
        all_traps.append(trap)
        traps_by_node[trap["agent"]].append(trap)


# ─── SNMP GET ─────────────────────────────────────────────────────────────────
STATUS_OIDS = [
    ("SNMPv2-MIB", "sysDescr",    0),
    ("SNMPv2-MIB", "sysName",     0),
    ("SNMPv2-MIB", "sysLocation", 0),
    ("SNMPv2-MIB", "sysContact",  0),
    ("SNMPv2-MIB", "sysUpTime",   0),
    ("IF-MIB",     "ifNumber",    0),
]

def snmp_get_status(host: str, community: str = "public", port: int = 161) -> dict:
    async def _do_get():
        results = {}
        engine = SnmpEngine()
        for mib, sym, idx in STATUS_OIDS:
            try:
                error_indication, error_status, error_index, var_binds = await get_cmd(
                    engine,
                    CommunityData(community, mpModel=1),
                    await UdpTransportTarget.create((host, port), timeout=2, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(mib, sym, idx)),
                )
                if error_indication:
                    results[f"{mib}::{sym}.{idx}"] = f"ERROR: {error_indication}"
                elif error_status:
                    results[f"{mib}::{sym}.{idx}"] = (
                        f"ERROR: {error_status.prettyPrint()} at "
                        f"{error_index and var_binds[int(error_index) - 1][0] or '?'}"
                    )
                else:
                    for oid, val in var_binds:
                        results[resolve_oid(oid.prettyPrint())] = val.prettyPrint()
            except Exception as e:
                results[f"{mib}::{sym}.{idx}"] = f"EXCEPTION: {e}"
        engine.close_dispatcher()
        return results

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_do_get())
    finally:
        loop.close()


def display_node_status():
    host = input("\n  Enter node IP address : ").strip()
    community = input("  Community string [public]: ").strip() or "public"
    port_str  = input("  SNMP port [1161]: ").strip()
    port = int(port_str) if port_str.isdigit() else 1161

    print(f"\n  Polling {host}:{port} (community='{community}') ...")
    results = snmp_get_status(host, community, port)

    if not results:
        print("  [No response or no data returned]\n")
        return

    print(f"\n  === Current Status: {host} ===")
    for oid, val in results.items():
        print(f"  {oid:<45} = {val}")
    print("  " + "-" * 56)


# ─── SNMP callback ────────────────────────────────────────────────────────────
def callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))
        if msgVer in api.PROTOCOL_MODULES:
            pMod = api.PROTOCOL_MODULES[msgVer]
        else:
            log.warning("Unsupported SNMP version %s" % msgVer)
            return

        reqMsg, wholeMsg = decoder.decode(
            wholeMsg,
            asn1Spec=pMod.Message(),
        )

        reqPDU = pMod.apiMessage.get_pdu(reqMsg)
        if reqPDU.isSameTypeWith(pMod.TrapPDU()):
            trap = {"timestamp": datetime.now().isoformat(), "version": msgVer}

            if msgVer == api.SNMP_VERSION_1:
                trap["agent"]         = transportAddress[0]
                ent_oid               = pMod.apiTrapPDU.get_enterprise(reqPDU).prettyPrint()
                trap["enterprise"]    = f"{resolve_oid(ent_oid)}  ({ent_oid})"
                generic_val       = pMod.apiTrapPDU.get_generic_trap(reqPDU).prettyPrint()
                specific_val      = pMod.apiTrapPDU.get_specific_trap(reqPDU).prettyPrint()
                # Try to resolve trap type from enterprise OID first, then generic field
                trap["trap_type"] = (
                    TRAP_OID_TO_TYPE.get(ent_oid)
                    or decode_trap_type(generic_val)
                )
                trap["uptime"]        = pMod.apiTrapPDU.get_timestamp(reqPDU).prettyPrint()

                varbinds = {}
                for oid, val in pMod.apiTrapPDU.get_varbinds(reqPDU):
                    varbinds[resolve_oid(oid.prettyPrint())] = val.prettyPrint()
                trap["varbinds"] = varbinds
            else:
                # SNMPv2c trap — extract event type from enterprise varbind 53864.1.1
                trap["agent"] = transportAddress[0]
                varbinds = {}
                event_type = None
                for oid, val in pMod.apiPDU.get_varbinds(reqPDU):
                    oid_str = oid.prettyPrint()
                    val_str = val.prettyPrint()
                    if oid_str == "1.3.6.1.6.3.1.1.4.1.0":
                        # snmpTrapOID — skip, we use event_type varbind instead
                        continue
                    elif oid_str == "1.3.6.1.4.1.53864.1.1":
                        event_type = val_str
                    else:
                        varbinds[resolve_oid(oid_str)] = val_str
                trap["trap_type"] = event_type or "unknown"
                trap["enterprise"] = f"{resolve_oid('1.3.6.1.4.1.53864.1.0')}  (1.3.6.1.4.1.53864.1.0)"
                trap["uptime"] = "N/A"
                trap["varbinds"] = varbinds

            log.info("Trap from %s | %s", trap["agent"], trap.get("enterprise", ""))
            store_trap(trap)

    return wholeMsg


# ─── Background dispatcher thread ────────────────────────────────────────────
def run_dispatcher():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    transportDispatcher = AsyncioDispatcher()
    transportDispatcher.register_transport(
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(("localhost", 5162))
    )
    transportDispatcher.register_recv_callback(callback)
    transportDispatcher.job_started(1)

    log.info("SNMP trap listener started on localhost:5162")
    try:
        transportDispatcher.run_dispatcher()
    except Exception as e:
        log.error("Dispatcher error: %s", e)
    finally:
        transportDispatcher.close_dispatcher()


# ─── Display helpers ──────────────────────────────────────────────────────────
def print_trap(trap: dict):
    print(f"\n  Timestamp : {trap['timestamp']}")
    print(f"  Agent     : {trap['agent']}")
    if "enterprise" in trap:
        print(f"  Trap Type : {trap.get('trap_type', 'unknown')}")
        print(f"  Enterprise: {trap['enterprise']}")
        print(f"  Uptime    : {trap['uptime']}")
    if trap["varbinds"]:
        print("  VarBinds:")
        for oid, val in trap["varbinds"].items():
            print(f"    {oid} = {val}")
    else:
        print("  VarBinds  : none")
    print("  " + "-" * 56)


def display_all_traps():
    with trap_lock:
        snapshot = list(all_traps)

    if snapshot:
        print(f"\n  === All Traps ({len(snapshot)} total) ===")
        for trap in snapshot:
            print_trap(trap)
    else:
        print("\n  [No traps yet — watching for incoming...]\n")

    last_seen = len(snapshot)
    print("\n  -- Live mode: new traps will appear below. Press Enter to return to menu --")

    stop_event = threading.Event()

    def watch():
        nonlocal last_seen
        while not stop_event.is_set():
            with trap_lock:
                current_len = len(all_traps)
                new_traps = list(all_traps[last_seen:current_len])
            if new_traps:
                for trap in new_traps:
                    print_trap(trap)
                last_seen = current_len
            stop_event.wait(timeout=1)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()

    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        stop_event.set()
        watcher.join(timeout=2)


def display_node_history():
    node = input("\n  Enter node IP address: ").strip()
    with trap_lock:
        traps = list(traps_by_node.get(node, []))

    if not traps:
        print(f"\n  [No traps recorded for {node}]\n")
        return

    print(f"\n  === Trap history for {node} ({len(traps)} entries) ===")
    for trap in traps:
        print_trap(trap)


# ─── Log file parser ─────────────────────────────────────────────────────────
LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+\w+\s+(.+)$"
)

def load_traps_from_log(log_path: str = "traps.log"):
    if not os.path.exists(log_path):
        return 0

    loaded = 0
    current = None
    in_varbinds = False

    def flush(trap):
        nonlocal loaded
        if trap and "agent" in trap:
            trap.setdefault("varbinds", {})
            store_trap(trap)
            loaded += 1

    with open(log_path, "r", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip()
            m = LOG_LINE_RE.match(line)
            if not m:
                if current and in_varbinds and "=" in line:
                    oid, _, val = line.strip().partition(" = ")
                    current["varbinds"][resolve_oid(oid.strip())] = val.strip()
                continue

            timestamp, body = m.group(1), m.group(2).strip()

            if body.startswith("Agent Address:"):
                flush(current)
                current = {
                    "timestamp": timestamp,
                    "agent": body.split(":", 1)[1].strip(),
                    "varbinds": {},
                    "source": "log",
                }
                in_varbinds = False

            elif current is None:
                continue

            elif body.startswith("Enterprise:"):
                raw_oid = body.split(":", 1)[1].strip()
                current["enterprise"] = f"{resolve_oid(raw_oid)}  ({raw_oid})"
                in_varbinds = False

            elif body.startswith("Uptime:"):
                current["uptime"] = body.split(":", 1)[1].strip()
                in_varbinds = False

            elif body.strip() == "VarBinds:":
                in_varbinds = True

            elif body.startswith("VarBinds:") and body != "VarBinds:":
                in_varbinds = False

            elif in_varbinds and "=" in body:
                oid, _, val = body.partition(" = ")
                current["varbinds"][resolve_oid(oid.strip())] = val.strip()

            else:
                in_varbinds = False

    flush(current)
    return loaded


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    load_traps_from_log("traps.log")

    listener = threading.Thread(target=run_dispatcher, daemon=True)
    listener.start()

    print("  SNMP Trap Listener running in background (localhost:5162)\n")

    while True:
        print("\n  ┌──────────────────────────────────┐")
        print("  │              MENU                │")
        print("  ├──────────────────────────────────┤")
        print("  │  1. Display all traps            │")
        print("  │  2. Trap history by node         │")
        print("  │  3. Get current status of node   │")
        print("  │  4. Exit                         │")
        print("  └──────────────────────────────────┘")

        try:
            choice = input("  Select option [1-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Shutting down...")
            break

        if choice == "1":
            display_all_traps()
        elif choice == "2":
            display_node_history()
        elif choice == "3":
            display_node_status()
        elif choice == "4":
            print("\n  Shutting down...\n")
            break
        else:
            print("\n  Invalid option. Please enter 1, 2, 3, or 4.\n")


if __name__ == "__main__":
    main()