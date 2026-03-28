from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pyasn1.codec.ber import decoder
from pysnmp.proto import api, rfc1902
from pysnmp.smi import builder, view, compiler
from pysnmp.hlapi.v3arch.asyncio import (
    get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)
import logging
import threading
import asyncio
import os
import json
from collections import defaultdict
from datetime import datetime

# ─── Logging setup ────────────────────────────────────────────────────────────
_file_handler = logging.FileHandler("traps.log")
_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[_file_handler],
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


# ─── SNMPv2c trap OID → type name ────────────────────────────────────────────
TRAP_OID_TO_TYPE = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
}

# ─── Shared state (thread-safe via lock) ─────────────────────────────────────
trap_lock = threading.Lock()
all_traps: list[dict] = []
traps_by_node: dict[str, list[dict]] = defaultdict(list)


def store_trap(trap: dict):
    with trap_lock:
        all_traps.append(trap)
        traps_by_node[trap["agent"]].append(trap)


# ─── SNMP GET (port 5161) ─────────────────────────────────────────────────────
# Standard MIB OIDs — the server sends GET, the node agent replies with GET-Response
STATUS_OIDS_MIB = [
    ("SNMPv2-MIB", "sysDescr",    0),
    ("SNMPv2-MIB", "sysName",     0),
    ("SNMPv2-MIB", "sysLocation", 0),
    ("SNMPv2-MIB", "sysContact",  0),
    ("IF-MIB",     "ifNumber",    0),
]

STATUS_OIDS_ENTERPRISE = [
    "1.3.6.1.4.1.53864.1.1",   # event / trap type string
    "1.3.6.1.4.1.53864.1.2",   # ISO timestamp from agent
    "1.3.6.1.4.1.53864.1.3",   # JSON payload: cpu_count, load_*, ip, node, uptime…
]


def snmp_get_status(host: str, community: str = "public", port: int = 5161) -> dict:
    async def _do_get():
        results: dict[str, str] = {}
        engine    = SnmpEngine()
        auth      = CommunityData(community, mpModel=1)   # SNMPv2c
        transport = await UdpTransportTarget.create(
            (host, port), timeout=2, retries=1
        )

        # ── Batch 1: standard MIB OIDs ───────────────────────
        for mib, sym, idx in STATUS_OIDS_MIB:
            try:
                err_ind, err_status, err_idx, var_binds = await get_cmd(
                    engine, auth, transport, ContextData(),
                    ObjectType(ObjectIdentity(mib, sym, idx)),
                )
                key = f"{mib}::{sym}.{idx}"
                if err_ind:
                    results[key] = f"ERROR: {err_ind}"
                elif err_status:
                    at = err_idx and var_binds[int(err_idx) - 1][0] or "?"
                    results[key] = f"ERROR: {err_status.prettyPrint()} at {at}"
                else:
                    for oid, val in var_binds:
                        results[resolve_oid(oid.prettyPrint())] = val.prettyPrint()
            except Exception as exc:
                results[f"{mib}::{sym}.{idx}"] = f"EXCEPTION: {exc}"

        # ── Batch 2: enterprise OIDs (custom node metrics) ───
        for raw_oid in STATUS_OIDS_ENTERPRISE:
            label = resolve_oid(raw_oid)
            try:
                err_ind, err_status, err_idx, var_binds = await get_cmd(
                    engine, auth, transport, ContextData(),
                    ObjectType(ObjectIdentity(raw_oid)),
                )
                if err_ind:
                    results[label] = f"ERROR: {err_ind}"
                elif err_status:
                    results[label] = f"ERROR: {err_status.prettyPrint()}"
                else:
                    for oid, val in var_binds:
                        results[resolve_oid(oid.prettyPrint())] = val.prettyPrint()
            except Exception as exc:
                results[label] = f"EXCEPTION: {exc}"

        engine.close_dispatcher()
        return results

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_do_get())
    finally:
        loop.close()


def display_node_status():
    host      = input("\n  Enter node IP address : ").strip()
    community = input("  Community string [public]: ").strip() or "public"

    print(f"\n  Sending GET to agent {host}:5161 ...")

    results = snmp_get_status(host, community, 5161)

    print(f"\n  {'=' * 54}")
    print(f"  Node Status  —  {host}")
    print(f"  {'=' * 54}")

    if not results:
        print("  [No GET-Response received from agent]\n")
        return

    # Enterprise JSON payload (53864.1.3) is pretty-printed separately
    enterprise_json_key = next(
        (k for k in results if "53864.1.3" in k), None
    )

    # ── Standard + non-JSON enterprise values ────────────────
    for oid, val in results.items():
        if oid == enterprise_json_key:
            continue
        label = oid.split("::")[-1] if "::" in oid else oid
        print(f"  {label:<32} {val}")

    # ── Enterprise JSON metrics (cpu, load, node name, …) ────
    if enterprise_json_key:
        raw = results[enterprise_json_key]
        print(f"\n  [ Node Metrics ]")
        try:
            payload = json.loads(raw)
            for k, v in payload.items():
                print(f"  {k:<32} {v}")
        except (json.JSONDecodeError, TypeError):
            print(f"  {raw}")

    print(f"  {'-' * 54}\n")


# ─── SNMP trap callback (SNMPv2c only, port 5162) ────────────────────────────
def callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))

        # Accept SNMPv2c only
        if msgVer != api.SNMP_VERSION_2C:
            log.warning("Dropped non-SNMPv2c message (version=%s)", msgVer)
            return

        pMod = api.PROTOCOL_MODULES[msgVer]
        reqMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        reqPDU = pMod.apiMessage.get_pdu(reqMsg)

        if not reqPDU.isSameTypeWith(pMod.TrapPDU()):  # Fixed: TrapV2PDU → TrapPDU
            return

        agent      = transportAddress[0]
        varbinds: dict[str, str] = {}
        trap_oid: str | None     = None
        event_type: str | None   = None

        for oid, val in pMod.apiTrapPDU.get_varbinds(reqPDU):
            oid_str = oid.prettyPrint()
            val_str = val.prettyPrint()

            if oid_str == "1.3.6.1.6.3.1.1.4.1.0":       # snmpTrapOID
                trap_oid   = val_str
                event_type = TRAP_OID_TO_TYPE.get(val_str)
            elif oid_str == "1.3.6.1.4.1.53864.1.1":      # enterprise event type
                event_type = val_str
            else:
                varbinds[resolve_oid(oid_str)] = val_str

        trap = {
            "ts":         datetime.now().isoformat(),
            "agent":      agent,
            "version":    "SNMPv2c",
            "trap_type":  event_type or (TRAP_OID_TO_TYPE.get(trap_oid) if trap_oid else None) or "unknown",
            "trap_oid":   trap_oid,
            "enterprise": resolve_oid("1.3.6.1.4.1.53864.1.0"),
            "varbinds":   varbinds,
        }

        # One compact JSON line per trap
        log.info(json.dumps(trap, separators=(",", ":")))
        store_trap(trap)

    return wholeMsg


# ─── Background dispatcher thread (port 5162) ────────────────────────────────
def run_dispatcher():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    transportDispatcher = AsyncioDispatcher()
    transportDispatcher.register_transport(
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(("0.0.0.0", 5162))
    )
    transportDispatcher.register_recv_callback(callback)
    transportDispatcher.job_started(1)
    log.info(json.dumps({"event": "listener_started", "host": "0.0.0.0", "port": 5162}))

    try:
        transportDispatcher.run_dispatcher()
    except Exception as e:
        log.error(json.dumps({"event": "dispatcher_error", "error": str(e)}))
    finally:
        transportDispatcher.close_dispatcher()


# ─── Display helpers ──────────────────────────────────────────────────────────
def print_trap(trap: dict):
    print(f"\n  Timestamp : {trap.get('ts', trap.get('timestamp', 'N/A'))}")
    print(f"  Agent     : {trap['agent']}")
    print(f"  Trap Type : {trap.get('trap_type', 'unknown')}")
    varbinds = trap.get("varbinds", {})
    if varbinds:
        print("  VarBinds:")
        for oid, val in varbinds.items():
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
                new_traps   = list(all_traps[last_seen:current_len])
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


# ─── JSON log parser ──────────────────────────────────────────────────────────
def load_traps_from_log(log_path: str = "traps.log") -> int:
    """
    Each trap line: "2026-03-22 20:00:54,049 INFO {…json…}"
    Skips meta-event lines (no "agent" key) and malformed lines silently.
    """
    if not os.path.exists(log_path):
        return 0

    loaded = 0
    with open(log_path, "r", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            brace = line.find("{")
            if brace == -1:
                continue
            try:
                trap = json.loads(line[brace:])
            except json.JSONDecodeError:
                continue
            if "agent" not in trap:
                continue
            store_trap(trap)
            loaded += 1

    return loaded


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    load_traps_from_log("traps.log")

    listener = threading.Thread(target=run_dispatcher, daemon=True)
    listener.start()
    print("  SNMP Trap Listener running in background")

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