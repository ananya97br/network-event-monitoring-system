from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pyasn1.codec.ber import decoder
from pysnmp.proto import api, rfc1902
from pysnmp.smi import builder, view, compiler
from pysnmp.hlapi.v3arch.asyncio import (
    get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity
)
from cryptography.fernet import Fernet, InvalidToken
import logging
import threading
import asyncio
import os
import json
import time
from collections import defaultdict
from datetime import datetime

# ----------------------------- Logging setup ----------------------------------------------------------
file_handler = logging.FileHandler("traps.log") #Creates a file handler to write logs to "traps.log"
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))  # Sets log format: timestamp, log level, message for this handler
#Configures logging system to INFO level with the file handler for the whole application (default format for the entire application)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[file_handler],
)
log = logging.getLogger("traps")  # Initializes a logger instance named "traps"

# ----------------------- Symmetric encryption (Fernet / AES-128) ---------------------------------------
FERNET_KEY = b"x81EKjn14CbZmChtM_G1A0zFprkP7CGi_OcEX32ZBxw="
fernet = Fernet(FERNET_KEY) # Initializes a Fernet instance with the provided key for encryption and decryption operations


def decrypt(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext string → UTF-8 plaintext. Returns raw value on failure."""
    try:
        return fernet.decrypt(ciphertext.encode()).decode()  # encode string to bytes, decrypt, decode back to string
    except InvalidToken:
        log.warning("Decryption failed — wrong key or tampered data")   # If decryption fails, log warning and return original ciphertext
        return ciphertext


# ---------------------- MIB / OID resolution setup -------------------------------------------------------
mib_builder = builder.MibBuilder() # Initializes a MIB builder instance to manage MIB modules 
compiler.add_mib_compiler(mib_builder, sources=["https://mibs.pysnmp.com/asn1/@mib@"]) # Adds a MIB compiler that can download MIB files from the web source
# Loads standard MIB modules for translating numeric OIDs to names
mib_builder.load_modules(
    "SNMPv2-MIB", "SNMPv2-SMI", "SNMPv2-TC",
    "IF-MIB", "IP-MIB", "TCP-MIB", "UDP-MIB",
    "HOST-RESOURCES-MIB", "ENTITY-MIB",
)
mib_view = view.MibViewController(mib_builder) # Enables lookup of MIB objects within the loaded modules---queries are made

def resolve_oid(oid_str: str) -> str:
    try:
        oid_obj = rfc1902.ObjectName(oid_str)
        mod_name, sym_name, suffix = mib_view.get_node_location(oid_obj)  #  searches loaded MIBs 
        suffix_str = ("." + ".".join(str(x) for x in suffix)) if suffix else ""
        return f"{mod_name}::{sym_name}{suffix_str}"
    except Exception:
        return oid_str


TRAP_OID_TO_TYPE = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
}

# -------------------------------------------------------------------------------------
trap_lock = threading.Lock()
all_traps: list[dict] = []
traps_by_node: dict[str, list[dict]] = defaultdict(list)


def store_trap(trap: dict):
    with trap_lock:
        all_traps.append(trap)
        traps_by_node[trap["agent"]].append(trap)


# ----------------- SNMP GET with retries --------------------------------------------
STATUS_OIDS_MIB = [
    ("SNMPv2-MIB", "sysDescr",    0),
    ("SNMPv2-MIB", "sysName",     0),
    ("SNMPv2-MIB", "sysLocation", 0),
    ("SNMPv2-MIB", "sysContact",  0),
    ("IF-MIB",     "ifNumber",    0),
]

STATUS_OIDS_ENTERPRISE = [
    "1.3.6.1.4.1.53864.1.1",
    "1.3.6.1.4.1.53864.1.2",
    "1.3.6.1.4.1.53864.1.3",
]

GET_TIMEOUT = 2
GET_RETRIES = 3


def snmp_get_status(host: str, community: str = "public", port: int = 5161) -> dict:
    async def _do_get():
        results: dict[str, str] = {}
        engine = SnmpEngine()
        auth   = CommunityData(community, mpModel=1)

        for attempt in range(1, GET_RETRIES + 1):
            try:
                # Creates a UDP transport target for the specified node(host) and port (socket wrapper)
                transport = await UdpTransportTarget.create(
                    (host, port), timeout=GET_TIMEOUT, retries=1
                )
                break
            except Exception as exc:
                log.warning("GET transport create attempt %d/%d failed: %s",
                            attempt, GET_RETRIES, exc)
                if attempt == GET_RETRIES:
                    log.error("All GET transport attempts failed for %s", host)
                    return {"error": f"Cannot reach {host}:{port} after {GET_RETRIES} attempts"}
                await asyncio.sleep(1)

        for mib, sym, idx in STATUS_OIDS_MIB:
            for attempt in range(1, GET_RETRIES + 1):
                try:
                    # Sends SNMP GET command and receives response
                    err_ind, err_status, err_idx, var_binds = await get_cmd( #err_idx: index of failed varbind
                        engine, auth, transport, ContextData(),
                        ObjectType(ObjectIdentity(mib, sym, idx)),
                    )
                    key = f"{mib}::{sym}.{idx}"  #Creates readable key for the OID
                    if err_ind:
                        if attempt < GET_RETRIES:
                            log.warning("GET %s attempt %d failed (%s), retrying...",
                                        key, attempt, err_ind)
                            await asyncio.sleep(0.5)
                            continue
                        results[key] = f"ERROR: {err_ind}"
                    elif err_status: # Handle SNMP protocol errors
                        at = err_idx and var_binds[int(err_idx) - 1][0] or "?"
                        results[key] = f"ERROR: {err_status.prettyPrint()} at {at}"
                    else:
                        for oid, val in var_binds:
                            results[resolve_oid(oid.prettyPrint())] = val.prettyPrint()  #store the result with resolved OID name
                    break
                except Exception as exc:
                    if attempt < GET_RETRIES:
                        log.warning("GET %s::%s attempt %d exception: %s, retrying...",
                                    mib, sym, attempt, exc)
                        await asyncio.sleep(0.5)
                    else:
                        results[f"{mib}::{sym}.{idx}"] = f"EXCEPTION: {exc}"

        for raw_oid in STATUS_OIDS_ENTERPRISE:
            label = resolve_oid(raw_oid)
            for attempt in range(1, GET_RETRIES + 1):
                try:
                    err_ind, err_status, _, var_binds = await get_cmd(
                        engine, auth, transport, ContextData(),
                        ObjectType(ObjectIdentity(raw_oid)),
                    )
                    if err_ind:
                        if attempt < GET_RETRIES:
                            await asyncio.sleep(0.5)
                            continue
                        results[label] = f"ERROR: {err_ind}"
                    elif err_status:
                        results[label] = f"ERROR: {err_status.prettyPrint()}"
                    else:
                        for oid, val in var_binds:
                            resolved = resolve_oid(oid.prettyPrint())
                            raw_val  = val.prettyPrint()
                            if "53864.1.3" in oid.prettyPrint():
                                raw_val = decrypt(raw_val)
                            results[resolved] = raw_val
                    break
                except Exception as exc:
                    if attempt < GET_RETRIES:
                        await asyncio.sleep(0.5)
                    else:
                        results[label] = f"EXCEPTION: {exc}"

        engine.close_dispatcher()  # Clean up transport resources
        return results

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_do_get())
    finally:
        loop.close()


def display_node_status():
    host = input("\n  Enter node IP address : ").strip()
    if not host:
        print("  [No address entered]\n")
        return
    community = input("  Community string [public]: ").strip() or "public"

    print(f"\n  Sending GET to agent {host}:5161 ...")
    t0 = time.monotonic()
    results = snmp_get_status(host, community, 5161)
    elapsed_ms = round((time.monotonic() - t0) * 1000)

    print(f"\n  {'=' * 54}")
    print(f"  Node Status  —  {host}")
    print(f"  {'=' * 54}")

    if "error" in results:
        print(f"  Error: {results['error']}\n")
        return

    print(f"  GET round-trip latency : {elapsed_ms} ms")

    enterprise_json_key = next(
        (k for k in results if "53864.1.3" in k), None
    )

    for oid, val in results.items():
        if oid == enterprise_json_key:
            continue
        label = oid.split("::")[-1] if "::" in oid else oid
        print(f"  {label:<32} {val}")

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


# ------------------- SNMP trap callback --------------------------------------------
def callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))

        if msgVer != api.SNMP_VERSION_2C:
            log.warning("Dropped non-SNMPv2c message (version=%s)", msgVer)
            return

        pMod = api.PROTOCOL_MODULES[msgVer]  # Gets the protocol module for SNMPv2c
        reqMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        reqPDU = pMod.apiMessage.get_pdu(reqMsg) # Extracts the PDU 

        if not reqPDU.isSameTypeWith(pMod.TrapPDU()): # Exit if it is not a trap
            break

        agent = transportAddress[0]
        varbinds: dict[str, str] = {}
        trap_oid: str | None     = None
        event_type: str | None   = None

        for oid, val in pMod.apiTrapPDU.get_varbinds(reqPDU):
            # convert oid value to strings
            oid_str = oid.prettyPrint()
            val_str = val.prettyPrint()

            if oid_str == "1.3.6.1.6.3.1.1.4.1.0": # Check if this is the snmpTrapOID varbind
                trap_oid   = val_str
                event_type = TRAP_OID_TO_TYPE.get(val_str)  # look up event type
            elif oid_str == "1.3.6.1.4.1.53864.1.1":
                event_type = val_str
            elif oid_str == "1.3.6.1.4.1.53864.1.3":
                val_str = decrypt(val_str)
                varbinds[resolve_oid(oid_str)] = val_str
            else:
                varbinds[resolve_oid(oid_str)] = val_str

        trap = {
            "ts":         datetime.now().isoformat(),
            "agent":      agent,
            "trap_type":  event_type or (TRAP_OID_TO_TYPE.get(trap_oid) if trap_oid else None) or "unknown",
            "trap_oid":   trap_oid,
            "enterprise": resolve_oid("1.3.6.1.4.1.53864.1.0"),
            "varbinds":   varbinds,
        }

        log.info(json.dumps(trap, separators=(",", ":")))
        store_trap(trap)

    return wholeMsg


#Function to run trap listener in background thread
def run_dispatcher():
    loop = asyncio.new_event_loop() 
    asyncio.set_event_loop(loop)

    transportDispatcher = AsyncioDispatcher() # Initializes an asynchronous dispatcher to handle incoming SNMP messages using asyncio event loop
    transportDispatcher.register_transport(  # Registers a transport mechanism (UDP)
        udp.DOMAIN_NAME,
        udp.UdpAsyncioTransport().open_server_mode(("0.0.0.0", 5162)) # Opens a UDP socket on all interfaces at port 5162 to listen for incoming SNMP traps
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


# ----------------Displayyyyyyyyyyyyy-------------------------
def print_trap(trap: dict):
    print(f"\n  Timestamp : {trap.get('ts', 'N/A')}")
    print(f"  Agent     : {trap['agent']}")
    print(f"  Trap Type : {trap.get('trap_type', 'unknown')}")
    varbinds = {k: v for k, v in trap.get("varbinds", {}).items() if "sysUpTime" not in k}
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

    def watch(): # Background thread function to watch for new traps and print them as they arrive, until stop_event is set
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

    watcher = threading.Thread(target=watch, daemon=True) # daemon thread to watch for new traps without blocking main thread
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


# ------------------- JSON log parser ----------------
def load_traps_from_log(log_path: str = "traps.log") -> int:
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


def main():
    load_traps_from_log("traps.log")

    listener = threading.Thread(target=run_dispatcher, daemon=True)
    listener.start()
    print("  SNMP Trap Listener running on port 5162")

    while True:
        print("\n  ┌──────────────────────────────────────┐")
        print("  │                MENU                  │")
        print("  ├──────────────────────────────────────┤")
        print("  │  1. Display all traps                │")
        print("  │  2. Trap history by node             │")
        print("  │  3. Get current status of node       │")
        print("  │  4. Exit                             │")
        print("  └──────────────────────────────────────┘")
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
            print("\n  Invalid option. Please enter 1-4.\n")


if __name__ == "__main__":
    main()