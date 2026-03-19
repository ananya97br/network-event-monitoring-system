from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pyasn1.codec.ber import decoder
from pysnmp.proto import api
#from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",

        handlers=[
        logging.FileHandler("traps.log"),
        logging.StreamHandler()
        ]
)
log = logging.getLogger("traps")

print("I'm working")

def callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        msgVer = int(api.decodeMessageVersion(wholeMsg))
        if msgVer in api.PROTOCOL_MODULES:
            pMod = api.PROTOCOL_MODULES[msgVer]

        else:
            print("Unsupported SNMP version %s" % msgVer)
            return

        reqMsg, wholeMsg = decoder.decode(
            wholeMsg,
            asn1Spec=pMod.Message(),
        )

        print(
            "Notification message from {}:{}: ".format(
                transportDomain, transportAddress
            )
        )
        reqPDU = pMod.apiMessage.get_pdu(reqMsg)
        if reqPDU.isSameTypeWith(pMod.TrapPDU()):
            if msgVer == api.SNMP_VERSION_1:
                # write to log file and display in terminal
                log.info("Agent Address: %s" % (transportAddress[0]))
                log.info("Enterprise:    %s" % (pMod.apiTrapPDU.get_enterprise(reqPDU).prettyPrint()))
                log.info("Generic Trap:  %s" % (pMod.apiTrapPDU.get_generic_trap(reqPDU).prettyPrint()))
                log.info("Specific Trap: %s" % (pMod.apiTrapPDU.get_specific_trap(reqPDU).prettyPrint()))
                log.info("Uptime:        %s" % (pMod.apiTrapPDU.get_timestamp(reqPDU).prettyPrint()))
                varBinds = pMod.apiTrapPDU.get_varbinds(reqPDU)
                if varBinds:
                    log.info("VarBinds:")
                    for oid, val in varBinds:
                        log.info(f"{oid.prettyPrint()} = {val.prettyPrint()}")
                
                else:
                    log.info("VarBinds: \t    none")

                print("-" * 60)

    return wholeMsg










transportDispatcher = AsyncioDispatcher()

transportDispatcher.register_transport(
    udp.DOMAIN_NAME, udp.UdpAsyncioTransport().open_server_mode(("localhost",5162))
)
transportDispatcher.register_recv_callback(callback)
transportDispatcher.job_started(1)

try:
    transportDispatcher.run_dispatcher()

except KeyboardInterrupt:
    print("Shutting down...")

finally:
    transportDispatcher.close_dispatcher()



