from pysnmp.carrier.asyncio.dispatch import AsyncioDispatcher
from pysnmp.carrier.asyncio.dgram import udp
from pyasn1.codec.ber import encoder
from pysnmp.proto import api

pMod = api.PROTOCOL_MODULES[api.SNMP_VERSION_1]

trapPDU = pMod.TrapPDU()
pMod.apiTrapPDU.set_defaults(trapPDU)

if pMod == api.PROTOCOL_MODULES[api.SNMP_VERSION_1]:
    pMod.apiTrapPDU.set_enterprise(trapPDU, (1,3,6,1,1,2,3,4,1))
    pMod.apiTrapPDU.set_generic_trap(trapPDU,"coldStart")

trapMsg = pMod.Message()
pMod.apiMessage.set_defaults(trapMsg)
pMod.apiMessage.set_community(trapMsg, "public")
pMod.apiMessage.set_pdu(trapMsg, trapPDU)

transportDispatcher = AsyncioDispatcher()

transportDispatcher.register_transport(
    udp.DOMAIN_NAME, udp.UdpAsyncioTransport().open_client_mode()
)
transportDispatcher.send_message(
    encoder.encode(trapMsg), udp.DOMAIN_NAME, ("127.0.0.1", 5162)
)

transportDispatcher.run_dispatcher(3)
transportDispatcher.close_dispatcher()