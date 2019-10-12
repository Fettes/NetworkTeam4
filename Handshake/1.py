
from playground.network.packet import PacketType


class HandshakePacket(PacketType):
    DEFINITION_IDENTIFIER = "handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2
    FIELDS = [
        ("SYN",UINT8({Optional:True})),
        ("ACK",UINT8({Optional:True})),
        ("status", UINT8),
        ("error",STRING({Optional:True}))
    ]