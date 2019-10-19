from playground.network.common.Protocol import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16,UINT32, BOOL
import logging
from playground.network.packet.fieldtypes.attributes import Optional
import random


logger = logging.getLogger("playground.__connector__." + __name__)

class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER="poop"
    DEFINITION_VERSION="1.0"

class DataPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS= [
        ("data",BUFFER),
        ("seq",UINT32),
    ]

class HandshakePacket(PoopPacketType):
    DEFINITION_IDENTIFIER =  "poop.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2

    FIELDS =[
        ("SYN",UINT32({Optional:True})),
        ("ACK",UINT32({Optional:True})),
        ("status",UINT8),
        ("error",STRING({Optional:True}))
    ]

class PassthroughProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.flag = 0

    def connection_made(self, transport):
        logger.debug("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        self.transport = transport
        packet = HandshakePacket()
        # At initialization, the client will set its SYN to be any random value between 0 and 2^32, server will set
        # its SYN anything between 0 and 2^32 and its ACK any random value between 0 and 2^32
        if self._mode == "client":
            # The client needs to send a packet with SYN and status NOT STARTED to the server to request a connection.
            self.SYN = random.randint(0,2**32)  # random value between 0 and 2**32
            packet.SYN = self.SYN
            packet.status = 0  # the status should be "NOT_STARTED" at the beginning
            #packet.ACK = random.randint(0,2**32)
            transport.write(packet.__serialize__())


    def data_received(self, buffer):
        logger.debug("{} passthrough received a buffer of size {}".format(self._mode, len(buffer)))
        # after handshake successfully, the deserializer should be changed
        # if self.flag == 0:
        #     self.buffer = HandshakePacket.Deserializer()
        #     self.buffer.update(buffer)
        # else:
        #     self.buffer = PacketType.Deserializer()
        #     self.buffer.update(buffer)
        self.buffer = PoopPacketType.Deserializer()
        self.buffer.update(buffer)

        for packet in self.buffer.nextPackets():
            print(packet)
            if self._mode == "server":
                if packet.status == 0:
                    if packet.SYN:
                        # Upon receiving packet, the server sends back a packet with random number from 0 to 2^32, ACK set to (SYN+1)%(2^32)and status SUCCESS.
                        new_packet = HandshakePacket()
                        self.ACK=random.randint(0,2**32)
                        new_packet.SYN = self.ACK
                        # get a random ACK and assign the value to SYN
                        new_packet.ACK = (packet.SYN+1)%(2**32)
                        new_packet.status = 1
                        self.transport.write(new_packet.__serialize__())
                    else:
                        new_packet = HandshakePacket()
                        new_packet.status = 2
                        self.transport.write(new_packet.__serialize__())

                elif packet.ACK == (self.ACK+1)%(2**32):
                    # Upon receiving the SUCCESS packet, the server checks if ACK is old ACK plus 1. If success, the server
                    # acknowledges this connection. Else, the server sends back a packet to the client with status
                    # ERROR.
                    higher_transport = StackingTransport(self.transport)
                    self.higherProtocol().connection_made(higher_transport)
                    self.flag = 1
                else:
                    new_packet = HandshakePacket()
                    new_packet.status = 2
                    self.transport.write(new_packet.__serialize__())

            elif self._mode == "client":
                # Upon receiving the SUCCESS packet, the client checks if new ACK is old SYN + 1. If it is correct,
                # the client sends back to server a packet with ACK set to (ACK+1)%(2^32)  and status SUCCESS and acknowledge this
                # connection with server. Else, the client sends back to server a packet with status set to ERROR.
                if packet.ACK == (self.SYN + 1)%(2**32):
                    new_packet = HandshakePacket()
                    new_packet.SYN = (packet.SYN+1)%(2**32)
                    new_packet.ACK = (packet.ACK+1)%(2**32)
                    new_packet.status = 1
                    self.flag = 1
                    self.transport.write(new_packet.__serialize__())
                    higher_transport = StackingTransport(self.transport)
                    self.higherProtocol().connection_made(higher_transport)
                else:
                    new_packet = HandshakePacket()
                    new_packet.status = 2
                    self.transport.write(new_packet.__serialize__())
            else:
                self.higherProtocol().data_received(buffer)

    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)

# from playground.network.common import StackingProtocolFactory
#
# PassthroughFactory = StackingProtocolFactory.CreateFactoryType(PassthroughProtocol)
# factory1 = PassthroughFactory()

PassthroughClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client")
)

PassthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server")
)

