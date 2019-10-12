import asyncio
import playground

from playground.network.packet import PacketType
from playground.network.protocols.vsockets import VNICDumpProtocol
from playground.network.protocols.packets.switching_packets import WirePacket

from Game_Bank.datasave import *


class Protocol_factory(VNICDumpProtocol):
    def __init__(self, loop):
        self.loop = loop
        self.deserializer = PacketType.Deserializer()
        pass

    def data_received(self, data_bytes):
        self.deserializer.update(data_bytes)
        for packet in self.deserializer.nextPackets():
            if isinstance(packet, WirePacket):
                print(packet.source)
                print(packet.sourcePort)
                print(packet.destination)
                print(packet.destinationPort)
                print(packet.data)
                if "OpenSession".encode() in packet.data:
                    print(packet.source)
                    print(packet.sourcePort)
                    print(packet.destination)
                    print(packet.destinationPort)
                    print(packet.data)



if __name__ == "__main__":
    createFile()
    loop = asyncio.get_event_loop()
    # Each client connection will create a new protocol instance
    coro = playground.connect.raw_vnic_connection(lambda: Protocol_factory(loop), vnicName="default")
    server = loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
