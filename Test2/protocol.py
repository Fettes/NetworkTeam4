from playground.network.common.Protocol import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16,UINT32, BOOL
import logging
from playground.network.packet.fieldtypes.attributes import Optional
from random import randrange
import time
import asyncio
import binascii
import bisect

logger = logging.getLogger("playground.__connector__." + __name__)

class PoopPacketType(PacketType):
    DEFINITION_IDENTIFIER = "poop"
    DEFINITION_VERSION = "1.0"


class DataPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("seq", UINT32({Optional: True})),
        ("hash", UINT32),
        ("data", BUFFER({Optional: True})),
        ("ACK", UINT32({Optional: True})),
    ]


class HandshakePacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [
        ("SYN", UINT32({Optional: True})),
        ("ACK", UINT32({Optional: True})),
        ("status", UINT8),
        ("hash", UINT32)
    ]


class ShutdownPacket(PoopPacketType):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"

    SUCCESS = 0
    ERROR = 1

    FIELDS = [
        ("FIN", UINT32),
        ("hash", UINT32)
    ]


class ResendPacket(DataPacket):
    DEFINITION_IDENTIFIER =  "poop.resendpacket"
    DEFINITION_VERSION = "1.0"
    TIMESTAMP = 0
    SHUTDOWN = 0

class PoopTransport(StackingTransport):
    def set_protocol(self,protocol):
        self.protocol = protocol

    def write(self,data):
        self.protocol.send_data(data)

    def close(self):
        self.protocol.init_close()

class PoopProtocol(StackingProtocol):
    def __init__(self, mode):
        super().__init__()
        self._mode = mode
        self.flag = 0
        self.recv_queue = []
        self.recv_wind_size = 10
        self.send_queue = []
        self.send_wind_size = 10
        self.send_buff = []
        self.last_data = 0
        self.last_handshake = 0
        self.status = NOT_STARTED
        self.last_shutdown = 0

    def connection_made(self, transport):
        logger.debug("{} passthrough connection made. Calling connection made higher.".format(self._mode))
        self.transport = transport
        self.init_SYN = randrange(2**32)
        self.SYN = self.init_SYN
        self.ACK = randrange(2**32)
        self.loop = asyncio.get_event_loop()


        # At initialization, the client will set its SYN to be any random value between 0 and 2^32, server will set
        # its SYN anything between 0 and 2^32 and its ACK any random value between 0 and 2^32

        if self._mode == "client":
            # The client needs to send a packet with SYN and status NOT STARTED to the server to request a connection.
            packet = HandshakePacket(SYN=self.SYN, status=0, hash=0)
            packet.hash=binascii.crc32(packet.__serialize__()) & 0xffffffff
            transport.write(packet.__serialize__())
            self.SYN = (self.SYN + 1)%(2**32)
            logger.debug("client send SYN packet")
            self.last_handshake = time.time()
            self.loop.create_task(self.handshake_check())

        self.loop.create_task(self.resend_check())

    def data_received(self, buffer):
        logger.debug("{} poop received a buffer of size {}".format(self._mode, len(buffer)))

        self.deserializer = PoopPacketType.Deserializer()
        self.deserializer.update(buffer)

        for packet in self.deserializer.nextPackets():
            if packet.DEFINITION_IDENTIFIER == "poop.handshakepacket":
                self.last_handshake = time.time()
                hash_copy = packet.hash
                packet.hash = 0
                if binascii.crc32(packet.__serialize__()) & 0xffffffff == hash_copy:
                    if packet.status == 2:
                        logger.debug("{} POOP: ERROR recv a error pkt ".format(self._mode))
                        return
                    if self._mode == "server":
                        if packet.status == 0:
                            if packet.SYN and self.flag == 0:
                                # Upon receiving packet, the server sends back a packet with random number from 0 to 2^32, ACK set to (SYN+1)%(2^32)and status SUCCESS.
                                new_packet = HandshakePacket()
                                new_packet.SYN = self.SYN
                                new_packet.ACK = (packet.SYN + 1)%(2**32)
                                new_packet.status = 1
                                new_packet.hash = 0
                                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                                # get a random ACK and assign the value to SYN
                                self.transport.write(new_packet.__serialize__())
                                self.SYN = (self.SYN+1)%(2**32)
                                self.ACK = new_packet.ACK
                                logger.debug("server SYN received")
                            else:
                                new_packet = HandshakePacket(status=2, hash=0)
                                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                                transport.write(new_packet.__serialize__())
                                logger.debug("Wrong SYN packet")

                        elif packet.status == 1 and self.flag == 0:
                            if packet.ACK == self.SYN and packet.SYN == self.ACK:
                                # Upon receiving the SUCCESS packet, the server checks if ACK is old ACK plus 1. If success, the server
                                # acknowledges this connection. Else, the server sends back a packet to the client with status
                                # ERROR.
                                self.next_expected_ack = self.init_SYN
                                higher_transport = PoopTransport(self.transport)
                                higher_transport.set_protocol(self)
                                self.higherProtocol().connection_made(higher_transport)
                                self.flag = 1
                                self.SYN = self.init_SYN
                                self.ACK = (packet.SYN - 1)%(2**32)
                                logger.debug("server ACK received, handshake pass!")
                            else:
                                new_packet = HandshakePacket(status=2, hash=0)
                                new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                                transport.write(new_packet.__serialize__())
                                logger.debug("Wrong ACK reply")

                    elif self._mode == "client":
                        # Upon receiving the SUCCESS packet, the client checks if new ACK is old SYN + 1. If it is correct,
                        # the client sends back to server a packet with ACK set to (ACK+1)%(2^32)  and status SUCCESS and acknowledge this
                        # connection with server. Else, the client sends back to server a packet with status set to ERROR.
                        if packet.ACK == self.SYN and flag == 0:
                            new_packet = HandshakePacket()
                            new_packet.SYN = self.SYN
                            new_packet.ACK = (packet.SYN + 1) % (2 ** 32)
                            new_packet.status = 1
                            new_packet.hash = 0
                            new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                            self.flag = 1
                            #
                            self.ACK = packet.SYN
                            self.transport.write(new_packet.__serialize__())
                            #
                            self.SYN = self.init_SYN
                            self.next_expected_ack = self.init_SYN
                            higher_transport = PoopTransport(self.transport)
                            higher_transport.set_protocol(self)
                            self.higherProtocol().connection_made(higher_transport)
                            logger.debug("client receives right SYN/ACK packet, client hand shake pass")
                        else:
                            new_packet = HandshakePacket(status=2, hash=0)
                            new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                            transport.write(new_packet.__serialize__())
                            logger.debug("Wrong SYN/ACK reply")
                else:
                    new_packet = HandshakePacket(status=2, hash=0)
                    new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                    transport.write(new_packet.__serialize__())
                    logger.debug("Wrong hash")

            elif(packet.DEFINITION_IDENTIFIER == "poop.datapacket"):
                self.last_data = time.time()
                hash_copy = packet.hash
                packet.hash = 0
                if binascii.crc32(packet.__serialize__()) & 0xffffffff == hash_copy:
                    if self.flag == 1:
                        if packet.ACK and self.send_queue:
                            # If ACK matches seq of a pkt in send queue, take off of send queue, and update send queue
                            self.send_queue[:] = [
                                send_pkt for send_pkt in self.send_queue if send_pkt.seq > packet.ACK]
                            if self.send_queue:
                                self.next_expected_ack = self.send_queue[0].seq
                            else:
                                self.next_expected_ack = (packet.ACK + 1)%(2**32)
                            self.queue_send_pkts()
                            return

                        #data packet
                        if packet.seq < self.ACK:
                            # resent packet that has already been accept by APP
                            ack_pkt = DataPacket(ACK=packet.seq, hash=0)
                            ack_pkt.hash = binascii.crc32(ack_pkt.__serialize__()) & 0xffffffff
                            self.transport.write(ack_pkt.__serialize__())
                            return

                        if packet.seq <= self.ACK + self.recv_wind_size:

                            if packet.seq > self.ACK:
                                ack_pkt = DataPacket(ACK=(self.ACK - 1) % (2 ** 32), hash=0)
                                ack_pkt.hash = binascii.crc32(ack_pkt.__serialize__()) & 0xffffffff
                                self.transport.write(ack_pkt.__serialize__())

                            self.recv_queue.append(packet)
                            self.recv_queue.sort(key=lambda packet_: packet_.seq)

                            while self.recv_queue:
                                if self.recv_queue[0].seq == self.ACK:
                                    self.higherProtocol().data_received(self.recv_queue[0].data)
                                    #ack packet that has been accepted by APP
                                    ack_pkt = DataPacket(self.recv_queue[0].seq, hash=0)
                                    ack_pkt.hash = binascii.crc32(ack_pkt.__serialize__()) & 0xffffffff
                                    self.transport.write(ack_pkt.__serialize__())
                                    self.recv_queue.pop(0)
                                    self.ACK = (self.ACK+1)%(2**32)
                                else:
                                    break

                        else:
                            return
                    else:
                        logger.debug("Connection has not been established, data packet dropped!")
                        return
                else:
                    return

            elif packet.DEFINITION_IDENTIFIER == "poop.shutdownpacket":
                #shutdown packet:
                #self.last_shutdown = time.time()
                hash_copy = packet.hash
                packet.hash = 0
                if binascii.crc32(packet.__serialize__()) & 0xffffffff == hash_copy:
                    if self.flag == 0:
                        new_packet = HandshakePacket(status=2, hash=0)
                        new_packet.hash = binascii.crc32(new_packet.__serialize__()) & 0xffffffff
                        transport.write(new_packet.__serialize__())
                        logger.debug("Unexpected shutdown packet in handshake")
                    elif self.status == "FIN_SENT":
                        self.fack_pkt_recv(packet)
                    else:
                        # status = FIN_SENT and Shutdown Packet
                        self.fin_pkt_recv(packet)
                else:
                    return


    def send_data(self,data):
        self.send_buff += data
        self.queue_send_pkts()

    def init_close(self):
        self.send_shutdown_pkt()

    def send_shutdown_pkt(self):
        while self.send_queue:
            sleep(0.1)
        self.last_shutdown = time.time()
        print('sending shutdown packet')
        packet = ShutdownPacket(FIN=self.SYN, hash=0)
        packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff
        self.transport.write(packet.__serialize__())
        resendpacket = ResendPacket()
        resendpacket.SHUTDOWN = 1
        resendpacket.TIMESTAMP = time.time()
        resendpacket.hash = packet.hash
        self.send_queue.append(resendpacket)
        self.status = 'FIN_SENT'
        self.loop.create_task(self.shutdown_timeout_check())
        return



    def fin_pkt_recv(self,pkt):
        if pkt.FIN == self.ACK:
            fin_ack_packet = DataPacket(ACK=pkt.FIN,hash=0)
            fin_ack_packet.hash = binascii.crc32(fin_ack_packet.__serialize__()) & 0xffffffff
            self.transport.write(fin_ack_packet.__serialize__())
            self.transport.close()
            self.flag = 0

    def fack_pkt_recv(self,pkt):
        if pkt.FIN:
            self.flag = 0
            self.transport.close()

    def queue_send_pkts(self):
        while self.send_buff and len(self.send_queue) <= self.send_wind_size and self.SYN < self.next_expected_ack + self.send_wind_size:
            if len(self.send_buff) >= 15000:#14999?
                packet = DataPacket(seq = self.SYN, data = bytes(self.send_buff[0:15000]),hash=0)
                packet.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
                self.send_buff = self.send_buff[15000:]
            else:
                packet = DataPacket(seq=self.SYN, data=bytes(self.send_buff[0:],hash=0))
                packet.hash = binascii.crc32(packet.__serialize__()) & 0xffffffff
                self.send_buff = []
            if self.SYN == 2**32:
                self.SYN = 0
            else:
                self.SYN += 1

            resend_packet = ResendPacket(seq = packet.seq, data = packet.data, hash =packet.hash)
            resend_packet.TIMESTAMP = time.time()
            self.send_queue.append(resend_packet)
            self.transport.write(packet.__serialize__())

    async def resend_check(self):
        shutdown_resend_times = 0
        while True:
            current_time = time.time()
            for resend_packet in self.send_queue:
                if current_time - resend_packet.TIMESTAMP > 1:
                    if resend_packet.SHUTDOWN == 1:
                        if shutdown_resend_times == 2:
                            self.flag = 0
                            self.transport.close()
                            break
                        shutdown_resend_times += 1
                        packet = ShutdownPacket(FIN=resend_packet.seq,hash=resend_packet.hash)
                        self.transport.write(packet.__serialize__())
                        resend_packet.TIMESTAMP = current_time

                    else:
                        packet = DataPacket(seq=resend_packet.seq, data=resend_packet.data, hash=resend_packet.hash)
                        self.transport.write(packet.__serialize__())
                        resend_packet.TIMESTAMP = current_time
            await asyncio.sleep(0.1)

    async def handshake_check(self):
        handshake_resend_times = 0
        while self.flag==0:
            current_time = time.time()
            if(current_time-self.last_handshake) > 1:
                if self._mode == "client":
                    if handshake_resend_times == 2:
                        self.transport.close()
                        break
                    new_packet = HandshakePacket(SYN=self.init_SYN, status=0, hash=0)
                    new_packet.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
                    self.transport.write(new_packet.__serialize__())
                    self.SYN = (self.init_SYN+1)%(2**32)
                    self.last_handshake = current_time

                elif self._mode == "server":
                    new_packet = HandshakePacket(SYN=self.init_SYN, ACK=self.ACK,status=1, hash=0)
                    new_packet.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
                    self.transport.write(new_packet.__serialize__())
                    self.SYN = (self.init_SYN+1)%(2**32)
                    self.last_handshake = current_time

            await asyncio.sleep(1-current_time+self.last_handshake)

    async def datapacket_check(self):
        while True:
            if (time.time() - self.last_data) > 300:
                # time out after 5 min
                self.flag = 0
                self.transport.close()
            await asyncio.sleep(300 - (time.time() - self.last_data))

    def connection_lost(self, exc):
        logger.debug("{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)


PoopClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PoopProtocol(mode="client")
)

PoopthroughServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PoopProtocol(mode="server")
)

