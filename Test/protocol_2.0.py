from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
# 9:47

import binascii
import bisect

logger = logging.getLogger("playground.__connector__."+__name__)


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
        ("status", UINT8),
        ("SYN", UINT32({Optional: True})),
        ("ACK", UINT32({Optional: True})),
        ("error", STRING({Optional: True})),
        ("last_valid_sequence", UINT32({Optional: True}))
    ]


class StartupPacket(HandshakePacket):
    DEFINITION_IDENTIFIER = "poop.startuppacket"
    DEFINITION_VERSION = "1.0"


class ShutdownPacket(HandshakePacket):
    DEFINITION_IDENTIFIER = "poop.shutdownpacket"
    DEFINITION_VERSION = "1.0"


class POOPTransport(StackingTransport):
    def connect_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        self.protocol.send_data(data)

    def close(self):
        self.protocol.init_close()


class POOP(StackingProtocol):
    def __init__(self, mode):
        print("test!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        super().__init__()

        self._mode = mode
        # 0 = no connection, 1 = waiting for handshake ack, 2 = connection established, 3 = dying
        self.SYN = None
        self.FIN = None
        self.status = 0
        self.last_recv = 0          # time of last pkt received
        self.shutdown_wait_start = 0
        # sequence number of last received data pkt that was passed up to the app layer
        self.last_in_order_seq = 0
        self.recv_queue = []
        self.recv_wind_size = 10
        self.recv_next = None
        self.send_buff = []
        self.send_queue = []
        self.send_wind_size = 10
        self.send_next = None       # sequence number of next pkt to send
        self.seq = randrange(255)
        self.higher_transport = None
        self.deserializer = PoopPacketType.Deserializer()
        self.next_expected_ack = None

    def connection_made(self, transport):
        logger.debug("{} POOP: connection made".format(self._mode))
        self.loop = asyncio.get_event_loop()
        self.last_recv = time.time()
        self.loop.create_task(self.connection_timeout_check())
        self.transport = transport

        self.higher_transport = POOPTransport(transport)
        self.higher_transport.connect_protocol(self)

        self.SYN = randrange(2**32)
        self.status = "LISTEN"
        if self._mode == "client":
            # may need to change handshake to startup in the future
            self.transport.write(StartupPacket(
                SYN=self.SYN, status=0).__serialize__())
            # TODO:start timer
            self.handshake_timeout_task = self.loop.create_task(
                self.handshake_timeout_check())  # @
            self.status = 'SYN_SENT'

    # may need to change handshake to startup in the future
    def handshake_pkt_recv(self, pkt):
        logger.debug("{} POOP recv a handshake ptk".format(self._mode))
        if pkt.status == 2:
            # ERROR
            logger.debug("{} POOP: ERROR recv a error pkt ".format(self._mode))
            return
        elif self.status == "LISTEN":
            if pkt.status == 0:
                if pkt.SYN:
                    self.transport.write(StartupPacket(
                        SYN=self.SYN, ACK=pkt.SYN+1, status=1).__serialize__())
                    self.status = "SYN_SENT"
                else:
                    # ERROR: there is no SYN in the handshake packet
                    self.transport.write(StartupPacket(
                        ACK=pkt.SYN+1, status=2, error="there is no SYN in the handshake packet").__serialize__())
                    return
            elif pkt.status == 1:
                # ERROR: handshake packet status shouldn't be 1 when the server status is LISTEN
                self.transport.write(StartupPacket(
                    ACK=pkt.SYN+1, status=2, error="handshake packet status shouldn't be 1 when the server status is LISTEN").__serialize__())
                return
        elif self.status == "SYN_SENT":
            if pkt.ACK:
                if pkt.ACK == self.SYN+1:
                    if self._mode == "client":
                        self.transport.write(StartupPacket(
                            SYN=self.SYN+1, ACK=pkt.SYN+1, status=1).__serialize__())
                        self.handshake_timeout_task.cancel()
                    self.status = "ESTABLISHED"
                    self.send_next = self.SYN
                    self.next_expected_ack = self.SYN
                    self.recv_next = pkt.SYN - 1
                    self.last_recv = time.time()
                    self.higherProtocol().connection_made(self.higher_transport)
                    logger.debug(
                        "{} POOP: handshake success!".format(self._mode))
                else:
                    # ERROR: the number of ACK in handshake is not expected
                    self.transport.write(StartupPacket(
                        ACK=pkt.SYN+1, status=2, error='the number of ACK in handshake  is not expected').__serialize__())
                    return
            else:
                # ERROR: there is no ACK in handshake packet
                self.transport.write(StartupPacket(
                    ACK=pkt.SYN+1, status=2, error="there is no ACK in handshake packet").__serialize__())
                return
        elif self.status == "ESTABLISHED":
            # ERROR: recvive a handshake packet when connect ESTABLISHED
            logger.debug("recvive a handshake packet when connect ESTABLISHED")
            return
        else:
            # ERROR
            logger.debug("BUG!")
            return

    def data_received(self, buffer):
        logger.debug("{} POOP received a buffer of size {}".format(
            self._mode, len(buffer)))

        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            if pkt.DEFINITION_IDENTIFIER == "poop.startuppacket":
                self.handshake_pkt_recv(pkt)
            elif pkt.DEFINITION_IDENTIFIER == "poop.datapacket":
                # TODO:
                self.data_pkt_recv(pkt)

            elif pkt.DEFINITION_IDENTIFIER == "poop.shutdownpacket":
                # TODO:
                if self.status == 'FIN_SENT':
                    self.shutdown_pkt_recv(pkt)
                else:
                    self.init_shutdown_pkt_recv(pkt)

    async def handshake_timeout_check(self):
        while True:
            if (time.time() - self.last_recv) > 10:
                # time out after 10 sec
                self.transport.write(StartupPacket(
                    SYN=self.SYN, status=0).__serialize__())
            await asyncio.sleep(10 - (time.time() - self.last_recv))

        # this function is called when the other side initiate a shutdown (received when status == ESTABLISHED)
    def init_shutdown_pkt_recv(self, pkt):
        if pkt.DEFINITION_IDENTIFIER != "poop.shutdownpacket":
            # wrong pkt. Check calling function?
            return
        if not pkt.last_valid_sequence or not pkt.SYN:
            # missing fields
            self.transport.write(ShutdownPacket(
                status=2, error="missing field(s).").__serialize__())
            return
        # check if we received all packets up to last_valid_sequence
        if not (pkt.last_valid_sequence == self.recv_next - 1):
            self.transport.write(ShutdownPacket(
                status=2, error="have not received all pkts up to last_valid_sequence").__serialize__())
            return
        # send ShutdownPacket (Handshake PKT) with SYN, ACK = pkt.SYN+1, and status: SUCCESS
        self.SYN = randrange(2**32)
        if (pkt.SYN == 2**32):
            ACK_num = 0
        else:
            ACK_num = pkt.SYN + 1
        # may need to change handshake to startup in the future
        self.transport.write(ShutdownPacket(SYN=self.SYN, ACK=ACK_num,
                                            status=1, last_valid_sequence=self.send_next-1).__serialize__())
        self.loop.create_task(self.shutdown_timeout_check())
        self.status = 'FIN_SENT'
        return

    # this function is called when self already sent a shutdown packet (status == FIN_SENT)
    def shutdown_pkt_recv(self, pkt):
        print('shutdown pkt recived while status == FIN_SENT')
        if pkt.DEFINITION_IDENTIFIER != "poop.shutdownpacket" or self.status != 'FIN_SENT':
            # wrong pkt or wrong call (should only be called when self.status == 'FIN_SENT').
            return
        if pkt.SYN:
            if (pkt.SYN == 2**32):
                ACK_num = 0
            else:
                ACK_num = pkt.SYN + 1
            # may need to change handshake to startup in the future
            self.transport.write(ShutdownPacket(
                SYN=self.SYN, ACK=ACK_num, status=1, last_valid_sequence=self.send_next-1).__serialize__())
            self.loop.create_task(self.shutdown_timeout_check())
        if (self.SYN == 2**32):
            expected_ACK = 0
        else:
            expected_ACK = self.SYN + 1
        if pkt.ACK and pkt.ACK == expected_ACK and self.status == 'FIN_SENT':
            # fin has been acked by other agent. Teardown connection.
            self.status = 'DYING'
            self.transport.close()
        else:
            self.transport.write(ShutdownPacket(
                status=2, error="missing ACK field or wrong ACK number.").__serialize__())
        return

    # initiate a shutdown by sending the shutdownpacket
    def send_shutdown_pkt(self):
        print('sending shutdown pkt')
        self.SYN = randrange(2**32)
        # send ShutdownPacket (Handshake PKT) with SYN, and status:not start
        # may need to change handshake to startup in the future
        self.transport.write(ShutdownPacket(
            SYN=self.SYN, status=0, last_valid_sequence=self.send_next-1).__serialize__())
        self.loop.create_task(self.shutdown_timeout_check())
        self.status = 'FIN_SENT'
        return

    async def shutdown_timeout_check(self):
        shutdown_wait_start = time.time()
        await asyncio.sleep(600 - (time.time() - shutdown_wait_start))
        if self.status != 'DYING':
            self.status = 'DYING'
            self.transport.close()

    def connection_lost(self, exc):
        logger.debug(
            "{} passthrough connection lost. Shutting down higher layer.".format(self._mode))
        self.higherProtocol().connection_lost(exc)

    async def connection_timeout_check(self):
        while True:
            if (time.time() - self.last_recv) > 300:
                # time out after 5 min
                self.status = 0
                self.transport.close()
            await asyncio.sleep(300 - (time.time() - self.last_recv))

    def data_pkt_recv(self, pkt):
        # Drop if not a datapacket
        if pkt.DEFINITION_IDENTIFIER != "poop.datapacket":
            return

        # If ACK is set, handle ACK
        if pkt.ACK:
            # Check hash, drop if invalid
            pkt_copy = DataPacket(ACK=pkt.ack, hash=0)
            if binascii.crc32(pkt_copy.__serialize__()) & 0xffffffff != pkt.hash:
                return
            # If ACK matches seq of a pkt in send queue, take off of send queue, and update send queue
            self.send_queue[:] = [
                send_pkt for send_pkt in self.send_queue if send_pkt.seq != pkt.ack]
            if self.send_queue:
                self.next_expected_ack = self.send_queue[0].seq
            else:
                self.next_expected_ack = pkt.ACK + 1
            self.queue_send_pkts()
            return

        if pkt.seq <= self.recv_next + self.recv_wind_size:
            pkt_copy = DataPacket(seq=pkt.seq, data=pkt.data, hash=0)
            if binascii.crc32(pkt_copy.__serialize__()) & 0xffffffff != pkt.hash:
                return
        else:
            return

        ack_pkt = DataPacket(ACK=pkt.seq, hash=0)
        ack_pkt.hash = binascii.crc32(ack_pkt.__serialize__()) & 0xffffffff
        self.transport.write(ack_pkt.__serialize__())

        if pkt.seq < self.recv_next:
            return

        self.recv_queue.append(pkt)
        self.recv_queue.sort(key=lambda pkt_: pkt_.seq)

        while self.recv_queue:
            if self.recv_queue[0].seq == self.recv_next:
                self.higherProtocol().data_received(self.recv_queue.pop(0).data)
                while self.recv_queue:
                    if self.recv_queue[0].seq == self.recv_next:
                        self.recv_queue.pop(0)
                    else:
                        break
                if self.recv_next == 2**32:
                    self.recv_next = 0
                else:
                    self.recv_next += 1
            else:
                break

        '''
        # MIGHT BE UNNECESSARY
        for pkt in self.recv_queue:
            if pkt.seq < self.recv_next:
                del(pkt)
        '''

    def send_data(self, data):
        self.send_buff += data
        self.queue_send_pkts()

    def init_close(self):
        self.send_shutdown_pkt()

    def queue_send_pkts(self):
        while self.send_buff and len(self.send_queue) <= self.send_wind_size and self.send_next < self.next_expected_ack + self.send_wind_size:
            if len(self.send_buff) >= 10000:
                pkt = DataPacket(seq=self.send_next,
                                 data=bytes(self.send_buff[0:15000]), hash=0)
                pkt.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
                self.send_buff = self.send_buff[10000:]
            else:
                pkt = DataPacket(seq=self.send_next, data=bytes(
                    self.send_buff[0:len(self.send_buff)]), hash=0)
                pkt.hash = binascii.crc32(pkt.__serialize__()) & 0xffffffff
                self.send_buff = []
            if self.recv_next == 2**32:
                self.recv_next = 0
            else:
                self.send_next += 1
            self.send_queue.append(pkt)
            self.transport.write(pkt.__serialize__())


POOPClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="client")
)

POOPServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: POOP(mode="server")
)
