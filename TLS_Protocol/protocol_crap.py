from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

import binascii
import bisect

logger = logging.getLogger("playground.__connector__." + __name__)


# ------------------------------------------Crap Packet Definition Here
class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"


class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2

    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional: True})),
        ("nonceSignature", BUFFER({Optional: True})),
        ("signature", BUFFER({Optional: True})),
        ("pk", BUFFER({Optional: True})),
        ("cert", BUFFER({Optional:True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]


# ------------------------------------------Secure Protocol
class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.dataA = None
        self.dataB = None
        self.mode = mode

    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self._mode))
        self.transport = transport

        if self._mode == "client":
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkA = self.privkA.public_key()

            signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            pubk_sigA = signkA.public_key()

            certA = pubk_sigA
            self.dataA = pubkA

            # sigA = signkA.sign(data,ec.ECDSA(hashes.SHA256()))
            sigA = signkA.sign(self.dataA, padding.PSS(mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
            new_secure_packet = HandshakePacket(status=0, pk=pubkA, signature=sigA, cert=certA)

            self.transport.write(new_secure_packet.__serialize__())

    def data_received(self, buffer):
        logger.debug("{} Crap recv a buffer of size {}".format(self._mode, len(buffer)))

        self.deserializer.update(buffer)
        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if not pkt_type:  # NOTE: not sure if this is necessary
                print("{} Crap error: the recv pkt don't have a DEFINITION_IDENTIFIER")
                return
            logger.debug("{} POOP the pkt name is: {}".format(self._mode, pkt_type))
            if pkt_type == "carp.handshakepacket":
                self.crap_handshake_recv(pkt)
                continue

    def crap_handshake_recv(self, packet):
        if self._mode == "server" and packet.status == 0:

            try:
                packet.cert.verify(packet.signature, self.dataA, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            except Exception as error:
                logger.debug("Sever verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkB = privkB.public_key()
            server_shared_key = privkB.exchange(ec.ECDH, packet.pk)

            signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            pubk_sigB = signkB.public_key()

            certB = pubk_sigB
            self.dataB = pubkB
            sigB = signkB.sign(self.dataB, padding.PSS(mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())

            new_secure_packet = HandshakePacket(status=1, pk=pubkB, signature=sigB, cert=certB)
            self.transport.write(new_secure_packet.__serialize__())

        if self._mode == "client" and packet.status == 1:
            try:
                packet.cert.verify(packet.signature, self.dataB, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

            except Exception as error:
                logger.debug("Sever verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            client_shared_key = self.privkA.exchange(ec.ECDH, packet.pk)
            new_secure_packet = HandshakePacket(status=1)
            self.transport.write(new_secure_packet.__serialize__())


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: CRAP(mode="client"),)

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: CRAP(mode="server"))

