from ..poop.protocol import POOP
from uuid import UUID
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import datetime
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
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID

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
        ("cert", BUFFER({Optional: True}))
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
        self.deserializer = CrapPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self.mode))
        self.transport = transport

        if self.mode == "client":
            # Create long term key
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkA = self.privkA.public_key()

            # Create pk in packet (serialization)
            tmp_pubkA = pubkA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.dataA = tmp_pubkA

            # Create ephemeral key for signing
            self.signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.pubk_sigA = self.signkA.public_key()

            # Create signature
            sigA = self.signkA.sign(self.dataA,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

            # Create nonceA
            tmp_nonceA = 1
            self.nonceA = tmp_nonceA

            # Create certificate with the help of ephemeral private key
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Baltimore"),
                # x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"JHU"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"20194networksecurity.com"),
            ])
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(issuer)
            builder = builder.public_key(self.pubk_sigA)
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(datetime.datetime.utcnow())
            builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
            certificate = builder.sign(private_key=self.signkA, algorithm=hashes.SHA256(), backend=default_backend())
            # Create CertA to transmit (serialization)
            certA = certificate.public_bytes(Encoding.PEM)

            new_secure_packet = HandshakePacket(status=0, pk=self.dataA, signature=sigA, nonce=self.nonceA, cert=certA)
            self.transport.write(new_secure_packet.__serialize__())

    def data_received(self, buffer):
        logger.debug("{} Crap recv a buffer of size {}".format(self.mode, len(buffer)))
        self.deserializer.update(buffer)

        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if not pkt_type:  # NOTE: not sure if this is necessary
                print("{} Crap error: the recv pkt don't have a DEFINITION_IDENTIFIER")
                return
            logger.debug("{} Crap the pkt name is: {}".format(self.mode, pkt_type))
            if pkt_type == "crap.handshakepacket":
                self.crap_handshake_recv(pkt)
                continue
            else:
                print("{} Crap error: the recv pkt name: \"{}\" this is unexpected".format(
                    self.mode, pkt_type))
                return

    def crap_handshake_recv(self, packet):
        if self.mode == "server":
            if packet.status == 0:
                certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
                extract_pubkA = certification.public_key()
                try:
                    extract_pubkA.verify(packet.signature, self.dataA,
                                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                     salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except Exception as error:
                    logger.debug("Sever verify failed because wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()

                privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                pubkB = privkB.public_key()

                publickeyB = load_pem_private_key(packet.pk, password=None, backend=default_backend())
                server_shared_key = privkB.exchange(ec.ECDH, publickeyB)

                signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                pubk_sigB = signkB.public_key()

                tmp_pubk_sigB = pubk_sigB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                certB = tmp_pubk_sigB

                tmpB = pubkB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.dataB = tmpB

                sigB = signkB.sign(self.dataB,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())

                nonceSignatureB = signkB.sign(packet.nonce,
                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH),
                                              hashes.SHA256())

                tmp_nonceB = 4
                nonceB = bytes(tmp_nonceB)

                new_secure_packet = HandshakePacket(status=1, pk=self.dataB, signature=sigB, nonce=tmp_nonceB,
                                                    nonceSignature=nonceSignatureB, cert=certB)

                self.transport.write(new_secure_packet.__serialize__())

            elif packet.status == 1:
                try:
                    self.pubk_sigA.verify(packet.nonceSignature, self.nonceA,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                      salt_length=padding.PSS.MAX_LENGTH),
                                          hashes.SHA256())

                except Exception as error:
                    logger.debug("Sever verify failed because wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()
                print("Handshake complete")

        if self.mode == "client" and packet.status == 1:
            try:
                packet.cert.verify(packet.signature, self.dataB,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())
                packet.cert.verify(packet.nonceSignature, self.nonceA,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())

            except Exception as error:
                logger.debug("Sever verify failed because wrong signature")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

            publickeyA = load_pem_private_key(packet.pk, password=None, backend=default_backend())
            client_shared_key = self.privkA.exchange(ec.ECDH, publickeyA)

            nonceSignatureA = self.signkA.sign(packet.nonce,
                                               padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH),
                                               hashes.SHA256())

            new_secure_packet = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
            self.transport.write(new_secure_packet.__serialize__())


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: CRAP(mode="server"))
