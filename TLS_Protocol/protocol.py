from ..poop.protocol import POOP
from uuid import UUID
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging
import datetime
import time
import asyncio
from random import randrange
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT32, STRING, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
        ("cert", BUFFER({Optional: True})),
        ("certChain", LIST(BUFFER, {Optional: True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
    ]


class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket”"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("message", STRING),
    ]


class CRAPTransport(StackingTransport):

    def connect_protocol(self, protocol):
        self.protocol = protocol

    def write(self, data):
        self.protocol.send(data)

    def close(self):
        self.protocol.transport.close()


# ------------------------------------------Secure Protocol
class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.dataA = None
        self.dataB = None
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        # crap handshake status
        self.crap_status = None

    def connection_made(self, transport):
        logger.debug("{} Crap: connection made".format(self.mode))
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)

        print("start Tianshi Feng Test")

        if self.mode == "client":
            # Create Client ephemeral key
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            pubkA = self.privkA.public_key()

            # Create pk in packet (serialization)
            self.dataA = pubkA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

            # Create long term key for signing
            self.signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            self.pubk_sigA = self.signkA.public_key()

            # Load the certificate and the private key of intermediate CA
            root_cert_data = open('20194_root.cert', 'rb').read()
            team4_cert_data = open('csr_team4_signed.cert', 'rb').read()
            team4_privk_data = open('key_team4.pem', 'rb').read()
            self.root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())
            self.team4_cert = x509.load_pem_x509_certificate(team4_cert_data, default_backend())
            self.team4_privk = load_pem_private_key(team4_privk_data, password=b'passphrase', backend=default_backend())

            print("load certificate success!!")

            # Create self cert subject
            subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                                 x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MD"),
                                 x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
                                 x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"JHU"),
                                 x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),
                                 ])
            # Build self cert
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(self.team4_cert.subject)  # change the issuer
            builder = builder.public_key(self.pubk_sigA)  # put self pubk in cert
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.not_valid_before(datetime.datetime.utcnow())
            builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.4")]), critical=False)
            # Sign the self with intermediate CA's private key
            certificate = builder.sign(private_key=self.team4_privk, algorithm=hashes.SHA256(),
                                       backend=default_backend())

            print("sign the self cert success!!!")

            # Create CertA to transmit (serialization)
            certA = certificate.public_bytes(Encoding.PEM)

            # Create certificate chain
            self.cert_chain = [team4_cert_data]

            # Create signature
            sigA = self.signkA.sign(self.dataA,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

            # Create nonceA
            tmp_nonceA = randrange(2 ** 32)
            self.nonceA = str(tmp_nonceA).encode('ASCII')

            # Generate packet
            new_secure_packet = HandshakePacket(status=0, pk=self.dataA, signature=sigA, nonce=tmp_nonceA, cert=certA,
                                                certChain=self.cert_chain)
            self.transport.write(new_secure_packet.__serialize__())

            print("client hello sending finished!!!")

    def data_received(self, buffer):
        logger.debug("{} Crap recv a buffer of size {}".format(self.mode, len(buffer)))
        self.deserializer.update(buffer)

        for pkt in self.deserializer.nextPackets():
            pkt_type = pkt.DEFINITION_IDENTIFIER
            if not pkt_type:
                print("{} Crap error: the recv pkt don't have a DEFINITION_IDENTIFIER")
                return
            logger.debug("{} Crap the pkt name is: {}".format(self.mode, pkt_type))

            if pkt_type == "crap.handshakepacket":
                self.crap_handshake_recv(pkt)

            elif pkt_type == "crap.datapacket":
                self.crap_data_recv(pkt)

            elif pkt_type == "crap.errorpacket":
                logger.debug("Error packet received received from {}".format(self.mode))
                self.crap_errer_recv(pkt)

            else:
                print("{} Crap error: the recv pkt name: \"{}\" this is unexpected".format(
                    self.mode, pkt_type))
                return

    def crap_handshake_recv(self, packet):
        if self.crap_status == "ESTABLISHED":
            logger.debug("recvive a handshake packet when connect ESTABLISHED")
            return

        if self.mode == "server":
            if packet.status == 0:
                logger.debug("Server start Hello")

                # Load the cert of intermediate CA and root CA
                root_cert_data = open('20194_root.cert', 'rb').read()
                team4_cert_data = open('csr_team4_signed.cert', 'rb').read()
                team4_privk_data = open('key_team4.pem', 'rb').read()
                self.root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())
                self.team4_cert = x509.load_pem_x509_certificate(team4_cert_data, default_backend())
                self.team4_privk = load_pem_private_key(team4_privk_data, password=b'passphrase',
                                                        backend=default_backend())

                # Receive from client
                certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
                self.extract_pubkA = certification.public_key()

                try:
                    print("start server verify hello")
                    # Check the signature from client
                    self.extract_pubkA.verify(packet.signature, packet.pk,
                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                    # Check the playground address
                    team4_addr = self.team4_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    recv_addr = certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    print("Team address:", team4_addr)
                    print("Client address:", recv_addr)
                    # if team4_addr in recv_addr:
                    #     print("Verify success")
                    #     pass
                    # else:
                    #     raise

                except Exception as error:
                    logger.debug("Server 0 verify failed because wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()

                # Create Server ephemeral key key
                self.privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                pubkB = self.privkB.public_key()

                # Create pk in packet (serialization)
                self.dataB = pubkB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

                # Generate shared key
                recv_pubk = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.privkB.exchange(ec.ECDH(), recv_pubk)

                # Create long term for signing
                self.signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                self.pubk_sigB = self.signkB.public_key()

                # Create self cert subject
                subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                                     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MD"),
                                     x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
                                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"JHU"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),
                                     ])
                # Build self cert
                builder = x509.CertificateBuilder()
                builder = builder.subject_name(subject)
                builder = builder.issuer_name(self.team4_cert.subject)  # change the issuer
                builder = builder.public_key(self.pubk_sigB)  # put self pubk in cert
                builder = builder.serial_number(x509.random_serial_number())
                builder = builder.not_valid_before(datetime.datetime.utcnow())
                builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.4")]),
                                                critical=False)

                # Sign the self with intermediate CA's private key
                certificate = builder.sign(private_key=self.team4_privk, algorithm=hashes.SHA256(),
                                           backend=default_backend())

                print("sign the self cert success!!!")

                # Create CertB to transmit (serialization)
                certB = certificate.public_bytes(Encoding.PEM)

                # Create certificate chain
                self.cert_chain = [team4_cert_data]

                # Create signature
                sigB = self.signkB.sign(self.dataB, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                # Create nonceB
                tmp_nonceB = randrange(2 ** 32)
                self.nonceB = str(tmp_nonceB).encode('ASCII')

                # Received nonceA
                nonceA = str(packet.nonce).encode('ASCII')

                # Create nonceSignatureB (bytes)
                nonceSignatureB = self.signkB.sign(nonceA,
                                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                               salt_length=padding.PSS.MAX_LENGTH),
                                                   hashes.SHA256())

                new_secure_packet = HandshakePacket(status=1, pk=self.dataB, signature=sigB, nonce=tmp_nonceB,
                                                    nonceSignature=nonceSignatureB, cert=certB,
                                                    certChain=self.cert_chain)

                self.transport.write(new_secure_packet.__serialize__())

                print("server hello sending finished!!!")

            elif packet.status == 1:
                try:
                    self.extract_pubkA.verify(packet.nonceSignature, self.nonceB,
                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH),
                                              hashes.SHA256())

                except Exception as error:
                    logger.debug("Server verify failed because wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()

                print("Server Handshake complete")

                # Start Generate hash --------------------------------------------------

                # Create hash 1, IVA, IVB
                digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest1.update(self.shared_key)
                hash1 = digest1.finalize()
                self.ivA = hash1[0:12]
                self.ivB = hash1[12:24]
                print("server iva:", self.ivA)
                print("server ivb:", self.ivB)

                # Create hash2, encA
                digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest2.update(hash1)
                hash2 = digest2.finalize()
                self.decB = hash2[0:16]
                print("server dec:", self.decB)

                # Create hash3, decA
                digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest3.update(hash2)
                hash3 = digest3.finalize()
                self.encB = hash3[0:16]
                print("server enc:", self.encB)

                self.crap_status = "ESTABLISHED"
                self.higherProtocol().connection_made(self.higher_transport)

        if self.mode == "client":
            if packet.status == 1:
                certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
                extract_pubkB = certification.public_key()
                try:
                    # Check the signature of nonce and key
                    extract_pubkB.verify(packet.signature, packet.pk,
                                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                         hashes.SHA256())
                    extract_pubkB.verify(packet.nonceSignature, self.nonceA,
                                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                         hashes.SHA256())

                    # Check the playground address
                    team4_addr = self.team4_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    recv_addr = certification.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    print("Team address:", team4_addr)
                    print("Client address:", recv_addr)
                    if team4_addr in recv_addr:
                        print("Verify success")
                        pass
                    else:
                        raise

                except Exception as error:
                    logger.debug("client verify failed because wrong signature")
                    new_secure_packet = HandshakePacket(status=2)
                    self.transport.write(new_secure_packet.__serialize__())
                    self.transport.close()

                # Generate shared key
                recv_pubk = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.privkA.exchange(ec.ECDH(), recv_pubk)

                # Reveive nonceB
                nonceB = str(packet.nonce).encode('ASCII')

                nonceSignatureA = self.signkA.sign(nonceB,
                                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                               salt_length=padding.PSS.MAX_LENGTH),
                                                   hashes.SHA256())

                new_secure_packet = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
                self.transport.write(new_secure_packet.__serialize__())

                print("Client Handshake complete")

                # Start Generate hash --------------------------------------------------

                # Create hash 1, IVA, IVB
                digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest1.update(self.shared_key)
                hash1 = digest1.finalize()
                self.ivA = hash1[0:12]
                self.ivB = hash1[12:24]
                print("client iva:", self.ivA)
                print("client ivb:", self.ivB)

                # Create hash2, encA
                digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest2.update(hash1)
                hash2 = digest2.finalize()
                self.encA = hash2[0:16]
                print("client enc:", self.encA)

                # Create hash3, decA
                digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest3.update(hash2)
                hash3 = digest3.finalize()
                self.decA = hash3[0:16]
                print("client dec:", self.decA)

                self.crap_status = "ESTABLISHED"
                self.higherProtocol().connection_made(self.higher_transport)

            else:
                logger.debug("client wrong!")
                new_secure_packet = HandshakePacket(status=2)
                self.transport.write(new_secure_packet.__serialize__())
                self.transport.close()

    def send(self, data):
        if self.mode == "client":
            aesgcm = AESGCM(self.encA)
            encDataA = aesgcm.encrypt(self.ivA, data, None)
            self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
            new_packet = DataPacket(data=encDataA)
            self.transport.write(new_packet.__serialize__())
            print("Client send encrypted data")

        if self.mode == "server":
            aesgcm = AESGCM(self.encB)
            encDataB = aesgcm.encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")
            new_packet = DataPacket(data=encDataB)
            self.transport.write(new_packet.__serialize__())
            print("server send encrypted data")

    def crap_data_recv(self, packet):
        if self.mode == "server":
            aesgcm = AESGCM(self.decB)
            try:
                decDataB = aesgcm.decrypt(self.ivA, packet.data, None)

            except Exception as error:
                logger.debug("Server Decryption failed")

            self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")
            self.higherProtocol().data_received(decDataB)

        if self.mode == "client":
            aesgcm = AESGCM(self.decA)
            try:
                decDataA = aesgcm.decrypt(self.ivB, packet.data, None)

            except Exception as error:
                logger.debug("Client Decryption failed")

            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")
            self.higherProtocol().data_received(decDataA)



SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: CRAP(mode="server"))
