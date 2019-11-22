from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from random import randint

import binascii
import bisect

logger = logging.getLogger("playground.__connector__." + __name__)


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
        self.protocol.write(data)

    def close(self):
        self.protocol.transport.close()


class crapHandshake(StackingProtocol):

    def __init__(self, mode):
        logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.mode = mode
        self.flag = False
        self.deserializer = CrapPacketType.Deserializer()

    def connection_made(self, transport):
        logger.debug("{}Crap:connection made".format(self.mode))
        self.transport = transport
        print("connection made print")

        if self.mode == "client":
            print("client mode test print")

            # get both ephemeral key and long term key
            self.getClientKey()

            # create pk, serialize
            self.client_pkData = self.client_pubKey_eph.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            print("client pkData is ", self.client_pkData)

            # load file
            self.loadCertFile()
            print("load success")

            # signature(signed long term emphermal public key)
            clientSignature = self.client_privKey_longTerm.sign(self.client_pkData,
                                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                            salt_length=padding.PSS.MAX_LENGTH),
                                                                hashes.SHA256())
            print("client signature:  ", clientSignature)

            # create nonceA
            client_int_nonce = randint(0, 100000)
            self.client_nonce = str(client_int_nonce).encode('ASCII')

            # creating the certificate
            certificate = self.createCertificate(self.client_pubKey_longTerm)

            # Create certificate chain
            self.cert_chain = [self.team4_cert_fileread]

            # send packet
            self.transport.write(
                HandshakePacket(status=0, pk=self.client_pkData, signature=clientSignature, nonce=client_int_nonce,
                                cert=certificate, certChain=self.cert_chain).__serialize__())
            print("client 0 success")

    def getClientKey(self):
        print("get client key print")
        # creating client ephemeral key
        self.client_privKey_eph = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.client_pubKey_eph = self.client_privKey_eph.public_key()

        # create long term key
        self.client_privKey_longTerm = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                                backend=default_backend())
        self.client_pubKey_longTerm = self.client_privKey_longTerm.public_key()

    def loadCertFile(self):
        # This function is both for client and server
        print("load Cert File")
        self.root_cert_fileread = open('20194_root.cert', 'rb').read()
        self.team4_cert_fileread = open('csr_team4_signed.cert', 'rb').read()
        self.team4_privk_fileread = open('key_team4.pem', 'rb').read()
        self.root_cert = x509.load_pem_x509_certificate(self.root_cert_fileread, default_backend())
        self.team4_cert = x509.load_pem_x509_certificate(self.team4_cert_fileread, default_backend())
        self.team4_privk = load_pem_private_key(self.team4_privk_fileread, password=b'passphrase',
                                                backend=default_backend())

    def createCertificate(self, pubKey_longTerm):
        # creating the certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"20194NetworkSecurity"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4")
        ])

        certficate = x509.CertificateBuilder().subject_name(subject).issuer_name(self.team4_cert.subject).public_key(
            pubKey_longTerm).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=100)).sign(
            self.team4_privk, hashes.SHA256(), default_backend()).public_bytes(Encoding.PEM)
        return certficate

    def data_received(self, buffer):
        self.deserializer.update(buffer)

        for packet in self.deserializer.nextPackets():
            pType = packet.DEFINITION_IDENTIFIER
            if not pType:
                print("no DEFINITION_IDENTIFIER")
                return
            if pType == "crap.handshakepacket":
                print(packet.status)
                self.handshake(packet)
            if pType == "crap.datapacket":
                print("received data in tls")
                self.tls_datareceived(packet)
            if pType == "crap.errorpacket":
                logger.debug("Error packet received received from {}".format(self.mode))
                print(packet.message)

    def handshake(self, packet):
        if self.flag:
            logger.debug("recvive a handshake packet when connect ESTABLISHED")
            return

        if self.mode == "server":
            if packet.status == 0:
                # load file
                self.loadCertFile()
                print("load success")

                certification = x509.load_pem_x509_certificate(packet.cert, default_backend())
                self.client_decode_pubKey = certification.public_key()

                try:
                    print("server mode begin verify")
                    self.client_decode_pubKey.verify(packet.signature, packet.pk,
                                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                 salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                    # Verify the signature in cryptography module (tbs)
                    cur_cert = certification
                    for data in packet.certChain:
                        cert = x509.load_pem_x509_certificate(data, default_backend())
                        cert_pubk = cert.public_key()
                        cert_pubk.verify(cur_cert.signature, cur_cert.tbs_certificate_bytes, padding.PKCS1v15(),
                                         hashes.SHA256())
                        cur_cert = cert

                    # Verify the root
                    root_pubk = self.root_cert.public_key()
                    root_pubk.verify(cur_cert.signature, cur_cert.tbs_certificate_bytes,
                                                       padding.PKCS1v15(), hashes.SHA256())

                except Exception as error:
                    logger.debug("wrong signature, server 0 failed")
                    self.transport.write(HandshakePacket(status=2).__serialize__())
                    self.transport.close()

                print("server mode verify success")
                # create server key, both ephemeral and long term
                self.getServerKey()

                # create pk
                self.server_pkData = self.server_pubKey_eph.public_bytes(Encoding.PEM,
                                                                         PublicFormat.SubjectPublicKeyInfo)

                # Generate shared key
                tmp_pubk = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.privkB.exchange(ec.ECDH(), tmp_pubk)

                # create signature
                serverSignature = self.server_privKey_longTerm.sign(self.server_pkData,
                                                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                                salt_length=padding.PSS.MAX_LENGTH),
                                                                    hashes.SHA256())

                # create server nonce
                server_int_nonce = randint(0, 100000)
                self.server_nonce = str(server_int_nonce).encode('ASCII')
                client_nonce = str(packet.nonce).encode('ASCII')

                # server certificate
                server_certificate = self.createCertificate(self.server_pubKey_longTerm)

                # Create certificate chain
                self.cert_chain = [self.team4_cert_fileread]

                # creating server nonceSignature
                serverNonceSignature = self.server_privKey_longTerm.sign(client_nonce,
                                                                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                                     salt_length=padding.PSS.MAX_LENGTH),
                                                                         hashes.SHA256())

                server_packet = HandshakePacket(status=1, pk=self.server_pkData, signature=serverSignature,
                                                nonce=server_int_nonce,nonceSignature=serverNonceSignature,
                                                cert=server_certificate, certChain=self.cert_chain)

                self.transport.write(server_packet.__serialize__())

                print("server 0 success")

            elif packet.status == 1:
                try:
                    print("packet status=1 test")
                    self.client_decode_pubKey.verify(packet.nonceSignature, self.server_nonce,
                                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                 salt_length=padding.PSS.MAX_LENGTH),
                                                     hashes.SHA256())
                except Exception as error:
                    logger.debug("wrong signature, server verify failed")
                    self.transport.write(HandshakePacket(status=2))
                    self.transport.close()

                print("packet status =1 test success")

                # Create hash 1
                digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest1.update(self.shared_key)
                hash1 = digest1.finalize()
                self.ivA = hash1[0:12]
                self.ivB = hash1[12:24]

                # Create hash2
                digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest2.update(hash1)
                hash2 = digest2.finalize()
                self.decB = hash2[0:16]

                # Create hash3
                digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest3.update(hash2)
                hash3 = digest3.finalize()
                self.encB = hash3[0:16]

                self.flag = True
                self.higherProtocol().connection_made(self.higher_transport)

        if self.mode == "client" and packet.status == 1:
            print(" client && packet status=1 test")
            self.server_decode_pubKey = x509.load_pem_x509_certificate(packet.cert, default_backend()).public_key()

            try:
                print(packet.pk)
                self.server_decode_pubKey.verify(packet.signature, packet.pk,
                                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH),
                                                 hashes.SHA256())

                self.server_decode_pubKey.verify(packet.nonceSignature, self.client_nonce,
                                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                             salt_length=padding.PSS.MAX_LENGTH),
                                                 hashes.SHA256())

                # Verify the signature in cryptography module (tbs)
                cur_cert = certification
                for data in packet.certChain:
                    cert = x509.load_pem_x509_certificate(data, default_backend())
                    cert_pubk = cert.public_key()
                    cert_pubk.verify(cur_cert.signature, cur_cert.tbs_certificate_bytes, padding.PKCS1v15(),
                                     hashes.SHA256())
                    cur_cert = cert

                # Verify the root
                root_pubk = self.root_cert.public_key()
                root_pubk.verify(cur_cert.signature, cur_cert.tbs_certificate_bytes,
                                                   padding.PKCS1v15(), hashes.SHA256())

            except Exception as error:
                logger.debug("client verify failed")
                self.transport.write(HandshakePacket(status=2).__serialize__())
                self.transport.close()

            print(" client && packet status=1 test   success")

            # Generate shared key
            tmp_pubk = load_pem_public_key(packet.pk, backend=default_backend())
            self.shared_key = self.privkA.exchange(ec.ECDH(), tmp_pubk)

            # server nonce
            server_nonce = str(packet.nonce).encode('ASCII')
            client_nonce = self.client_privKey_longTerm.sign(server_nonce,
                                                             padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                         salt_length=padding.PSS.MAX_LENGTH),
                                                             hashes.SHA256())

            self.transport.write(HandshakePacket(status=1, nonceSignature=client_nonce).__serialize__())
            print("client packet status =1 test success")

            # Create hash 1
            digest1 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest1.update(self.shared_key)
            hash1 = digest1.finalize()
            self.ivA = hash1[0:12]
            self.ivB = hash1[12:24]

            # Create hash2
            digest2 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest2.update(hash1)
            hash2 = digest2.finalize()
            self.decB = hash2[0:16]

            # Create hash3
            digest3 = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest3.update(hash2)
            hash3 = digest3.finalize()
            self.encB = hash3[0:16]

            self.flag = True
            self.higherProtocol().connection_made(self.higher_transport)

    def getServerKey(self):
        # create server ephemeral term key
        self.server_privKey_eph = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.server_pubKey_eph = self.server_privKey_eph.public_key()

        # create server long term key
        self.server_privKey_longTerm = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                                backend=default_backend())
        self.server_pubKey_longTerm = self.server_privKey_longTerm.public_key()

    def write(self, data):
        if self.mode == "client":
            aesgcm = AESGCM(self.encA)
            encData = aesgcm.encrypt(self.ivA, data, None)
            self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")

        if self.mode == "server":
            aesgcm = AESGCM(self.encB)
            encData = aesgcm.encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")

        new_packet = DataPacket(data=encData)
        self.transport.write(new_packet.__serialize__())

    def crap_data_recv(self, packet):
        if self.mode == "server":
            aesgcm = AESGCM(self.decB)
            try:
                decData = aesgcm.decrypt(self.ivA, packet.data, None)

            except Exception as error:
                logger.debug("Server Decryption failed")
            self.ivA = (int.from_bytes(self.ivA, "big") + 1).to_bytes(12, "big")

        if self.mode == "client":
            aesgcm = AESGCM(self.decA)
            try:
                decData = aesgcm.decrypt(self.ivB, packet.data, None)

            except Exception as error:
                logger.debug("Client Decryption failed")
            self.ivB = (int.from_bytes(self.ivB, "big") + 1).to_bytes(12, "big")

        self.higherProtocol().data_received(decData)


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: crapHandshake(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: crapHandshake(mode="server"))
