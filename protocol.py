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
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID

import binascii
import bisect
import random

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
        ("cert", BUFFER({Optional: True}))
        ("certChain", LIST(BUFFER, {Optional:True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]


class CRAP(StackingProtocol):
    def __init__(self, mode):
        #logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.mode = mode
        self.Desrialize_Packet = CrapPacketType.Deserializer()

    def GenerateCert(self, publickey, privatekey, issuer):
        subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                                      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tianjin"),
                                      x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tanggu"),
                                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"The Johns Hopkins University"),
                                      x509.NameAttribute(NameOID.COMMON_NAME, u"20194.5.20.30"),
                                      ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            publickey
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)  # Our certificate will be valid for 10 days
        ).sign(  # Sign our certificate with our private key
            private_key=privatekey,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        return cert

    def GenerateKey(self):
        DH_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        DH_public = DH_private.public_key()
        RSA_private = rsa.generate_private_key(public_exponent=65537, key_size=2048,backend=default_backend())
        RSA_public = RSA_private.public_key()
        return DH_private, DH_public, RSA_private, RSA_public

    def GenerateCertChain(self):
        cert_root = open("20194_root.cert", 'rb').read()
        cert_team = open("csr_team4_signed.cert", 'rb').read()
        private_key_team_rd = open("key_team4.pem", 'rb').read()
        cert_root_pem = x509.load_pem_x509_certificate(cert_root, default_backend())
        cert_team_pem= x509.load_pem_x509_certificate(cert_team, default_backend())
        private_key_team_pem = load_pem_private_key(private_key_team_rd,
                                                password=b'passphrase',
                                                backend=default_backend())
        return cert_team, cert_root_pem, cert_team_pem, private_key_team_pem

        print("----------Wayne get the cert!-----------")

    # def connection_made(self, transport):
    #     #logger.debug("{} Crap: connection made".format(self.mode))
    #     self.transport = transport
    #     print('---------------Wayne Start---------------')
    #     if self.mode == "client":
    #         print('---------------Wayne Client 1---------------')
    #
    #         self.DH_private_key_client, self.DH_public_key_client, self.RSA_private_key_client, self.RSA_public_key_client = self.GenerateKey()
    #
    #         DH_public_key_client_trans = self.DH_public_key_client.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    #
    #         Signature_client = self.RSA_private_key_client.sign(DH_public_key_client_trans,
    #                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    #                                 hashes.SHA256())
    #
    #         gen_nonce_client = random.randint(0, 1000)
    #         self.nonce_client = str(gen_nonce_client).encode('ASCII')
    #
    #         cert_team_client_b, cert_root_client, cert_team_client, private_key_team_client = self.GenerateCertChain()
    #
    #         cert_client = self.GenerateCert(self.RSA_public_key_client,
    #                                         private_key_team_client,
    #                                         cert_team_client.subject()).public_bytes(Encoding.PEM)
    #
    #         self.chain_client = [cert_team_client_b]
    #
    #         client_packet = HandshakePacket(status=0,
    #                                         pk=DH_public_key_client_trans,
    #                                         signature=Signature_client,
    #                                         nonce=gen_nonce_client,
    #                                         cert=cert_client,
    #                                         chain=self.chain_client)
    #         client_packet_trans = client_packet.__serialize__()
    #
    #         self.transport.write(client_packet_trans)
    #
    # def data_received(self, buffer):
    #     #logger.debug("{} Crap recv a buffer of size {}".format(self.mode, len(buffer)))
    #     self.Desrialize_Packet.update(buffer)
    #     packet_recieve = self.Desrialize_Packet.nextPackets()
    #     for p in packet_recieve:
    #         packet_type = p.DEFINITION_IDENTIFIER
    #
    #         if packet_type == "crap.handshakepacket":
    #             self.CRAP_recieve(p)
    #             continue
    #         else:
    #             return
    #
    # def CRAP_recieve(self, packet):
    #     if self.mode == "server":
    #
    #         if packet.status == 0:
    #             print('---------------Wayne Server 1---------------')
    #
    #             cert_client = x509.load_pem_x509_certificate(packet.cert, default_backend())
    #             self.public_key_extract_client = cert_client.public_key()
    #
    #             cert_team_server_b, cert_root_server, cert_team_server, private_key_team_server = self.GenerateCertChain()
    #
    #
    #             try:
    #                 self.public_key_extract_client.verify(packet.signature, packet.pk,
    #                                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    #
    #                 add_team = cert_team_server.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
    #                 add_recieve = cert_client.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
    #                 if add_team == add_recieve:
    #                     pass
    #                 else:
    #                     raise
    #
    #             except Exception as error:
    #                 server_packet = HandshakePacket(status=2)
    #                 server_packet_trans = server_packet.__serialize__()
    #                 self.transport.write(server_packet_trans)
    #                 self.transport.close()
    #
    #             self.DH_private_key_sever, self.DH_public_key_server, self.RSA_private_key_server, self.RSA_public_key_server = self.GenerateKey()
    #
    #             DH_public_key_server_trans = self.DH_public_key_server.public_bytes(Encoding.PEM,
    #                                                                                 PublicFormat.SubjectPublicKeyInfo)
    #
    #             Signature_server= self.RSA_private_key_server.sign(DH_public_key_server_trans,
    #                                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                                      salt_length=padding.PSS.MAX_LENGTH),
    #                                                          hashes.SHA256())
    #
    #             self.chain_server = [cert_team_server_b]
    #
    #             gen_nonce_server = random.randint(0, 1000)
    #             self.nonce_server = str(gen_nonce_server).encode('ASCII')
    #
    #             nonce_client = str(packet.nonce).encode('ASCII')
    #
    #             cert_server = self.GenerateCert(self.RSA_public_key_server,
    #                                             private_key_team_server,
    #                                             cert_team_server.subject()).public_bytes(Encoding.PEM)
    #
    #
    #             nonceSignature_server = self.RSA_private_key_server.sign(nonce_client,
    #                                                                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                                                  salt_length=padding.PSS.MAX_LENGTH),
    #                                                                      hashes.SHA256())
    #
    #             server_packet = HandshakePacket(status=1,
    #                                             pk=DH_public_key_server_trans,
    #                                             signature=Signature_server,
    #                                             nonce=gen_nonce_server,
    #                                             nonceSignature=nonceSignature_server,
    #                                             cert=cert_server,
    #                                             chain=self.chain_server
    #                                             )
    #             server_packet_trans = server_packet.__serialize__()
    #             self.transport.write(server_packet_trans)
    #
    #         elif packet.status == 1:
    #
    #             print('---------------Wayne Server 2---------------')
    #
    #             try:
    #                 self.extract_pubkA.verify(packet.nonceSignature, self.nonce_server,
    #                                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                       salt_length=padding.PSS.MAX_LENGTH),
    #                                           hashes.SHA256())
    #
    #             except Exception as error:
    #                 new_secure_packet = HandshakePacket(status=2)
    #                 self.transport.write(new_secure_packet.__serialize__())
    #                 self.transport.close()
    #             print("---------------Wayne Complete---------------")
    #     if self.mode == "client" and packet.status == 1:
    #
    #         print('---------------Wayne Client 2---------------')
    #
    #         cert_server = x509.load_pem_x509_certificate(packet.cert, default_backend())
    #         extract_public_key_server = cert_server.public_key()
    #
    #         cert_team_client_b, cert_root_client, cert_team_client, private_key_team_client = self.GenerateCertChain()
    #
    #         try:
    #             extract_public_key_server.verify(packet.signature,
    #                                              packet.pk,
    #                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                          salt_length=padding.PSS.MAX_LENGTH),
    #                                              hashes.SHA256())
    #             extract_public_key_server.verify(packet.nonceSignature,
    #                                              self.nonce_client,
    #                                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                          salt_length=padding.PSS.MAX_LENGTH),
    #                                              hashes.SHA256())
    #             add_team = cert_team_client.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
    #             add_recieve = cert_server.subject.get_attributes_for_aid(NameOID.COMMON_NAME)[0].value
    #             if add_team == add_recieve:
    #                 pass
    #             else:
    #                 raise
    #
    #         except Exception as error:
    #             client_packet_1 = HandshakePacket(status=2)
    #             client_packet_1_trans = client_packet_1.__serialize__()
    #             self.transport.write(client_packet_1_trans)
    #             self.transport.close()
    #
    #
    #         nonce_server = str(packet.nonce).encode('ASCII')
    #
    #         nonceSignature_client = self.RSA_private_key_client.sign(nonce_server,
    #                                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
    #                                                        salt_length=padding.PSS.MAX_LENGTH),
    #                                            hashes.SHA256())
    #
    #         new_secure_packet = HandshakePacket(status=1, nonceSignature=nonceSignature_client)
    #         self.transport.write(new_secure_packet.__serialize__())


SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                            lambda: CRAP(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                            lambda: CRAP(mode="server"))
                                                                    

