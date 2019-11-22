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
        ("cert", BUFFER({Optional: True}))
    ]


class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]


class crapHandshake(StackingProtocol):

    def __init__(self,mode):
        logger.debug("{} Crap: init protocol".format(mode))
        super().__init__()
        self.mode=mode
        self.deserializer=CrapPacketType.Deserializer()

    def connection_made(self,transport):
        logger.debug("{}Crap:connection made".format(self.mode))
        self.transport=transport
        print("connection made print")

        if self.mode == "client":
            print("client mode test print")
            #get both ephemeral key and long term key
            self.getClientKey()
            #create pk, serialize
            self.client_pkData=self.client_pubKey_eph.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
            print("client pkData is ",self.client_pkData)
            #signature(signed long term emphermal public key)
            clientSignature=self.client_privKey_longTerm.sign(self.client_pkData, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        
            print("client signature:  ",clientSignature)
            #create nonceA
            client_int_nonce=randint(0,100000)
            self.client_nonce=str(client_int_nonce).encode('ASCII')

            #creating the certificate
            certificate=self.createCertificate(self.client_pubKey_longTerm,self.client_privKey_longTerm)

            self.transport.write(HandshakePacket(status=0,pk=self.client_pkData,signature=clientSignature, nonce=client_int_nonce,cert=certificate).__serialize__())



    def getClientKey(self):
        print("get client key print")
        # creating client ephemeral key
        self.client_privKey_eph = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.client_pubKey_eph = self.client_privKey_eph.public_key()

        # create long term key
        self.client_privKey_longTerm = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.client_pubKey_longTerm = self.client_privKey_longTerm.public_key()


    def createCertificate(self,pubKey_longTerm,privKey_longTerm):
        # creating the certificate
        subject = issuer = x509.Name(
            [ x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"20194NetworkSecurity")])
        certficate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            pubKey_longTerm).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=100)).sign(
            privKey_longTerm, hashes.SHA256(), default_backend()).public_bytes(Encoding.PEM)
        return certficate



    def handshake(self,packet):
        if self.mode == "server":
        
            if packet.status==0:
                self.client_decode_pubKey=x509.load_pem_x509_certificate(packet.cert, default_backend()).public_key()
                try:
                    print("server mode begin verify")
                    self.client_decode_pubKey.verify(packet.signature, packet.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                except Exception as error:
                    logger.debug("wrong signature, server 0 failed")
                    self.transport.write(HandshakePacket(status=2).__serialize__())
                    self.transport.close()
                print("server mode verify success")
                #create server key, both ephemeral and long term
                self.getServerKey()
                

                
                #create pk
                self.server_pkData=self.server_pubKey_eph.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                #create signature

                serverSignature=self.server_privKey_longTerm.sign(self.server_pkData, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                #create server nonce
                server_int_nonce=randint(0,100000)
                self.server_nonce=str(server_int_nonce).encode('ASCII')
                client_nonce=str(packet.nonce).encode('ASCII')

                #server certificate
                server_certificate=self.createCertificate(self.server_pubKey_longTerm,self.server_privKey_longTerm)

                # creating server nonceSignature
                serverNonceSignature=self.server_privKey_longTerm.sign(client_nonce, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                               salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

                server_packet=HandshakePacket(status=1, pk=self.server_pkData, signature=serverSignature, nonce=server_int_nonce,
                                                    nonceSignature=serverNonceSignature, cert=server_certificate)
                self.transport.write(server_packet.__serialize__())

            elif packet.status==1:
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

        if self.mode == "client" and packet.status == 1:
            print(" client && packet status=1 test")
            self.server_decode_pubKey=x509.load_pem_x509_certificate(packet.cert, default_backend()).public_key()
    
            try:
                print(packet.pk)
                self.server_decode_pubKey.verify(packet.signature, packet.pk,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
                
                self.server_decode_pubKey.verify(packet.nonceSignature, self.client_nonce,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())

            except Exception as error:
                logger.debug("client verify failed")
                self.transport.write(HandshakePacket(status=2).__serialize__())
                self.transport.close()
            print(" client && packet status=1 test   success")

            server_nonce=str(packet.nonce).encode('ASCII')
            client_nonce=self.client_privKey_longTerm.sign(server_nonce,
                                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                        salt_length=padding.PSS.MAX_LENGTH),
                                            hashes.SHA256())
            self.transport.write(HandshakePacket(status=1,nonceSignature=client_nonce).__serialize__())

    def getServerKey(self):
        # create server ephemeral term key
        self.server_privKey_eph = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.server_pubKey_eph = self.server_privKey_eph.public_key()

        # create server long term key
        self.server_privKey_longTerm = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                                                backend=default_backend())
        self.server_pubKey_longTerm = self.server_privKey_longTerm.public_key()


    def data_received(self, buffer):
        self.deserializer.update(buffer)
        
        for packet in self.deserializer.nextPackets():
            pType=packet.DEFINITION_IDENTIFIER
            if not pType:
                print("no DEFINITION_IDENTIFIER")
                return
            if pType=="crap.handshakepacket":
                print(packet.status)
                self.handshake(packet)





SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: crapHandshake(mode="client"))

SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: crapHandshake(mode="server"))
