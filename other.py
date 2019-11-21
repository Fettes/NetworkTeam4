from playground.network.common.Protocol import StackingProtocolFactory, StackingProtocol, StackingTransport
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16,UINT32, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography import x509
from cryptography.x509.oid import NameOID
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


import logging
import time
import asyncio
import os      
import datetime
import binascii
import bisect
import uuid
import random

from ..poop.protocol import POOP

logger = logging.getLogger("playground.__connector__." + __name__)


class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"
class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2
    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional:True})),
        ("nonceSignature", BUFFER({Optional:True})),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True})),
        ("certChain", LIST(BUFFER, {Optional:True}))
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
        self.protocol.send_data(data)
    def close(self):
        self.protocol.init_close()

class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug(">>>>> Crap Init Protocol Start: {} <<<<<".format(mode))
        print ("init init init init")
        # super().__init__()
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        self.initenc = False
        self.handshake = True
        print ("init init init init")
        logger.debug(">>>>> Crap Init Protocol End: {} <<<<<".format(self.mode))

    def connection_made(self, transport):
        logger.debug(">>>>> Crap Connection Made Start: {} <<<<<".format(self.mode))
        print ("connection made connection made connection made")
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)

        if self.mode == "client":
            print (">>>>> Client: Send First Packet START <<<<<")
            # create the secret key and public key
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.pubkA = self.privkA.public_key()
            # create a signing key
            self.signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            # FIXME note: cert_t4.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            # create a certification with current playground address
            cert_root_data = open('20194_root.cert', 'rb').read()
            cert_t4_data = open('csr_team4_signed.cert', 'rb').read()
            privk_t4_data = open('key_team4.pem', 'rb').read()
            self.cert_root = cryptography.x509.load_pem_x509_certificate(cert_root_data, default_backend())
            self.cert_t4 = cryptography.x509.load_pem_x509_certificate(cert_t4_data, default_backend())
            self.privk_t4 = serialization.load_pem_private_key(privk_t4_data,password=b'passphrase',backend=default_backend())
            subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 4"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),
            ])
            print ("aaaaaaa")
            self.certA = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.cert_t4.subject
            ).public_key(
                self.signkA.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.4")]),
                critical=False,
            ).sign(self.privk_t4, hashes.SHA256(), default_backend())
            print ("aaaaaaa")
            certA_bytes = self.certA.public_bytes(Encoding.PEM)

            # create a signature for the public key
            pubkA_bytes = self.pubkA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.sigA = self.signkA.sign(pubkA_bytes,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                                hashes.SHA256())
            # create a challenge (256 bits) and a signature for this challenge
            # self.nonceA = int.from_bytes(uuid.uuid4().bytes + uuid.uuid4().bytes, "little")
            # self.nonceA = uuid.uuid4().int
            self.nonceA = random.randint(0, 999999)

            self.certChain = [cert_t4_data]
            # create a new packet
            new_packet = HandshakePacket(status=0,nonce=self.nonceA,pk=pubkA_bytes,signature=self.sigA,cert=certA_bytes,certChain=self.certChain)
            # transport the new packet
            self.transport.write(new_packet.__serialize__())
            print (">>>>> Client: Send First Packet END <<<<<")

        logger.debug(">>>>> Crap Connection Made End: {} <<<<<".format(self.mode))
            
    def data_received(self, buffer):
        print (">>>>> data recv data <<<<<<< ")

        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            print (packet)
            if isinstance(packet, HandshakePacket) and self.handshake:
                self.handshake_handler(packet)
            elif isinstance(packet, DataPacket) and not self.handshake:
                self.data_handler(packet)
            elif isinstance(packet, ErrorPacket):
                print (">>> ERROR PACKET:  ")
                print (packet.message)
                    
    def connection_lost(self, exc):
        print (">>>>> Connection Lost <<<<<")
        self.higherProtocol().connection_lost(exc)

    def send_data(self, data):
        if self.mode == "client":
            # aesccm = AESCCM(self.encA)
            encData = AESCCM(self.encA).encrypt(self.ivA, data, None)
            self.ivA = (int.from_bytes(self.ivA, "big")+1).to_bytes(12,"big")
        elif self.mode == "server":
            # aesccm = AESCCM(self.encB)
            encData = AESCCM(self.encB).encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big")+1).to_bytes(12,"big")

        new_packet = DataPacket(data=encData)
        self.transport.write(new_packet.__serialize__())
        print ("CLIENT: CRAP OUT")

    def data_handler(self, packet):
        if self.mode == "client":
            # aesccm = AESCCM(self.decA)
            decData = AESCCM(self.decA).decrypt(self.ivB, packet.data, None)
            self.ivB = (int.from_bytes(self.ivB, "big")+1).to_bytes(12,"big")
        elif self.mode == "server":
            # aesccm = AESCCM(self.decB)
            try:
                decData = AESCCM(self.decB).decrypt(self.ivA, packet.data, None)
            except Exception as error:
                print (error)
            self.ivA = (int.from_bytes(self.ivA, "big")+1).to_bytes(12,"big")
        self.higherProtocol().data_received(decData)


    def handshake_handler(self, packet):
        if self.mode == "server":
            if packet.status == 0:
                print (">>>>> Server: Send First Packet START <<<<<")

                cert_root_data = open('20194_root.cert', 'rb').read()
                cert_t4_data = open('csr_team4_signed.cert', 'rb').read()
                self.cert_root = cryptography.x509.load_pem_x509_certificate(cert_root_data, default_backend())
                self.cert_t4 = cryptography.x509.load_pem_x509_certificate(cert_t4_data, default_backend())

                self.certA = x509.load_pem_x509_certificate(packet.cert, default_backend())

                # verify the signature 
                try:
                    print ("verify")
                    print (packet.pk.decode("ASCII"))
                    self.certA.public_key().verify(packet.signature, packet.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    cur = self.certA
                    for data in packet.certChain:
                        cert = x509.load_pem_x509_certificate(data, default_backend())
                        cert.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())
                        cur = cert
                    self.cert_root.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())

                except Exception as error:
                    logger.debug(">>>>> Crap Handshake Handler Error: {}, {} <<<<<".format(self.mode, error))
                    print ("verify failed !")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return

                print ("verify success !")
                # create the secret key and public key
                self.privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                self.pubkB = self.privkB.public_key()
                # compute the shared key
                self.pubkA = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.privkB.exchange(ec.ECDH(), self.pubkA)

                # create a signing key
                self.signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                # create a certification 
                cert_root_data = open('20194_root.cert', 'rb').read()
                cert_t4_data = open('csr_team4_signed.cert', 'rb').read()
                privk_t4_data = open('key_team4.pem', 'rb').read()
                self.cert_root = cryptography.x509.load_pem_x509_certificate(cert_root_data, default_backend())
                self.cert_t4 = cryptography.x509.load_pem_x509_certificate(cert_t4_data, default_backend())
                self.privk_t4 = serialization.load_pem_private_key(privk_t4_data,password=b'passphrase',backend=default_backend())
                subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 4"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),
                ])
                self.certB = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    self.cert_t4.subject
                ).public_key(
                    self.signkB.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow()
                ).not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=10)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.4")]),
                    critical=False,
                ).sign(self.privk_t4, hashes.SHA256(), default_backend()) # TODO change sign key
                certB_bytes = self.certB.public_bytes(Encoding.PEM)

                self.certChain = [cert_t4_data]
                # create a signature for the public key
                pubkB_bytes = self.pubkB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.sigB = self.signkB.sign(pubkB_bytes,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())

                # create a challenge (256 bits) and a signature for this challenge
                # self.nonceB = uuid.uuid4().bytes + uuid.uuid4().bytes
                self.nonceA = packet.nonce
                self.nonceBSignature = self.signkB.sign(str(self.nonceA).encode('ASCII'),
                                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                    salt_length=padding.PSS.MAX_LENGTH),
                                                    hashes.SHA256())

                # self.nonceB = int.from_bytes(uuid.uuid4().bytes + uuid.uuid4().bytes, "little")
                self.nonceB = random.randint(0, 999999)
                # create a new packet
                new_packet = HandshakePacket(status=1,nonce=self.nonceB,
                                            nonceSignature=self.nonceBSignature,
                                            pk=pubkB_bytes,
                                            signature=self.sigB,
                                            cert=certB_bytes,
                                            certChain=self.certChain)
                # transport the new packet
                self.transport.write(new_packet.__serialize__())
                print (">>>>> Server: Send First Packet END <<<<<")
                
                # passed here
            
            elif packet.status == 1:
                print (">>>>> Server: Send Second Packet START <<<<<")
                try:
                    print ("verify")
                    self.certA.public_key().verify(packet.nonceSignature, str(self.nonceB).encode("ASCII"),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                except Exception as error:
                    logger.debug(">>>>> Crap Handshake Handler Error: {}, {} <<<<<".format(self.mode, error))
                    print ("verify failed !")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return
                print ("verify success !")
                # TODO need to connect higher protocol ? 
                # self.higher_transport = POOPTransport(transport)
                # self.higherProtocol().connection_made(self.higher_transport)

                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(self.shared_key)
                hash1 = digest.finalize()
                self.ivA = hash1[0:12]
                self.ivB = hash1[12:24]
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(hash1)
                hash2 = digest.finalize()
                self.decB = hash2[0:16]
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(hash2)
                hash3 = digest.finalize()
                self.encB = hash3[0:16]

                print ("-"*20)
                print (self.ivA)
                print (self.ivB)
                print (self.shared_key.hex())
                print ("-"*20)

                self.handshake = False
                self.higherProtocol().connection_made(self.higher_transport)
 
                print (">>>>> Server: Send Second Packet END <<<<<")
            
            else:
                error_packet = HandshakePacket(status=2)
                self.transport.write(error_packet.__serialize__())
                self.transport.close()


        if self.mode == "client":
            if packet.status == 1:
                print (">>>>> Client: Send Second Packet START <<<<<")
                self.certB = x509.load_pem_x509_certificate(packet.cert, default_backend())
                # verify the signature 
                try:
                    print ("verify")
                    print (packet.pk.decode("ASCII"))
                    self.certB.public_key().verify(packet.signature, packet.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    print ("Done first verify")
                    self.certB.public_key().verify(packet.nonceSignature, str(self.nonceA).encode("ASCII"),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    cur = self.certB
                    for data in packet.certChain:
                        cert = x509.load_pem_x509_certificate(data, default_backend())
                        cert.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())
                        cur = cert
                    self.cert_root.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())
                except Exception as error:
                    logger.debug(">>>>> Crap Handshake Handler Error: {}, {} <<<<<".format(self.mode, error))
                    print ("verify failed !")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return
                
                print ("verify success !")

                # load public key B 
                self.pubkB = load_pem_public_key(packet.pk, backend=default_backend())
                # create a shared key
                self.shared_key = self.privkA.exchange(ec.ECDH(), self.pubkB)

                # sign nonce B
                self.nonceB = packet.nonce
                nonceSignatureA = self.signkA.sign(str(self.nonceB).encode('ASCII'),
                                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                salt_length=padding.PSS.MAX_LENGTH),
                                                    hashes.SHA256())
                new_packet = HandshakePacket(status=1, nonceSignature=nonceSignatureA)
                self.transport.write(new_packet.__serialize__())

                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(self.shared_key)
                hash1 = digest.finalize()
                self.ivA = hash1[0:12]
                self.ivB = hash1[12:24]
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(hash1)
                hash2 = digest.finalize()
                self.encA = hash2[0:16]
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(hash2)
                hash3 = digest.finalize()
                self.decA = hash3[0:16]

                print ("-"*20)
                print (self.ivA)
                print (self.ivB)
                print ("-"*20)

                self.handshake = False
                self.higherProtocol().connection_made(self.higher_transport)

                print (">>>>> Client: Send Second Packet END <<<<<")
            else:
                error_packet = HandshakePacket(status=2)
                self.transport.write(error_packet.__serialize__())
                self.transport.close()



SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: CRAP(mode="server"))
