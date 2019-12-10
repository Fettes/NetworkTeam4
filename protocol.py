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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
        self.protocol.transport.close()

class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug(">>>>> Crap Init Protocol Start: {} <<<<<".format(mode))
        # super().__init__()
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        self.initenc = False
        self.handshake = True
        logger.debug(">>>>> Crap Init Protocol End: {} <<<<<".format(self.mode))

    def connection_made(self, transport):
        logger.debug(">>>>> Crap Connection Made Start: {} <<<<<".format(self.mode))
        self.transport = transport
        self.higher_transport = CRAPTransport(transport)
        self.higher_transport.connect_protocol(self)
        global connector
        connector = transport.get_extra_info('peername')

        # 0 for success
        self.rule = 0


        if self.mode == "client":
            logger.debug(">>>>> Client: Send First Packet START <<<<<")
            # create the secret key and public key
            self.privkA = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.pubkA = self.privkA.public_key()
            # create a signing key
            self.signkA = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

            cert_root_data = open('/home/student_20194/.playground/connectors/crap/20194_root.cert', 'rb').read()
            cert_t4_data = open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read()
            privk_t4_data = open('/home/student_20194/.playground/connectors/crap/key_team4.pem', 'rb').read()
            self.cert_root = cryptography.x509.load_pem_x509_certificate(cert_root_data, default_backend())
            self.cert_t4 = cryptography.x509.load_pem_x509_certificate(cert_t4_data, default_backend())
            self.privk_t4 = serialization.load_pem_private_key(privk_t4_data,password=b'passphrase',backend=default_backend())

            # create a certification 

            # good cert
            if self.rule == 0:

                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),
                ])
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

            # bad cert: unmatched common name (make sure current address is not 20194.4.4.5)
            # aaa 
            # aaa
            elif self.rule == 1:

                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.5"),
                ])
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
                    x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.5")]),
                    critical=False,
                ).sign(self.privk_t4, hashes.SHA256(), default_backend())
            
            # bad cert: unmatched prefix (make sure the current address 20194.5.5.5)
            elif self.rule == 2:

                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.5.5.5"),
                ])
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
                    x509.SubjectAlternativeName([x509.DNSName(u"20194.5.5.5")]),
                    critical=False,
                ).sign(self.privk_t4, hashes.SHA256(), default_backend())

            # bad cert: cert with unmatched sign key
            elif self.rule == 3:

                wrong_signk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.5.5.5"),
                ])
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
                    x509.SubjectAlternativeName([x509.DNSName(u"20194.5.5.5")]),
                    critical=False,
                ).sign(wrong_signk, hashes.SHA256(), default_backend())

            # bad cert: cert signed by a self signed team cert
            elif self.rule == 4:

                bad_team_privk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4."),
                ])
                bad_team_cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    bad_team_privk.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow()
                ).not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=10)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(u"20194.4.")]),
                    critical=False,
                ).sign(bad_team_privk, hashes.SHA256(), default_backend())
                bad_team_cert_bytes = bad_team_cert.public_bytes(Encoding.PEM)

                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),
                ])
                self.certA = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    bad_team_cert.subject
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
                ).sign(bad_team_privk, hashes.SHA256(), default_backend())


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

            # create a cert chain
            if self.rule == 4:
                self.certChain = [bad_team_cert_bytes]
            else:
                self.certChain = [cert_t4_data]
            # create a new packet
            new_packet = HandshakePacket(status=0,nonce=self.nonceA,pk=pubkA_bytes,signature=self.sigA,cert=certA_bytes,certChain=self.certChain)
            # transport the new packet
            self.transport.write(new_packet.__serialize__())
            logger.debug(">>>>> Client: Send First Packet END <<<<<")

        logger.debug(">>>>> Crap Connection Made End: {} <<<<<".format(self.mode))

    def data_received(self, buffer):
        logger.debug(">>>>> data recv data <<<<<<< ")

        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            print (packet)
            if isinstance(packet, HandshakePacket) and self.handshake:
                self.handshake_handler(packet)
            elif isinstance(packet, DataPacket) and not self.handshake:
                self.data_handler(packet)
            elif isinstance(packet, ErrorPacket):
                logger.debug(">>> ERROR PACKET:  ")
                logger.debug(packet.message)

    def connection_lost(self, exc):
        logger.debug(">>>>> Connection Lost <<<<<")
        self.higherProtocol().connection_lost(exc)

    def send_data(self, data):
        if self.mode == "client":
            encData = AESGCM(self.encA).encrypt(self.ivA, data, None)
            self.ivA = (int.from_bytes(self.ivA, "big")+1).to_bytes(12,"big")
        elif self.mode == "server":
            encData = AESGCM(self.encB).encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big")+1).to_bytes(12,"big")

        new_packet = DataPacket(data=encData)
        self.transport.write(new_packet.__serialize__())
        logger.debug("CLIENT: CRAP OUT")

    def data_handler(self, packet):
        if self.mode == "client":
            decData = AESGCM(self.decA).decrypt(self.ivB, packet.data, None)
            self.ivB = (int.from_bytes(self.ivB, "big")+1).to_bytes(12,"big")
        elif self.mode == "server":
            decData = AESGCM(self.decB).decrypt(self.ivA, packet.data, None)
            self.ivA = (int.from_bytes(self.ivA, "big")+1).to_bytes(12,"big")
        self.higherProtocol().data_received(decData)


    def handshake_handler(self, packet):
        if self.mode == "server":
            if packet.status == 0:
                logger.debug(">>>>> Server: Send First Packet START <<<<<")

                cert_root_data = open('/home/student_20194/.playground/connectors/crap/20194_root.cert', 'rb').read()
                cert_t4_data = open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read()
                self.cert_root = cryptography.x509.load_pem_x509_certificate(cert_root_data, default_backend())
                self.cert_t4 = cryptography.x509.load_pem_x509_certificate(cert_t4_data, default_backend())

                self.certA = x509.load_pem_x509_certificate(packet.cert, default_backend())

                # verify the signature
                try:
                    logger.debug(packet.pk.decode("ASCII"))
                    self.certA.public_key().verify(packet.signature, packet.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )


                    certA_address = self.certA.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if certA_address != self.transport.get_extra_info("peername")[0]:
                        raise Exception("cert address doesn't match with transport address")
                    if len(certA_address.split(".")) != 4:
                        raise Exception("bad cert format")

                    cur = self.certA
                    cur_addr = certA_address
                    for data in packet.certChain:
                        cert = x509.load_pem_x509_certificate(data, default_backend())
                        cert.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())
                        cert_addr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                        for i in range(2):
                            if cur_addr[i] != cert_addr[i]:
                                raise Exception("unmatched perfix")

                        cur = cert
                    self.cert_root.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())

                    cert_root_addr = self.cert_root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if cert_root_addr[0] != cur_addr [0]:
                        raise Exception("unmatched perfix")

                except Exception as error:
                    logger.debug(">>>>> Crap Handshake Handler Error: {}, {} <<<<<".format(self.mode, error))
                    logger.debug("----verify failed !----")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return

                logger.debug("verify success !")
                # create the secret key and public key
                self.privkB = ec.generate_private_key(ec.SECP384R1(), default_backend())
                self.pubkB = self.privkB.public_key()
                # compute the shared key
                self.pubkA = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.privkB.exchange(ec.ECDH(), self.pubkA)

                # create a signing key
                self.signkB = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                # create a certification
                cert_root_data = open('/home/student_20194/.playground/connectors/crap/20194_root.cert', 'rb').read()
                cert_t4_data = open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read()
                privk_t4_data = open('/home/student_20194/.playground/connectors/crap/key_team4.pem', 'rb').read()
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
                ).sign(self.privk_t4, hashes.SHA256(), default_backend())
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
                # self.nonceB = uuid.uuid4().int
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
                logger.debug(">>>>> Server: Send First Packet END <<<<<")

                # passed here

            elif packet.status == 1:
                logger.debug(">>>>> Server: Send Second Packet START <<<<<")
                try:
                    logger.debug("verify")
                    self.certA.public_key().verify(packet.nonceSignature, str(self.nonceB).encode("ASCII"),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                except Exception as error:
                    logger.debug(">>>>> Crap Handshake Handler Error: {}, {} <<<<<".format(self.mode, error))
                    logger.debug("verify failed !")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return
                logger.debug("verify success !")

                # generate keys and transfer to a higher protocol
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

                logger.debug(self.ivA)
                logger.debug(self.ivB)

                self.handshake = False
                self.higherProtocol().connection_made(self.higher_transport)
                try:

                    team = connector[0].split(".")[1]
                    connection_made_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    print('------connect made-------')
                    with open('/home/student_20194/Tianshi_Feng/NetworkTeam4/Game_Bank/tstest.txt', 'a') as f:

                        print(team)
                        f.write("team{}".format(team))
                        print('2222')
                        f.write("   time:{}".format(connection_made_time))
                        print('3333')
                        f.write("   Connection made success!!!")
                        print('4444')
                        f.write("\n")
                    print("------write in success----")
                    #count times
                    #with open('./tstest.txt', 'w') as f:
                        #f.write("team{} pay time: {}".format.(team,quit_flag))
                except Exception as error:
                    logger.debug(">>>Only one filed, this is not a legal team!!!<<<")

                logger.debug(">>>>> Server: Send Second Packet END <<<<<")
                #try:
                    #connector = transport.get_extra_info('peername')
                    #team = connector[0].split(".")[1]
                    #connection_made_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    #print("time:{}, team{}, connector:{}, trying to make connection".format(connection_made_time, team, connector))
                #except Exception as error:
                    #logger.debug(">>>Only one filed, this is not a legal team!!!<<<")

        #if self.mode == "client":
            #logger.debug(">>>>> Client: Send First Packet START <<<<<")

                #Mconnector = transport.get_extra_info('peername')
                #Mteam = connector.split(".")[1]
                #Mconnection_made_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                #print("time:{}, team{}, connector:{}, connection made success!!!".format(connection_made_time, team, connector)


            #else:
                #error_packet = HandshakePacket(status=2)
                #self.transport.write(error_packet.__serialize__())
                #self.transport.close()


        if self.mode == "client":
            if packet.status == 1:
                logger.debug(">>>>> Client: Send Second Packet START <<<<<")
                self.certB = x509.load_pem_x509_certificate(packet.cert, default_backend())
                # verify the signature
                try:
                    logger.debug("verify")
                    self.certB.public_key().verify(packet.signature, packet.pk,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    logger.debug("Done first verify")
                    self.certB.public_key().verify(packet.nonceSignature, str(self.nonceA).encode("ASCII"),
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )

                    certB_address = self.certB.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if certB_address != self.transport.get_extra_info("peername")[0]:
                        raise Exception("cert address doesn't match with transport address")
                    if len(certB_address.split(".")) != 4:
                        raise Exception("bad cert format")

                    cur = self.certB
                    cur_addr = certB_address
                    for data in packet.certChain:
                        cert = x509.load_pem_x509_certificate(data, default_backend())
                        cert.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())

                        cert_addr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                        for i in range(2):
                            if cur_addr[i] != cert_addr[i]:
                                raise Exception("unmatched perfix")

                        cur = cert
                    self.cert_root.public_key().verify(cur.signature, cur.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            hashes.SHA256())

                    cert_root_addr = self.cert_root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if cert_root_addr[0] != cur_addr [0]:
                        raise Exception("unmatched perfix")

                except Exception as error:
                    logger.debug(">>>>> Crap Handshake Handler Error: {}, {} <<<<<".format(self.mode, error))
                    logger.debug("verify failed !")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return

                logger.debug("verify success !")

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

                # generate keys and transfer to a higher protocol
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

                logger.debug(self.ivA)
                logger.debug(self.ivB)


                self.handshake = False
                self.higherProtocol().connection_made(self.higher_transport)

                logger.debug(">>>>> Client: Send Second Packet END <<<<<")
            else:
                error_packet = HandshakePacket(status=2)
                self.transport.write(error_packet.__serialize__())
                self.transport.close()



SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="client"),
                                                                lambda: CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda: POOP(mode="server"),
                                                                lambda: CRAP(mode="server"))

