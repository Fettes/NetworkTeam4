
from uuid import UUID

import logging
import datetime
import time
import asyncio
from random import randrange

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



team4_cert_data = open('csr_team4_signed.cert', 'rb').read()
team4_cert = x509.load_pem_x509_certificate(team4_cert_data, default_backend())
result = team4_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

print(result)

string = '20194.5.4.23'
result = '20194.4.' in string
print(result)