from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat

# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=2048,
                                     backend=default_backend())
# Generate a private key for use in the exchange.
private_key = parameters.generate_private_key()
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.
peer_public_key = parameters.generate_private_key().public_key()
shared_key = private_key.exchange(peer_public_key)
# Perform key derivation.
derived_key = HKDF(
     algorithm=hashes.SHA256(),
     length=32,
     salt=None,
     info=b'handshake data',
     backend=default_backend()
 ).derive(shared_key)

# For the next handshake we MUST generate another private key, but
# we can reuse the parameters.
private_key_2 = parameters.generate_private_key()
peer_public_key_2 = parameters.generate_private_key().public_key()
shared_key_2 = private_key_2.exchange(peer_public_key_2)
derived_key_2 = HKDF(
     algorithm=hashes.SHA256(),
     length=32,
     salt=None,
     info=b'handshake data',
     backend=default_backend()
 ).derive(shared_key_2)

result = peer_public_key_2.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
print(result)
print(derived_key_2)

