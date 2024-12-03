from kademlia.crypto.signature_verifier import SignatureVerifier
from kademlia.crypto.signer import Signer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

class Ed25519SignatureVerifier(SignatureVerifier):
    
    def verify(self,public_key: bytes, message, signature: bytes) -> bool:
        try:
            pub_key = Ed25519PublicKey.from_public_bytes(public_key)
            pub_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
    
class Ed25519Signer(Signer):
    
    def sign(self,private_key: bytes, message) -> bytes:
        priv_key = Ed25519PrivateKey.from_private_bytes(private_key)
        return priv_key.sign(message)