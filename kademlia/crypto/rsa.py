from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from kademlia.crypto.signature_verifier import SignatureVerifier
from kademlia.crypto.signer import Signer

class RSASignatureVerifier(SignatureVerifier):
    
    @staticmethod
    def verify(public_key:bytes, signature: bytes, message: bytes) -> bool:
        try:
            rsa_key = RSA.import_key(public_key)
            h = SHA256.new(message)
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            print("Invalid Signature")
            return False

class RSASigner(Signer):
    
    @staticmethod
    def sign(privat_key: bytes, message) -> bytes:
        try:
            rsa_key = RSA.import_key(privat_key)
            h = SHA256.new(message)
            signature = pkcs1_15.new(rsa_key).sign(h)
            return signature
        except ValueError as e:
            print(f"Error during signing process")
            return None
        
    