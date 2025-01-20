import os
import sys
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)

from kademlia.crypto.rsa import RSASignatureVerifier, RSASigner
from kademlia.crypto.dilithium_signature import DilithiumSignatureVerifier, DilithiumSigner
from kademlia.crypto.ed25519 import Ed25519SignatureVerifier, Ed25519Signer
from kademlia.crypto.signature_verifier import SignatureVerifier
from kademlia.crypto.signer import Signer

class SignatureVerifierFactory:
    
    @staticmethod
    def get_verifier(algorithm: str) -> SignatureVerifier:
        data_string = algorithm.split("-")
        algorithm = data_string[0]
        if algorithm == "RSA":
            return RSASignatureVerifier()
        elif algorithm == "Dilithium":
            return DilithiumSignatureVerifier()
        elif algorithm == "Ed25519":
            return Ed25519SignatureVerifier()
        else:
            raise ValueError(f"unsupported signature algorithm: {algorithm}")


class SignerFactory:
    
    @staticmethod
    def get_signer(algorithm: str) -> Signer:
        data_string = algorithm.split("-")
        algorithm = data_string[0]
        
        if algorithm == "RSA":
            return RSASigner()
        elif algorithm == "Dilithium":
            return DilithiumSigner()
        elif algorithm == "Ed25519":
            return Ed25519Signer()
        else:
            raise ValueError(f"unsupported signature algorithm: {algorithm}")
     
