from abc import ABC, abstractmethod

SIGNATURE_ALG_LENGTHS = {
    "RSA": 256,
    "Dilithium": {
        2: 2420,
        3: 3293,
        5: 4595
    },
    "Ed25519": 64
}
class SignatureVerifier(ABC):
    
    @abstractmethod
    def verify(self,public_key:bytes,signature: bytes, message: bytes) -> bool:
        pass
    
    
