from kademlia.crypto.signature_verifier import SignatureVerifier
from kademlia.crypto.signer import Signer
from kademlia.crypto.dilithium_py.src.dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

LENGTH_SECURITY_LEVEL ={
    (1312, 2528): 2,
    (1952, 4000): 3,
    (2592, 4864): 5
}

class DilithiumSignatureVerifier(SignatureVerifier):
    
    
    @staticmethod
    def verify(public_key: bytes,signature: bytes ,message) -> bool:
        print(f"public_key length: {len(public_key)}")
        security_level = None
        for key_length, sec_level in LENGTH_SECURITY_LEVEL.items():
           if key_length[0] == len(public_key):
               security_level = sec_level
               break
             
        if security_level == 2:
            return Dilithium2.verify(public_key,message, signature)
        elif security_level == 3:
            return Dilithium3.verify(public_key,message, signature)
        elif security_level == 5:
            return Dilithium5.verify(public_key,message, signature)
        else:
            raise ValueError(f"Invalid Dilithium security level: {security_level}")


class DilithiumSigner(Signer):
    
    @staticmethod
    def sign(private_key: bytes, message) -> bytes:
        
        security_level = None
        for key_length, sec_level in LENGTH_SECURITY_LEVEL.items():
           if key_length[1] == len(private_key):
               security_level = sec_level
               break
           
        if security_level == 2:
            return Dilithium2.sign(private_key,message)
        elif security_level == 3:
            return Dilithium3.sign(private_key,message)
        elif security_level == 5:
            return Dilithium5.sign(private_key,message)
        else:
            raise ValueError(f"Invalid Dilithium security level: {security_level}")