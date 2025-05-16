from kademlia.crypto.signature_factory import SignatureVerifierFactory
from kademlia.crypto.signature_verifier import SIGNATURE_ALG_LENGTHS
from abc import ABC, abstractmethod
import json
import base64

class SignatureVerifierHandler():
    
    def __init__(self):
        self.factory_verifier = SignatureVerifierFactory()
        
    @abstractmethod
    def handle_signature_verification(value):
        pass
    
    @abstractmethod
    def handle_update_verification(value,old_value,auth_signature):
        pass
    
    
class DIDSignatureVerifierHandler(SignatureVerifierHandler):
    
    def __init__(self):
        super().__init__()
        
    def handle_signature_algorithm_type(self,algorithm: str) -> tuple:
        data_string = algorithm.split("-")
        alg = data_string[0]
        dilithium_security_level = None
        length = None
        if len(data_string) > 1:
            dilithium_security_level = data_string[1]
        
        if not alg in SIGNATURE_ALG_LENGTHS:
            print(f"Unsupported signature algorithm: {alg}")
            return None
        
        if dilithium_security_level:
            length = SIGNATURE_ALG_LENGTHS[alg][int(dilithium_security_level)]
            return alg, length
        
        length = SIGNATURE_ALG_LENGTHS[alg]
        return alg, length
    
    
    def decode_b64(self,key):
        padding_needed = len(key) % 4
        if padding_needed > 0:
            key += '=' * (4 - padding_needed)
        return base64.urlsafe_b64decode(key)
    
    def get_alg_string(self,value):
        return value[:12].rstrip(b'\0').decode('utf-8')
    
    
    def extracts_data(self,value,length_param):
        signature = value[12:(12+length_param)]
        data = value[(12 + length_param):]
        return signature, data
        
    def handle_signature_verification(self,value):
        """The first 12 bytes of the value are a string representing the type of algorithm used for the signature."""
        algorithm_string = self.get_alg_string(value)
        alg_param, length_param = self.handle_signature_algorithm_type(algorithm_string)
        signature = value[12:(12 + length_param)]
        data = value[(12 + length_param):]
        did_document = json.loads(data.decode('utf-8'))
        verification_method0 = did_document['verificationMethod'][0]
        public_key = verification_method0['publicKeyJwk']['x']
        
        pub_key_bytes = self.decode_b64(public_key)
        
        signature_verifier = self.factory_verifier.get_verifier(algorithm_string)
        is_valid_signature = signature_verifier.verify(pub_key_bytes,signature,data)
        return is_valid_signature
    
    
    def handle_update_verification(self,value,old_value,auth_signature):
        return self.handle_key_rotation(value,old_value,auth_signature)
    
    
    def handle_key_rotation(self,value,old_value,auth_signature):
        old_alg_string = self.get_alg_string(old_value)
        old_alg_param, old_length_param = self.handle_signature_algorithm_type(old_alg_string)
        old_signature, old_data = self.extracts_data(old_value,old_length_param)
        old_did_document = json.loads(old_data.decode('utf-8'))
        verification_method0 = old_did_document['verificationMethod'][0]
        public_key = verification_method0['publicKeyJwk']['x']
        pub_key_bytes = self.decode_b64(public_key)
        signature_verifier = self.factory_verifier.get_verifier(old_alg_string)
        is_valid_sign = signature_verifier.verify(pub_key_bytes,auth_signature,value)
        if not is_valid_sign:
            return False
        return self.handle_signature_verification(value)
    
    
    def handle_signature_delete_operation(self, value, auth_signature, delete_msg):
        algorithm_string = self.get_alg_string(value)
        alg_param, length_param = self.handle_signature_algorithm_type(algorithm_string)
        data = value[(12 + length_param):]
        did_document = json.loads(data.decode('utf-8'))
        verification_method0 = did_document['verificationMethod'][0]
        public_key = verification_method0['publicKeyJwk']['x']
        
        pub_key_bytes = self.decode_b64(public_key)
        
        signature_verifier = self.factory_verifier.get_verifier(algorithm_string)
        is_valid_signature = signature_verifier.verify(pub_key_bytes,auth_signature,delete_msg) 
        return is_valid_signature

    
    

    
    
    
    