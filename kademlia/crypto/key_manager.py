from abc import ABC, abstractmethod
import os
import base64
from typing import Tuple, Dict, Any
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__),'dilithium'))

from dilithium.src.dilithium_py.dilithium.default_parameters import Dilithium2, Dilithium3, Dilithium5
from kyber.src.kyber_py.kyber.default_parameters import Kyber512, Kyber1024, Kyber768

def b64encode_key(key):
    return base64.urlsafe_b64encode(key).decode('utf-8').rstrip("=")

def b64decode_key(key):
    padding_needed = len(key) % 4
    if padding_needed > 0:
        key += '=' * (4 - padding_needed)
    return base64.urlsafe_b64decode(key)

class KeyManagerError(Exception):
    """Base class for KeyManager-related exceptions."""
    pass

class KeyNotFoundError(KeyManagerError):
    """Raised when a key is not found."""
    pass

class KeyExistsError(KeyManagerError):
    """Raised when a key already exists."""
    pass


class KeyManager(ABC):
    
    def __init__(self, keys_dir: str = "keys"):
        self.keys_dir = keys_dir
        os.makedirs(self.keys_dir, exist_ok=True)
    
    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new public and private key pair with the given name.
        
        Returns:
        Tuple[bytes, bytes]: The public key and private key data.
        """
        pass
    
    @abstractmethod
    def store_public_key(self, key_name: str, public_key: bytes) -> None:
        """
        Store the public key with the given name.
        
        Parameters:
        key_name (str): A unique name to identify the key.
        public_key (bytes): The public key data.
        """
        pass

    @abstractmethod
    def store_private_key(self, key_name: str, private_key: bytes) -> None:
        """
        Store the private key with the given name.
        
        Parameters:
        key_name (str): A unique name to identify the key.
        private_key (bytes): The private key data.
        """
        pass

    @abstractmethod
    def get_private_key(self, key_name: str) -> bytes:
        """
        Retrieve the private key with the given name.
        
        Parameters:
        key_name (str): The name of the key.
        
        Returns:
        bytes: The private key data.
        """
        pass

    @abstractmethod
    def get_public_key(self, key_name: str) -> bytes:
        """
        Retrieve the public key with the given name.
        
        Parameters:
        key_name (str): The name of the key.
        
        Returns:
        bytes: The public key data.
        """
        pass
    
    @abstractmethod
    def get_public_key(self, fname:str) -> bytes:
        """
        Retrieve the public key with the given name.
        
        Parameters:
        key_name (str): The name of the key pair.
        
        Returns:
        bytes: The public key data.
        """
        pass
    
   
    @abstractmethod
    def get_jose_format() -> dict:
        """
        Return a dictionary representing the key in JWK (JSON Web Key) format
        according to RFC 7517 and related specifications.
        
        Parameters:
        key: The name of the key to represent in JWK format
        
        Returns:
        Dict[str, Any]: A dictionary containing the JWK representation of the key
        
        """
    

class DilithiumKeyManager(KeyManager):
    """
    Concrete implementation of KeyManager for Dilithium keys.
    """
    def generate_keypair(self,security_level: int) -> Tuple[bytes]:
        self.security_level = security_level
        if security_level == 2:
            return Dilithium2.keygen()
        elif security_level == 3:
            return Dilithium3.keygen()
        elif security_level == 5:
            return Dilithium5.keygen()
        else:
            return None, None
    
    def store_public_key(self, key_name: str, public_key: bytes) -> None:
        public_key_path = os.path.join(self.keys_dir, f"{key_name}.public")
        with open(public_key_path, "wb") as f:
            f.write(public_key)

    def store_private_key(self, key_name: str, private_key: bytes) -> None:
        private_key_path = os.path.join(self.keys_dir, f"{key_name}.private")
        with open(private_key_path, "wb") as f:
            f.write(private_key)

    def get_public_key(self, key_name: str) -> bytes:
        public_key_path = os.path.join(self.keys_dir, f"{key_name}.public")
        with open(public_key_path, "rb") as f:
            return f.read()

    def get_private_key(self, key_name: str) -> bytes:
        private_key_path = os.path.join(self.keys_dir, f"{key_name}.private")
        with open(private_key_path, "rb") as f:
            return f.read()
        
    def sign(self,private_key: bytes, message,security_level: int) -> bytes:
        if security_level == 2:
            return Dilithium2.sign(private_key,message)
        elif security_level == 3:
            return Dilithium3.sign(private_key,message)
        elif security_level == 5:
            return Dilithium5.sign(private_key,message)
        else:
            raise ValueError(f"Invalid Dilithium security level: {security_level}")
        
    def verify_signature(self,public_key: bytes, message: bytes, signature: bytes,security_level: int) -> bool:
        if security_level == 2:
            return Dilithium2.verify(public_key,message, signature)
        elif security_level == 3:
            return Dilithium3.verify(public_key,message, signature)
        elif security_level == 5:
            return Dilithium5.verify(public_key,message, signature)
        else:
            raise ValueError(f"Invalid Dilithium security level: {security_level}")
        
    def get_jose_format(self,public_key: bytes,security_level: int) -> Dict[str, Any]:
        if not security_level == 2 and not security_level == 3 and not security_level == 5:
            return None
        base64_public_key = b64encode_key(public_key)
        return {
            "kty":"MLWE",
            "alg":f"CRYDI{security_level}",
            "x":base64_public_key
        }
        
class KyberKeyManager(KeyManager):
    """
    Concrete implementation of KeyManager for Kyber keys.
    """
    def generate_keypair(self, security_level: int) -> Tuple[bytes, bytes]:
        self.security_level = security_level
        if security_level == 512:
            return Kyber512.keygen()
        elif security_level == 768:
            return Kyber768.keygen()
        elif security_level == 1024:
            return Kyber1024.keygen()
        else:
            return None, None

    def store_public_key(self, key_name: str, public_key: bytes) -> None:
        public_key_path = os.path.join(self.keys_dir, f"{key_name}.public")
        with open(public_key_path, "wb") as f:
            f.write(public_key)

    def store_private_key(self, key_name: str, private_key: bytes) -> None:
        private_key_path = os.path.join(self.keys_dir, f"{key_name}.private")
        with open(private_key_path, "wb") as f:
            f.write(private_key)

    def get_public_key(self, key_name: str) -> bytes:
        public_key_path = os.path.join(self.keys_dir, f"{key_name}.public")
        with open(public_key_path, "rb") as f:
            return f.read()

    def get_private_key(self, key_name: str) -> bytes:
        private_key_path = os.path.join(self.keys_dir, f"{key_name}.private")
        with open(private_key_path, "rb") as f:
            return f.read()


    def get_jose_format(self, public_key: bytes, security_level: int) -> Dict[str, Any]:
        if security_level not in (2, 3, 5):
            return None
        base64_public_key = b64encode_key(public_key)
        return {
            "kty": "KEM",
            "alg": f"KYBER{security_level}",
            "x": base64_public_key
        }
  
class Ed25519KeyManager(KeyManager):
    
    def generate_keypair(self) -> Tuple[bytes]:
        pass
    

    
    