from abc import ABC, abstractmethod

class Signer(ABC):
    @abstractmethod
    def sign(private_key: bytes, message):
        pass
