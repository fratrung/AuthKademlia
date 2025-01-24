import os
import sys
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from AuthKademlia.kademlia.network import Server
from AuthKademlia.kademlia.crypto.key_manager import DilithiumKeyManager, KyberKeyManager
from AuthKademlia.kademlia.auth_handler import DIDSignatureVerifierHandler
from AuthKademlia.kademlia.crypto.dilithium.src.dilithium_py.dilithium.default_parameters import Dilithium2, Dilithium3, Dilithium5
from AuthKademlia.kademlia.crypto.signature_verifier import SIGNATURE_ALG_LENGTHS