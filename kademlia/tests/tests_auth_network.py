import logging 
import argparse
import asyncio
import hashlib
import os
import sys
import uuid
project_root = os.path.dirname(os.path.abspath(".."))
sys.path.append(project_root)
from kademlia.crypto.key_manager import DilithiumKeyManager
from kademlia.network import Server
from kademlia.auth_handler import DIDSignatureVerifierHandler
from kademlia.storage import ForgetfulStorage
import json
import base64

log = logging.getLogger('kademlia')
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())



def create_did_record():
    key_manager = DilithiumKeyManager()
    pk, sk = key_manager.generate_keypair(2)
    pub_key_base64 = base64.urlsafe_b64encode(pk).decode('utf-8').rstrip("=")
    
    did = f"did:iiot:{uuid.uuid4()}"
    #did = "did:iiot:13148719-dba5-4477-bd23-3100097867b3"
    print(did)
    did_document = {
        "id":did,
        "verificationMethod": [{
            "id": f"{did}#k0",
            "type":"JsonWebKey",
            "controller":did,
            "publicKeyJwk":{
                "kid":f"{did}#k0",
                "kty": "MLWE",
                "alg":"CRYDI2",
                "x": pub_key_base64
            }
        },
        {
           "id": f"{did}#k0",
            "type":"JsonWebKey",
            "controller":did,
            "publicKeyJwk":{
                "kid":f"{did}#k0",
                "kty": "OKP",
                "alg":"Kyber-512",
                "x": "NLQ5gChTuPlcyVs2T_Qg62CQu-ycfcNgFXkpKMZo99SZp-hkUYOVbWFOXrIrDfUEjEkRHDZnRpYfmfFvghLD5Hanr-Oer3RxdRQYpqMGDlqsb6UG-dBNX6k6o5RXjVApz8WVJVUL-ukUbUVxWOCpoQBMciGqV2NvTrSsHkvJshsO7Wo2IjS8ZGtn1vdWFlAHeRkGcoolXxeHKSWpamCzxXxAFaWlChMw1Fg7HsQEntebceOTh6uW48avzJtFBNNLDEKczwABpsZi80YlIRhjVFeqTVYu1Bob4ZQqBsU4J7MMTtYA-DCyVAaC6adY4PzDvtkgT0gdCuBXHmkOjFCIWSW2jESzVOgNf9JFTqVeetBR-IsNvegniJpyA4tEBFM55rh4Btoo_gtJmJsINhWRTAkSkhQz7ym99jErJqpoJvif3aqXaZKjozynkaSttuPKSVWU8ptfyGsUmpCfSvAq_WymEawz1KcFeIiV3Hpf6Bm7SCII57A8MoVQptSzM3HLAvpMyUxXd3XDWmFwNqhY9bS1xno_XFpRBjvNzfehQcqIgAgMoXir_CgeDYWJ9VxkcfaqInp3Hzh2ztOgkYI2rfZk7enDdnsnQGRDHafAeNV-AMN4syQFJfKdT_SC2LPEf4xUSuZPCyBb-1dP_7dlUupjRzkzyudyLdlldwZJJVowReGYQ3Uj3TuPasWKG0OYexaD79QnZYSJxNJiC2nDr2Fu74bIcDGB-NqAocAbGHJUopQGbrp-I-xuFWtdJOxqG0Yb0POoFWa21BpR0eKDUzOpfSEbsRKgE6lflHAuSjUMgnm6g1ZqLZIBl9aGevQIMSUKUqfLYNhfeYFvlQFRjsJykBUhqpQSNiiiLLWSLwlGNalO_WMNxhwB_JO-8Fy2YRADPhNGNYhAajaSvwtBUPBr1bylcNLBbcRAYryPwwO9AzOAXRuTfmAyVIqVHZpZOuVsVxyCp5PEDaOnHIS61SHK5-au7ldNoIOpOwMTqvc_cnmPkiWBPDCs--Bh0ogdORU9G1xMWQPoChZLKL4PbOgICzKJqUh8TVtV9qcedz4"
            } 
        },                       
                               
        ],
        "service":[],
        "authentication": [f"{did}#k0"],
        "assertionMethod": [f"{did}#k0"],
        "capabilityInvocation": [f"{did}#k0"],
        "capabilityDelegation": [f"{did}#k0"]
    }
    
    did_doc_bytes = json.dumps(did_document,sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    signature = key_manager.sign(sk,did_doc_bytes,2)
    algorithm = 'Dilithium-2'.encode('utf-8')[:12].ljust(12, b'\0')
    #print(f"\n\nlen alg {len(algorithm)} \nlen signature : {len(signature)}\nlen did doc :{len(did_doc_bytes)}")
    value = algorithm + signature + did_doc_bytes
    return did.split(":")[-1], value, sk


def test_insert_record():
    key, value, sk = create_did_record()
    bootstrap_nodes = [("127.0.0.1", 8009), ("127.0.0.1", 8008)]
    node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(node.listen(8016))
        loop.run_until_complete(node.bootstrap(bootstrap_nodes))
        print(f"BOOTSTRAP AVVENUTO CON SUCCESSO")
        
        failure = 0
        loop.run_until_complete(node.set(key, value))
        keys = []
        
       # for _ in range(3):
       #     loop.run_until_complete(asyncio.sleep(4))
       #     key, value = create_did_record()
       #     loop.run_until_complete(node.set(key, value))
       #     keys.append(key)

    #    for k in keys:
    #        print(f"\n\nkey: {k}")
    #        loop.run_until_complete(asyncio.sleep(4))
    #        result = loop.run_until_complete(node.get(k))
    #        if not result:
    #            failure += 1
    #        else:
    #            print(result)

    #    print(f"\n\n Failure: {failure}")
    finally:
        loop.run_until_complete(node.stop())
        loop.close()
        log.info("Node stopped")
  
        
        
def test_existing_dht_auth_network():
    
    key , value, sk = create_did_record()
    bootstrap_nodes = [("127.0.0.1",8009),("127.0.0.1",8007),("127.0.0.1",8008)]
    node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(node.listen(8017))
    loop.run_until_complete(node.bootstrap(bootstrap_nodes))
    
    print(f"BOOTSTRAP AVVENUTO CON SUCCESSO")
    failure = 0
    loop.run_until_complete(node.set(key,value))
    print(f"\n\n Failure: {failure}")       
                  
    try:
        loop.run_forever()
    except KeyboardInterrupt or asyncio.CancelledError:
        print("\nShutting down node...")
    finally:
        loop.run_until_complete(node.stop())
        loop.close()
        log.info("Node stopped")
    
def test_get_record(bootstrap_nodes= [("127.0.0.1",8008),("127.0.0.1",8009)]):
    node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(node.listen(8001))
    loop.run_until_complete(node.bootstrap(bootstrap_nodes))
    try:
        result = loop.run_until_complete(node.get("efc226eb-23bd-4835-9aa4-66c9e3b12846")) 
        print(f"RESULT:\n {result}")
    finally:
        loop.run_until_complete(node.stop())
        loop.close()
        
def test_key_rotation(bootstrap_nodes = [("127.0.0.1",8007),("127.0.0.1",8008),("127.0.0.1",8009)]):
    key, value, sk = create_did_record()
    bootstrap_nodes = [("127.0.0.1", 8009), ("127.0.0.1", 8008)]
    node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(node.listen(8016))
        loop.run_until_complete(node.bootstrap(bootstrap_nodes))
        print(f"BOOTSTRAP AVVENUTO CON SUCCESSO")
        
        loop.run_until_complete(node.set(key, value))
        
        result = loop.run_until_complete(node.get(key))
        
        if not result:
            print("TEST FALLITO")
            return
        did_document = result[12+2420:]
        did_doc = json.loads(did_document.decode('utf-8'))
        did = did_doc['id']
        print(f"\nOLD DID DOCUMENT: \n{json.dumps(did_doc,indent=4)}")
        key_manager = DilithiumKeyManager()
        new_pk, new_sk = key_manager.generate_keypair(2)
        new_pub_key_base64 = base64.urlsafe_b64encode(new_pk).decode('utf-8').rstrip("=")
        new_verification_method = {
            "id": f"{did}#k0",
            "type":"JsonWebKey",
            "controller":did,
            "publicKeyJwk":{
                "kid":f"{did}#k0",
                "kty": "MLWE",
                "alg":"CRYDI2",
                "x": new_pub_key_base64
            }
        }
        did_doc["verificationMethod"][0] = new_verification_method
        #print(f"\nNEW DID DOCUMENT BEFORE STORING :\n {json.dumps(did_doc,indent=4)}\n")
        did_doc_bytes = json.dumps(did_doc,sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = key_manager.sign(new_sk,did_doc_bytes,2)
        algorithm = 'Dilithium-2'.encode('utf-8')[:12].ljust(12, b'\0')
        #print(f"\n\nlen alg {len(algorithm)} \nlen signature : {len(signature)}\nlen did doc :{len(did_doc_bytes)}")
        value = algorithm + signature + did_doc_bytes
        auth_signature = key_manager.sign(sk,value,2)
        print(len(auth_signature+value+key.encode()))
        loop.run_until_complete(node.update(key,value,auth_signature))
        
        new_record = loop.run_until_complete(node.get(key))
        if not new_record:
            print("TEST FALLITO")
            return
        new_did_document = new_record[12+2420:]
        new_did_doc = json.loads(new_did_document.decode('utf-8'))
        print(f"\n\nNEW DID DOCUMENT: \n{json.dumps(new_did_doc,indent=4)}")
        
    finally:
        loop.run_until_complete(node.stop())
        loop.close()
        log.info("Node stopped")     
        
               
#test_existing_dht_auth_network()
#test_insert_record()

#test_get_record()
test_key_rotation()
