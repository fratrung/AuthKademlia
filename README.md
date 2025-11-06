# Python Distributed Hash Table
[![Build Status](https://github.com/bmuller/kademlia/actions/workflows/ci.yml/badge.svg)](https://github.com/bmuller/kademlia/actions/workflows/ci.yml)
[![Docs Status](https://readthedocs.org/projects/kademlia/badge/?version=latest)](http://kademlia.readthedocs.org)

**Documentation can be found at [kademlia.readthedocs.org](http://kademlia.readthedocs.org/).**

This library is an asynchronous Python implementation of the [Kademlia distributed hash table](http://en.wikipedia.org/wiki/Kademlia).  It uses the [asyncio library](https://docs.python.org/3/library/asyncio.html) in Python 3 to provide asynchronous communication.  The nodes communicate using [RPC over UDP](https://github.com/bmuller/rpcudp) to communiate, meaning that it is capable of working behind a [NAT](http://en.wikipedia.org/wiki/Network_address_translation).

This library aims to be as close to a reference implementation of the [Kademlia paper](http://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) as possible.

## Installation

```
pip install git+https://github.com/fratrung/AuthKademlia 
```
## Signed Records and Verifiable Data Registry Support

This extended version of the Kademlia DHT adds native support for **signed records**, enabling the network to act as a **Verifiable Data Registry (VDR)** for **W3C Decentralized Identifiers (DIDs)**.

Each stored value in the DHT can now be a **structured signed record**, composed as:
## Usage
*This assumes you have a working familiarity with [asyncio](https://docs.python.org/3/library/asyncio.html).*

Assuming you want to connect to an existing network:
```
algorithm + did document + signature
```
This structure allows any peer to verify the authenticity and integrity of the data stored in the DHT using the corresponding public key found in the DID Document.
### How It Works

- When inserting data (e.g., a DID Document), the record is **digitally signed** by the data owner using their private key.  
- The DHT node **validates signatures** through the integrated `DIDSignatureVerifierHandler`.  
- Retrieved records can be **independently verified** by any node using the **public key** contained in the DID Document.

## DID:IIoT Integration

This implementation is designed to work with the [`did:iiot` method](https://github.com/fratrung/did-iiot), an open DID method for **Industrial IoT** environments.

DID Documents published to the DHT contain **post-quantum public keys** (`Dilithium` / `Kyber`) enabling **secure authentication**, **key exchange**, and **credential verification**.

Example usage and full implementation are available in  
[**fratrung/did-iiot-dht**](https://github.com/fratrung/did-iiot-dht)

## Example Usage

Below is a minimal example showing how to generate post-quantum key pairs, create a `did:iiot` DID Document, sign it, and store it as a verifiable record in the DHT.

```python
import asyncio
from AuthKademlia.modules import Server, DilithiumKeyManager, KyberKeyManager, DIDSignatureVerifierHandler, Dilithium2 
from did_iiot.modules import DIDIndustrialIoT, DIDDocument, Service, VerificationMethod

def base64_encode_publickey(pk: bytes) -> str:
    """Encodes a public key in base64url format (without padding)."""
    return base64.urlsafe_b64encode(pk).decode('utf-8').rstrip("=")

def encode_did_document(did_document: dict) -> bytes:
    """Serializes a DID Document as canonical JSON bytes."""
    return json.dumps(did_document, sort_keys=True, separators=(",", ":")).encode('utf-8')

def get_dilithium_pub_key_for_did_doc(did, pk, security_level, kid="k0"):
    """Creates a Dilithium public key JWK for inclusion in a DID Document."""
    from did_iiot.did_iiot.publicjwk import DilithiumPublicJwkey
    x = base64_encode_publickey(pk)
    return DilithiumPublicJwkey(f"{did}#{kid}", security_level=security_level, x=x)

def get_kyber_pub_key_for_did_doc(did, pk, lat, kid="k1"):
    """Creates a Kyber public key JWK for inclusion in a DID Document."""
    from did_iiot.did_iiot.publicjwk import KyberPublicJwkey
    x = base64_encode_publickey(pk)
    return KyberPublicJwkey(lat, x)

def get_signed_did_document_record(did_document: dict, sk: bytes, algorithm: str):
    """Signs the DID Document and returns a structured record (alg + record + signature)."""
    raw_did_doc_encoded = encode_did_document(did_document)
    alg = algorithm.encode('utf-8')[:12].ljust(12, b'\0')
    signature = Dilithium2.sign(sk, raw_did_doc_encoded)
    value = alg + signature + raw_did_doc_encoded
    return value

async def run():
    # Initialize DHT node with signature verification
    node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
    await node.listen(5678)

    # Generate post-quantum key pairs
    dilith_mgr = DilithiumKeyManager("dilithium_keys")
    kyber_mgr = KyberKeyManager("kyber_keys")

    dilith_pk, dilith_sk = dilith_mgr.generate_keypair(2)
    kyber_pk, kyber_sk = kyber_mgr.generate_keypair(512)

    # Create DID:IIoT and DID Document
    did = DIDIndustrialIoT.generate_did_uri()

    dilith_jwk = get_dilithium_pub_key_for_did_doc(did, dilith_pk, 2)
    kyber_jwk = get_kyber_pub_key_for_did_doc(did, kyber_pk, "Kyber-512", "k1")

    vm_auth = VerificationMethod(f"{did}#k0", type="Authentication", public_jwkey=dilith_jwk)
    vm_session = VerificationMethod(f"{did}#k1", type="KeySessionExchange", public_jwkey=kyber_jwk)

    service = [Service(f"{did}#device", "DeviceAgent", "http://example.com/device")]

    did_doc = DIDDocument(id=did, verification_methods=[vm_auth, vm_session], service=service)

    # Create a signed record (algorithm + record + signature)
    signed_record = get_signed_did_document_record(did_doc.get_dict(), dilith_sk, algorithm="Dilithium-2")

    # Store the signed record in the DHT
    key = did.split(":")[-1]
    await node.set(key, signed_record)

    # Retrieve and verify the record
    result = await node.get(key)
    print("Verified record:", result)

asyncio.run(run())
```

## Initializing a Network
If you're starting a new network from scratch, just omit the `node.bootstrap` call in the example above.  Then, bootstrap other nodes by connecting to the first node you started.

See the examples folder for a first node example that other nodes can bootstrap connect to and some code that gets and sets a key/value.

## Logging
This library uses the standard [Python logging library](https://docs.python.org/3/library/logging.html).  To see debut output printed to STDOUT, for instance, use:

```python
import logging

log = logging.getLogger('kademlia')
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())
```

