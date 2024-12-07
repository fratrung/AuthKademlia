import logging 
import argparse
import asyncio
import os
import sys
project_root = os.path.dirname(os.path.abspath(".."))
sys.path.append(project_root)
from kademlia.network import Server
from kademlia.auth_handler import DIDSignatureVerifierHandler
import uuid
import json
import base64
from kademlia.crypto.key_manager import DilithiumKeyManager

log = logging.getLogger('kademlia')
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())


def run_node(dht_port:int,bootstrap_nodes=None):
    
    node = Server(signature_verifier_handler=DIDSignatureVerifierHandler())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_debug(True)
    loop.run_until_complete(node.listen(dht_port))
    if bootstrap_nodes:
        loop.run_until_complete(node.bootstrap(bootstrap_nodes))
    try:
        loop.run_forever()
        
    except KeyboardInterrupt:
        print("\nShutting down node...")
    finally:
        loop.run_until_complete(node.stop())
        loop.close()
        log.info("Node stopped")
        

def get_args():
    parser = argparse.ArgumentParser(description="Start DHT Node")
    parser.add_argument("dht_port",type=int,help="Port for DHT node")
    parser.add_argument("--bootstrap_ip", type=str, help="Bootstrap node IP", default=None)
    parser.add_argument("--bootstrap_port", type=int, help="Bootstrap node port", default=None)
    return parser.parse_args()

if __name__ == '__main__':
    args = get_args()
    if args:
        if args.bootstrap_ip and args.bootstrap_port:
            bootstrap_nodes = [(args.bootstrap_ip, args.bootstrap_port)]
        else:
            bootstrap_nodes = None
        try:
           #bootstrap_nodes=[("127.0.0.1",8007),("127.0.0.1",8008)]
           run_node(args.dht_port, bootstrap_nodes)
        except KeyboardInterrupt:
            print("\nShutting down node...")