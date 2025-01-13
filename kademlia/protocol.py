import random
import asyncio
import logging
import zlib

from rpcudp.rpcudp.protocol import RPCProtocol

from kademlia.node import Node
from kademlia.routing import RoutingTable
from kademlia.utils import digest
from kademlia.auth_handler import  SignatureVerifierHandler, DIDSignatureVerifierHandler

log = logging.getLogger(__name__)  # pylint: disable=invalid-name


class KademliaProtocol(RPCProtocol):
    def __init__(self, source_node, storage, ksize,signature_verifier_handler: SignatureVerifierHandler):
        RPCProtocol.__init__(self)
        self.router = RoutingTable(self, ksize, source_node)
        self.storage = storage
        self.source_node = source_node
        self.signature_verifier_handler = signature_verifier_handler
        
    def get_refresh_ids(self):
        """
        Get ids to search for to keep old buckets up to date.
        """
        ids = []
        for bucket in self.router.lonely_buckets():
            rid = random.randint(*bucket.range).to_bytes(20, byteorder='big')
            ids.append(rid)
        return ids

    def rpc_stun(self, sender):  # pylint: disable=no-self-use
        return sender

    def rpc_ping(self, sender, nodeid):
        source = Node(nodeid, sender[0], sender[1])
        self.welcome_if_new(source)
        return self.source_node.id
    
    def rpc_update(self,sender,nodeid,key,value,auth_signature):
        
        #try:
        #    value = zlib.decompress(compressed_value)
        #    auth_signature = zlib.decompress(compressed_auth_signature)  
        #except zlib.error as e:
        #    log.error("Errore nella decompressione dei dati: %s", e)
        #    return False
        
        old_value = self.storage[key]
        if not old_value:
            log.error(f"Record {key} does not existsQ!")
        is_authenticated_update = self.signature_verifier_handler.handle_update_verification(value,old_value,auth_signature)
        
        if not is_authenticated_update:
            log.error("Unauthenticated Update")
            return False
        
        log.debug("AUTHENTICATED UPDATE")
        source = Node(nodeid, sender[0], sender[1])
        self.welcome_if_new(source)
        log.debug("got a store request from %s, storing '%s'='%s'",
                  sender, key.hex(), value)
        self.storage[key] = value
        return True
    
    def rpc_store(self, sender, nodeid, key, value):
        
        result = self.storage.get(key)
        if result:
            log.error(f"record {key} already exists")
            return 
            
        is_valid_signature = self.signature_verifier_handler.handle_signature_verification(value)
        if not is_valid_signature:
            log.error("Invalid Signature")
            return False
        print("\n\nSIGNATURE VERIFIED (protocol.py)\n\n")
        
        source = Node(nodeid, sender[0], sender[1])
        self.welcome_if_new(source)
        log.debug("got a store request from %s, storing '%s'='%s'",
                  sender, key.hex(), value)
        self.storage[key] = value
        return True

    def rpc_find_node(self, sender, nodeid, key):
        log.info("finding neighbors of %i in local table",
                 int(nodeid.hex(), 16))
        source = Node(nodeid, sender[0], sender[1])
        self.welcome_if_new(source)
        node = Node(key)
        neighbors = self.router.find_neighbors(node, exclude=source)
        return list(map(tuple, neighbors))

    def rpc_find_value(self, sender, nodeid, key):
        source = Node(nodeid, sender[0], sender[1])
        self.welcome_if_new(source)
        value = self.storage.get(key, None)
        if value is None:
            return self.rpc_find_node(sender, nodeid, key)
        return {'value': value}

    async def call_find_node(self, node_to_ask, node_to_find):
        address = (node_to_ask.ip, node_to_ask.port)
        result = await self.find_node(address, self.source_node.id,
                                      node_to_find.id)
        return self.handle_call_response(result, node_to_ask)

    async def call_find_value(self, node_to_ask, node_to_find):
        address = (node_to_ask.ip, node_to_ask.port)
        result = await self.find_value(address, self.source_node.id,
                                       node_to_find.id)
        return self.handle_call_response(result, node_to_ask)

    async def call_ping(self, node_to_ask):
        address = (node_to_ask.ip, node_to_ask.port)
        result = await self.ping(address, self.source_node.id)
        return self.handle_call_response(result, node_to_ask)

    async def call_store(self, node_to_ask, key, value):
        address = (node_to_ask.ip, node_to_ask.port)
        result = await self.store(address, self.source_node.id, key, value)
        return self.handle_call_response(result, node_to_ask)
    
    async def call_update(self,node_to_ask,key,value,auth_signature):
        
        #compressed_value = zlib.compress(value) 
        #compressed_auth_signature = zlib.compress(auth_signature)
        
        #print(len(compressed_value+compressed_auth_signature))
        address = (node_to_ask.ip, node_to_ask.port)
        result = await self.update(address,self.source_node.id,key,value,auth_signature)
        return self.handle_call_response(result, node_to_ask)
    
    def welcome_if_new(self, node):
        """
        Given a new node, send it all the keys/values it should be storing,
        then add it to the routing table.

        @param node: A new node that just joined (or that we just found out
        about).

        Process:
        For each key in storage, get k closest nodes.  If newnode is closer
        than the furtherst in that list, and the node for this server
        is closer than the closest in that list, then store the key/value
        on the new node (per section 2.5 of the paper)
        """
        if not self.router.is_new_node(node):
            return

        log.info("never seen %s before, adding to router", node)
        for key, value in self.storage:
            keynode = Node(digest(key))
            neighbors = self.router.find_neighbors(keynode)
            if neighbors:
                last = neighbors[-1].distance_to(keynode)
                new_node_close = node.distance_to(keynode) < last
                first = neighbors[0].distance_to(keynode)
                this_closest = self.source_node.distance_to(keynode) < first
            if not neighbors or (new_node_close and this_closest):
                asyncio.ensure_future(self.call_store(node, key, value))
        self.router.add_contact(node)

    def handle_call_response(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if not result[0]:
            log.warning("no response from %s, removing from router", node)
            self.router.remove_contact(node)
            return result

        log.info("got successful response from %s", node)
        self.welcome_if_new(node)
        return result
    
    def rpc_leave(self, sender, nodeid):
        """
        Handle the scenario when a node leaves the network.
        The sender here is the node that is leaving the network.
        The receiver should remove this node from its routing table.
        """
        log.info(f"Node {nodeid.hex()} is leaving the network.")
        
        # Remove the node from the local routing table
        source = Node(nodeid, sender[0], sender[1])
        self.router.remove_contact(source)
        
        # 3. Optionally notify neighbors that this node is leaving (broadcasting leave)
        #for neighbor in self.router.buckets:
        #    for n in neighbor.get_nodes():
        #        asyncio.ensure_future(self.call_leave(n, nodeid))

        return True

    def handle_call_leave_response(self, result, node):
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if not result[0]:
            log.warning("no response from %s, removing from router", node)
            self.router.remove_contact(node)
            return result
        return None
        
    
    async def call_leave(self, node_to_ask, nodeid):
        """
        Notify a node that another node is leaving the network.
        This will prompt the node to remove the leaving node from its routing table.
        """
        try:
            address = (node_to_ask.ip,node_to_ask.port)
            result = await self.leave(address, nodeid)
            return self.handle_call_leave_response(result, node_to_ask)
        except asyncio.CancelledError:
            log.warning(f"Call to {node_to_ask} was cancelled.")
            return None
 
