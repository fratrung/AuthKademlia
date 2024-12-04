import socket
from abc import abstractmethod
import asyncio

class LANDiscover():
    
    @abstractmethod
    
    async def discover_peers(port,timeout=2):
        message = b"Kademlia Bootstrap"
        broadcast_ip = "255.255.255.255" 
        peers = []
        
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.setblocking(False)
        

        try:
            print("Operazione di Discovery")
            await loop.sock_sendto(sock, message, (broadcast_ip, port))
            print(f"messaggio inviato: {message}, {broadcast_ip}, {port}")
            while True:
                try:
                    data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout)
                    if data:
                        print(data)
                        peers.append(addr)
                except asyncio.TimeoutError:
                    print("Timeout raggiunto durante la scoperta dei peer.")
                    break
                
        except Exception as e:
            print(f"Errore durante la comunicazione: {e}")
      
        finally:
            sock.close()

        return peers
    
    @staticmethod
    async def listen_broadcast(broadcast_port,response):
        loop = asyncio.get_event_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(("",broadcast_port))
            s.setblocking(False)
            print("Nodo in ascolto per richieste broadcast LAN Discovery")
            
            try:
                while True:
                    print(f"Sono in ascolto sulla porta {broadcast_port}")
                    data, addr = await loop.sock_recvfrom(s,1024)
                    message = data.decode('utf-8')
                    print(f"Ricevuto messaggio broadcast da : {addr}: {message}")
                    await loop.sock_sendto(s, response.encode('utf-8'), addr)
                    print(f"Invio della risponta {response}")
                    
            except Exception as e:
                print(f"Errore durante l'ascolto del broadcast: {e}")