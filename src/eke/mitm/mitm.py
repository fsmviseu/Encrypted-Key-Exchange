import socketserver
import logging
from eke import common
from eke.client.client import Client
import json

logger = logging.getLogger(__name__)

class MITMRequestHandler(socketserver.BaseRequestHandler):
    SERVER_HOST = None
    SERVER_PORT = None

    def handle_client_data(self, _):
        raise NotImplementedError("This method should be overridden in subclasses.")

    def handle_server_data(self, _):
        raise NotImplementedError("This method should be overridden in subclasses.")

    def handle(self):
        logger.debug(f"Accepted connection from {self.client_address[0]}")
        client = self.request
        server = Client(self.SERVER_HOST, self.SERVER_PORT)

        try:
            while True:
                data = client.recv(common.CHUNK_SIZE)

                if not data:
                    break
                
                data = json.loads(data)

                logger.debug(f"Received data from client: {data}")
                data = self.handle_client_data(data)

                logger.debug(f"Sending data to server: {data}")
                server.send_data(data)
                
                data = server.recv_data()

                logger.debug(f"Received data from server: {data}")
                data = self.handle_server_data(data)

                logger.debug(f"Sending data back to client: {data}")
                client.sendall(json.dumps(data).encode())

        except ConnectionResetError:
            logger.fatal("Connection was reset by a peer.")
            exit(1)
        except Exception as e:
            logger.fatal(f"An error occurred during forwarding: {e}")
            raise e
            exit(1)
        finally:
            logger.debug(f"Closing connection from {self.client_address[0]}")
            server.close()
            client.close()
            
class MITMServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, host, port, request_handler):
        super().__init__((host, port), request_handler)
        logger.info(f"MITM server started on {host}:{port}")

