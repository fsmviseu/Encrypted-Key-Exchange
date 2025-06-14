import socketserver
import logging
from eke import common
import json

logger = logging.getLogger(__name__)

class RequestHandler(socketserver.BaseRequestHandler):
    def handle_data(self, _):
        raise NotImplementedError("This method should be overridden in subclasses.")

    def handle(self):
        logger.debug(f"--- Accepted connection from {self.client_address[0]} ---")
        client = self.request

        try:
            while True:
                data = client.recv(common.CHUNK_SIZE)

                if not data:
                    break
                
                data = json.loads(data)

                logger.debug(f"Received data from client: {data}")
                data = self.handle_data(data)

                logger.debug(f"Sending data back to client: {data}")
                client.sendall(json.dumps(data).encode())
        except ConnectionResetError:
            logger.fatal("Connection was reset by a peer.")
            exit(1)
        except Exception as e:
            logger.fatal(f"An error occurred: {e}")
            exit(1)
        finally:
            logger.debug(f"--- Closing connection from {self.client_address[0]} ---")
            client.close()
            

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, host, port, request_handler):
        super().__init__((host, port), request_handler)
        logger.info(f"Server started on {host}:{port}")

