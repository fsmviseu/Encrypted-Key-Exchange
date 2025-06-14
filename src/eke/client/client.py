import socket
import json
import logging
from eke import common

logger = logging.getLogger(__name__)

class Client:
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug(f"Connecting to {host}:{port}")

        try:
            self.socket.connect((host, port))
        except ConnectionRefusedError:
            logger.fatal(f"Failed to connect to server {host}:{port}")
            exit(1)

        logger.debug(f"Successfully connected")
        
    def close(self):
        self.socket.close()
        
    def send_data(self, data):
        try:
            self.socket.sendall(json.dumps(data).encode())
        except Exception as e:
            logger.fatal(f"An error ocurred while sending data: {e}")
            exit(1)
        
    def recv_data(self):
        try:
            data = self.socket.recv(common.CHUNK_SIZE)
            return json.loads(data)
        except Exception as e:
            logger.fatal(f"An error ocurred while receiving  data: {e}")
            exit(1)

    def interact(self):
        raise NotImplementedError("This method should be implemented by subclasses")