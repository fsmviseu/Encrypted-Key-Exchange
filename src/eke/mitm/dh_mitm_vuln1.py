from eke.mitm.mitm import MITMRequestHandler
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib
import logging

logger = logging.getLogger(__name__)

class DHMITMRequestHandler(MITMRequestHandler):
    capture_response = False

    def handle_client_data(self, data):
        if data.get("action") != "message":
            logger.info(f"Forwarding DH data from client to server: {data}")
            return data
    
        # using 1 as the secret key since a=0
        key = hashlib.sha256(long_to_bytes(1)).digest()
        R = AES.new(key, AES.MODE_ECB)
        
        message = b64decode(data.get("message"))
        print(message)
        message = unpad(R.decrypt(message), 16)

        new_message = "MITM attack successful! Original message: " + message.decode()
        logger.info(f"Changing message from client {data.get('username')} to: '{new_message}'")
        
        data["message"] = pad(new_message.encode(), 16)
        data["message"] = b64encode(R.encrypt(data["message"])).decode()
        
        self.capture_response = True
        return data

    def handle_server_data(self, data):
        if not self.capture_response:
            logger.info(f"Forwarding DH data from server to client: {data}")
            return data

        # using 1 as the secret key since a=0
        key = hashlib.sha256(long_to_bytes(1)).digest()
        R = AES.new(key, AES.MODE_ECB)

        message = b64decode(data.get("message"))
        message = unpad(R.decrypt(message), 16)

        new_message = "Hello from the MITM side!"
        logger.info(f"Changing message from client {data.get('username')} to: '{new_message}'")
        
        data["message"] = pad(new_message.encode(), 16)
        data["message"] = b64encode(R.encrypt(data["message"])).decode()
        
        self.capture_response = False
        
        return data
        
