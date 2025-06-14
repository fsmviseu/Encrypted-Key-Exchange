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
    users = {}

    def handle_client_data(self, data):
        action = data.get("action")
        if action == "register":
            username = data.get("username")
            password = data.get("password")
            p = data.get("p")
            
            self.users[username] = {
                "password": password,
                "p": p
            }

        elif action == "negotiate":
            username = data.get("username")
            self.capture_response = username
        
        logger.info(f"Forwarding DH data from client to server: {data}")
        return data
    


    def handle_server_data(self, data):
        if self.capture_response:
            user = self.users.get(self.capture_response)
            password = user.get("password")
            p = user.get("p")

            password = hashlib.sha256(password.encode()).digest()
            P = AES.new(password, AES.MODE_ECB)
            
            enc_server_public_key = data["enc_public_key"]
            enc_server_public_key  = b64decode(enc_server_public_key)
            dec_server_public_key = P.decrypt(enc_server_public_key)

            B = bytes_to_long(dec_server_public_key)
            
            logger.info(f"Succesfully decrypted server's public key: {B}")
            
            B_new = pow(B, 2, p)

            logger.info(f"Generating a new B parameter: {B_new}")
            
            B_new = P.encrypt(long_to_bytes(B_new))
            
            data["enc_public_key"] = b64encode(B_new).decode()

        logger.info(f"Forwarding DH data from server to client: {data}")
        return data
