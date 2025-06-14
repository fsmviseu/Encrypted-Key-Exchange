from eke.server.server import RequestHandler
from eke.common import DH_G
from base64 import b64encode, b64decode
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import logging
import random

logger = logging.getLogger(__name__)

class DHRequestHandler(RequestHandler):
    users = {}

    def handle_data(self, data):
        logger.info(f"Processing DH data: {data}")
        
        action = data.get("action", None)
        
        match action:
            case "register":
                return self.handle_register(data)
            case "negotiate":
                return self.handle_negotiate(data)
            case "challenge_a":
                return self.handle_challenge_a(data)
            case "challenge_b":
                return self.handle_challenge_b(data)
            case "message":
                return self.handle_message(data)
            case _:
                logger.error(f"Unknown action: {action}")
                return {"success": False, "message": "Unknown action"}

    def handle_register(self, data):
        username = data.get("username", None)
        password = data.get("password", None)
        p = data.get("p", None)
        
        if not username or not password or not p:
            logger.info("Username or password or p not provided for registration")
            return {"success": False, "message": "Username and password and p are required"}

        if username in self.users:
            logger.info(f"User {username} already exists")
            return {"success": False, "message": "User already exists"}

        self.users[username] = {
            "password": password,
            "state": "register",
            "p": p
        }

        logger.info(f"User {username} registered successfully")
        
        return {"success": True, "message": "User registered successfully"}

    def handle_negotiate(self, data):
        username = data.get("username", None)
        enc_pub_key = data.get("enc_pub_key", None)

        if not username or not enc_pub_key:
            logger.info("Missing negotiation parameters")
            return {"success": False, "message": "Missing negotiation parameters"}

        if username not in self.users:
            logger.info(f"User {username} does not exist")
            return {"success": False, "message": "User does not exist"}

        self.users[username]["state"] = "negotiate"
        
        # decrypt A using password

        password = self.users[username]["password"].encode() 
        password = hashlib.sha256(password).digest()
        
        p = self.users[username]["p"]

        logger.debug(f"Decrypting public key for user {username}")
        P = AES.new(password, AES.MODE_ECB)
        enc_pub_key = b64decode(enc_pub_key)
        dec_pub_key = P.decrypt(enc_pub_key)
        dec_pub_key = unpad(dec_pub_key, 16)
        A = bytes_to_long(dec_pub_key)

        logger.debug(f"Client public key A: {A}")
        
        b = random.randint(1, p - 1)

        logger.debug(f"Generated b: {b}")

        # generate secret key R
        R = pow(A, b, p)
        
        logger.info(f"Computed secret key R: {R}")
        self.users[username]["secret_key"] = R

        B = pow(DH_G, b, p)
        logger.debug(f"Computed server public key B: {B}")

        enc_public_key = P.encrypt(long_to_bytes(B))

        logger.debug(f"Sending encrypted server public key {enc_public_key.hex()} to user {username}")
        return {
            "success": True,
            "enc_public_key": b64encode(enc_public_key).decode()
        }

    def handle_challenge_a(self, data):
        username = data.get("username", None)
        challenge_a = data.get("challenge_a", None)

        if not username or not challenge_a:
            logger.info("Missing parameters for challenge A")
            return {"success": False, "message": "Missing parameters for challenge A"}

        if username not in self.users or self.users[username]["state"] != "negotiate":
            logger.info(f"User {username} is not in the correct state for challenge A")
            return {"success": False, "message": "User not in correct state"}
        
        # transform secret key into a cipher instance
        secret_key = self.users[username]["secret_key"]
        secret_key = hashlib.sha256(long_to_bytes(secret_key)).digest()
        self.users[username]["state"] = "challenge_a"

        logger.debug(f"Using secret key for user {username}: {secret_key.hex()}")
        R = AES.new(secret_key, AES.MODE_ECB)

        challenge_a = b64decode(challenge_a)
        challenge_a = R.decrypt(challenge_a)
        logger.debug(f"Decrypted challenge A: {challenge_a.hex()}")

        challenge_b = get_random_bytes(16)
        
        logger.debug(f"Generated challenge B: {challenge_b.hex()}")
        challenges = R.encrypt(challenge_a + challenge_b)

        self.users[username]["challenge_b"] = challenge_b
        
        logger.info(f"Sending challenge response {challenges.hex()} for user {username}")
        return {
            "success": True,
            "challenge_response": b64encode(challenges).decode()
        }


    def handle_challenge_b(self, data):
        username = data.get("username", None)
        challenge_b = data.get("challenge_b", None)

        if not username or not challenge_b:
            logger.info("Missing parameters for challenge B")
            return {"success": False, "message": "Missing parameters for challenge B"}

        if username not in self.users or self.users[username]["state"] != "challenge_a":
            logger.info(f"User {username} is not in the correct state for challenge B")
            return {"success": False, "message": "User not in correct state"}

        # transform secret key into a cipher instance
        secret_key = self.users[username]["secret_key"]
        secret_key = hashlib.sha256(long_to_bytes(secret_key)).digest()
        self.users[username]["state"] = "challenge_b"

        logger.debug(f"Using secret key for user {username}: {secret_key}")
        R = AES.new(secret_key, AES.MODE_ECB)

        challenge_b = b64decode(challenge_b)
        challenge_b = R.decrypt(challenge_b)
        logger.debug(f"Decrypted challenge B: {challenge_b.hex()}")
        
        saved_challenge_b = self.users[username].get("challenge_b")
        logger.debug(f"Saved challenge B: {saved_challenge_b.hex()}")
        
        if challenge_b != saved_challenge_b:
            logger.info(f"Challenge B failed for user {username}")
            return {"success": False, "message": "Challenge B failed"}
        else:
            logger.info(f"Challenge B successful for user {username}")
            return {"success": True, "message": "Challenge B successful"}

    def handle_message(self, data):
        username = data.get("username", None)
        message = data.get("message", None)

        if not username or not message:
            logger.info("Missing parameters for message")
            return {"success": False, "message": "Missing parameters for message"}

        if username not in self.users or self.users[username]["state"] != "challenge_b":
            logger.info(f"User {username} is not in the correct state for sending messages")
            return {"success": False, "message": "User not in correct state"}

        # transform secret key into a cipher instance
        secret_key = self.users[username]["secret_key"]
        logger.debug(f"Using secret key for user {username}: {secret_key}")
        secret_key = hashlib.sha256(long_to_bytes(secret_key)).digest()
        R = AES.new(secret_key, AES.MODE_ECB)

        decoded_message = unpad(R.decrypt(b64decode(message)), 16)
        
        logger.info(f"Received message from user {username}: {decoded_message.decode().strip()}")
        
        message = "Hello back from server! This was your message: " + decoded_message.decode().strip()
        message = pad(message.encode(), 16)
        encoded_message = R.encrypt(message)

        return {
            "success": True,
            "message": b64encode(encoded_message).decode()
        }