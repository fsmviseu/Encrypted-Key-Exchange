from eke.server.server import RequestHandler
from eke.crypto.RSA import RSA
from base64 import b64encode, b64decode
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import logging

logger = logging.getLogger(__name__)

class RSARequestHandler(RequestHandler):
    users = {}

    def handle_data(self, data):
        logger.info(f"Processing RSA data: {data}")
        
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
        
        if not username or not password:
            logger.info("Username or password not provided for registration")
            return {"success": False, "message": "Username and password are required"}

        if username in self.users:
            logger.info(f"User {username} already exists")
            return {"success": False, "message": "User already exists"}

        self.users[username] = {
            "password": password,
            "state": "register"
        }

        logger.info(f"User {username} registered successfully")
        
        return {"success": True, "message": "User registered successfully"}

    def handle_negotiate(self, data):
        username = data.get("username", None)
        enc_pub_key = data.get("enc_pub_key", None)
        modulus = data.get("modulus", None)

        if not username or not enc_pub_key or not modulus:
            logger.info("Missing negotiation parameters")
            return {"success": False, "message": "Missing negotiation parameters"}

        if username not in self.users:
            logger.info(f"User {username} does not exist")
            return {"success": False, "message": "User does not exist"}

        self.users[username]["state"] = "negotiate"
        
        # decrypt Ea using P

        password = self.users[username]["password"].encode() 
        password = hashlib.sha256(password).digest()

        logger.debug(f"Decrypting public key for user {username}")
        P = AES.new(password, AES.MODE_ECB)
        e = bytes_to_long(P.decrypt(b64decode(enc_pub_key)))

        # e is always odd, but we add 1 with 50% probability
        if e % 2 == 0:
            e -= 1

        logger.debug(f"Using public exponent e: {e}")

        # generate secret key R
        R = get_random_bytes(16)
        Ea = RSA.from_pub_key(e, modulus)
        
        logger.debug(f"Generated secret key R: {R.hex()}")
        self.users[username]["secret_key"] = R
        R = bytes_to_long(R)
        enc_secret_key = Ea.encrypt(R)
        enc_secret_key = P.encrypt(long_to_bytes(enc_secret_key))
        

        logger.info(f"Sending encrypted secret key {enc_secret_key.hex()} to user {username}")
        return {
            "success": True,
            "enc_secret_key": b64encode(enc_secret_key).decode()
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
        self.users[username]["state"] = "challenge_b"

        logger.debug(f"Using secret key for user {username}: {secret_key.hex()}")
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
        R = AES.new(secret_key, AES.MODE_ECB)
        logger.debug(f"Using secret key for user {username}: {secret_key.hex()}")

        decoded_message = R.decrypt(b64decode(message))
        
        logger.info(f"Received message from user {username}: {decoded_message.decode().strip()}")
        
        message = "Hello back from server! This was your message: " + decoded_message.decode().strip()
        message = message.encode().ljust(len(message) + (16 - (len(message) % 16)))
        encoded_message = R.encrypt(message)

        return {
            "success": True,
            "message": b64encode(encoded_message).decode()
        }