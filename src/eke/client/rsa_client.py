from eke.client.client import Client
from eke.crypto.RSA import RSA
from base64 import b64encode, b64decode
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import logging

logger = logging.getLogger(__name__)

class RSAClient(Client):
    def register(self):
        username = input("Username: ")
        password = input("Password: ")
        
        self.send_data({
            "action": "register",
            "username": username,
            "password": password
        })
        
        response = self.recv_data()
        
        logger.info(f"Registration response - {response.get('success')}: {response.get('message', 'No message received')}")
        
    def negotiate(self):
        username = input("Username: ")
        password = input("Password: ")

        # generate random public key Ea
        Ea = RSA.gen()
        logger.debug(f"Generated RSA key pair: n={Ea.n}, e={Ea.e}, d={Ea.d}")

        # instantiate AES with the password
        logger.debug("Creating AES cipher with password")
        password = hashlib.sha256(password.encode()).digest()
        P = AES.new(password, AES.MODE_ECB)

        # send a negotiate command
        logger.debug("Sending negotiation request")
        self.send_data({
                "action": "negotiate",
                "username": username,
                "enc_pub_key": b64encode(P.encrypt(Ea.encode_public_key())).decode(),
                "modulus": Ea.n
        })

        # receive and decrypt R
        data = self.recv_data()
        
        if not data.get("success"):
            logger.fatal(f"Negotiation failed with message: {data.get('message')}")
            exit(1)

        logger.debug("Received negotiation data")

        enc_secret_key = data["enc_secret_key"]
        enc_secret_key = b64decode(enc_secret_key)
        dec_secret_key = P.decrypt(enc_secret_key)
        key = long_to_bytes(Ea.decrypt(bytes_to_long(dec_secret_key)))

        R = AES.new(key.ljust(16, b'\x00'), AES.MODE_ECB)
        logger.debug(f"Decrypted secret key: {key.ljust(16, b'\x00').hex()}")

        # send first challenge
        challengeA = get_random_bytes(16)
        logger.debug(f"Sending challenge A: {challengeA.hex()}")
        self.send_data({
            "action": "challenge_a",
            "username": username,
            "challenge_a": b64encode(R.encrypt(challengeA)).decode()
        })

        # receive challenge response
        data = self.recv_data()

        if not data.get("success"):
            logger.fatal(f"Challenge A failed with message: {data.get('message')}")
            exit(1)

        challenge_response = b64decode(data["challenge_response"])
        challenge_response = R.decrypt(challenge_response)
        logger.debug(f"Received challenge response: {challenge_response.hex()}")

        if challenge_response[:16] != challengeA:
            logger.fatal("Challenge A failed.")
            exit(1)

        logger.debug("Challenge A successful, proceeding with challenge B")
        challengeB = challenge_response[16:]
        
        logger.debug(f"Sending challenge B: {challengeB.hex()}")

        # response with challengeB
        self.send_data({
            "action": "challenge_b",
            "username": username,
            "challenge_b": b64encode(R.encrypt(challengeB)).decode()
        })

        # receive success message
        data = self.recv_data()
        if not data["success"]:
            logger.fatal(f"Challenge B failed with message: {self.data.get("message")}")
            exit(1)

        logger.debug("Challenge B successful")

        logger.info(f"Negotiation successful.")
        
        message = input("Enter a message to send to the server: ")
        message = message.encode().ljust(len(message) + (16 - (len(message) % 16)))

        encoded_message = R.encrypt(message)
        self.send_data({
            "action": "message",
            "username": username,
            "message": b64encode(encoded_message).decode(),
        })
        
        logger.info("Message sent successfully.")
        
        data = self.recv_data()
        
        if data.get("success"):
            decoded_message = R.decrypt(b64decode(data["message"]))
            print(f"Received message from server: {decoded_message.decode().strip()}")
        else:
            logger.fatal(f"Failed to receive message")    
            exit(1)

    def interact(self):
        print("Choose your action:" \
              "\n1. Register" \
              "\n2. Negotiate and send message")
        
        choice = int(input("Enter your choice: "))
        
        if choice == 1:
            self.register()
        elif choice == 2:
            self.negotiate()
        else:
            logger.error("Invalid choice. Please try again.")
            self.interact()