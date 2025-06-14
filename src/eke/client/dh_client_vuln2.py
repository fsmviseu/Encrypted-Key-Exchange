from eke.client.client import Client
from eke.common import DH_PRIME_BITS, DH_G
from base64 import b64encode, b64decode
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import logging
import hashlib
import random

logger = logging.getLogger(__name__)

class DHClient(Client):
    def register(self):
        username = input("Username: ")
        password = input("Password: ")
        
        p = getPrime(DH_PRIME_BITS)
        print(f"Generated prime p: {p}")
        
        """
        Prime is pre-shared with the server as an additional security measure against MITM attacks. 
        In the ideal protocol, p would be agreed upon beforehand, similarly to the password.
        """
        self.send_data({
            "action": "register",
            "username": username,
            "password": password,
            "p": p
        })
        
        response = self.recv_data()
        
        logger.info(f"Registration response - {response.get('success')}: {response.get('message', 'No message received')}")
        
    def negotiate(self):
        username = input("Username: ")
        password = input("Password: ")
        p = int(input("Enter the prime number p generated in the registration step: "))
        
        logger.debug(f"generated prime p: {p}")

        # Alice generates a private number a
        a = random.randint(1, p - 1)
        logger.debug(f"Generated a: {a}")

        # instantiate AES with the password
        logger.debug("Creating AES cipher with password")
        password = hashlib.sha256(password.encode()).digest()
        P = AES.new(password, AES.MODE_ECB)
        
        A = pow(DH_G, a, p)
        enc_public_key = pad(long_to_bytes(A), 16)

        # send a negotiate command with enc_password(g^a % p)
        logger.debug(f"Sending negotiation request with public key: {A}")
        self.send_data({
                "action": "negotiate",
                "username": username,
                "enc_pub_key": b64encode(P.encrypt(enc_public_key)).decode(),
        })

        # receive and decrypt R
        data = self.recv_data()
        
        if not data.get("success"):
            logger.fatal(f"Negotiation failed with message: {data.get('message')}")
            exit(1)

        logger.debug("Received negotiation data")

        enc_server_public_key = data["enc_public_key"]
        enc_server_public_key  = b64decode(enc_server_public_key)
        dec_server_public_key = P.decrypt(enc_server_public_key)
        B = bytes_to_long(dec_server_public_key)
        
        logger.debug(f"Received server public key B: {B}")
        
        R = pow(B, a, p)
        logger.debug(f"Computed secret key R: {R}")

        print(f"Secret key are different between client and server but correlated. Attack succesful!")

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