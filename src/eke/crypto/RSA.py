import random
import math
from Crypto.Util.number import getPrime, long_to_bytes
import Crypto.Random.random as random

# Nr of bits of the RSA modulo N
from eke.common import RSA_SECURITY_BITS

class RSA:
    # Standard RSA parameters
    def __init__(self, p=None, q=None):
        if p is None or q is None:
            self.p = self.q = self.n = self.d = self.e = None
        else:
            self.p, self.q, self.n, phi = p, q, p * q, (p - 1) * (q - 1)
            while True:
                e = random.getrandbits(RSA_SECURITY_BITS)
                if math.gcd(e, phi) == 1: # ensure that e is coprime to phi in order to ensure unique decryption
                    self.d, self.e = pow(e, -1, phi), e
                    break

    # create an RSA object with new keypair
    def gen():
        return RSA(getPrime(RSA_SECURITY_BITS // 2), getPrime(RSA_SECURITY_BITS // 2))

    def from_pub_key(e, n):
        rsa = RSA()
        rsa.e, rsa.n = e, n
        return rsa

    # standard RSA encryption/decryption
    def encrypt(self, message):
        return pow(message, self.e, self.n)

    def decrypt(self, message):
        return pow(message, self.d, self.n)

    def encode_public_key(self):
        # add 1 to e 50% of the time to prevent partition attacks 
        e = self.e + 1 * random.getrandbits(1)
        return long_to_bytes(e)

