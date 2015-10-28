import base64
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256
from Crypto import Random

#
# File to declare functions and classes used by servers and client
#

# Block size in bytes of AES Message
BLOCK_SIZE = 16

# Function to pad data that does not match BLOCK_SIZE, used by AES methods
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s)-1:])]

# Functions to encrypt and decrypt AES
def encrypt_aes(plaintext, key):
    plaintext = pad(plaintext)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plaintext))

def decrypt_aes(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]))

# Function that returns the hash of a given plaintext
def md5_hash(plaintext):
    h = MD5.new()
    h.update(plaintext)
    return h

# Class for the authenticator object to be sent through the procol
class MessageA:
    def __init__(self, sessionKey):
        self.sessionKey = sessionKey

class MessageB:
    def __init__(self, clientId, validityPeriod, clientSessionKey):
        self.clientId = clientId
        self.validityPeriod = validityPeriod
        self.clientSessionKey = clientSessionKey

class MessageC:
    def __init__(self, ticket, serviceId):
        self.ticket = ticket
        self.serviceId = serviceId

class MessageD:
    def __init__(self, clientID, timestamp):
        self.clientID = clientID
        self.timestamp = timestamp
