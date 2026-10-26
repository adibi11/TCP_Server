from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

AES_KEY_SIZE = 32


"""Generate a random AES key of size AES_KEY_SIZE"""


def generate_aes_key() -> bytes:
    return get_random_bytes(AES_KEY_SIZE)


"""Encrypt the given data using the provided RSA public key. The public key should be in bytes format."""


def encrypt_with_rsa(public_key: bytes, data: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA1)
    return cipher.encrypt(data)


"""Decrypt the given data using the provided RSA private key. The private key should be in bytes format."""


def decrypt_with_aes(encrypted: bytes, aes_key: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError("Invalid AES key length")

    if not encrypted or len(encrypted) % 16 != 0:
        raise ValueError("Invalid encrypted content length")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(16))

    return unpad(cipher.decrypt(encrypted), AES.block_size)
