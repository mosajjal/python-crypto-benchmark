import os
import time
from struct import pack

from Crypto.Cipher import AES, ARC2, ARC4, CAST, Blowfish, ChaCha20, Salsa20
from Crypto.Hash import MD5
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def timing(f):
    def wrap(*args, **kwargs):
        time1 = time.time()
        ret = f(**kwargs)
        time2 = time.time()
        print(
            "function {:s} with arguments {} took {:.3f} ms".format(
                f.__name__, kwargs, (time2 - time1) * 1000.0
            )
        )
        return ret

    return wrap


@timing
def pycrypto_rc4(keysize=64, nonce=16, data_size=1024):
    key = get_random_bytes(keysize)
    nonce = get_random_bytes(nonce)
    tempkey = MD5.new(key + nonce).digest()
    cipher = ARC4.new(tempkey)
    _ = nonce + cipher.encrypt(get_random_bytes(data_size * 1024))

@timing
def pycrypto_rc2(keysize=32, data_size=1024, mode_str="", mode=ARC2.MODE_EAX):
    plaintext = get_random_bytes(data_size * 1024)
    secret = get_random_bytes(keysize)
    cipher = ARC2.new(key=secret, mode=mode)
    _ = cipher.iv + cipher.encrypt(plaintext)

@timing
def pycrypto_salsa20(keysize=32, data_size=1024):
    plaintext = get_random_bytes(data_size * 1024)
    secret = get_random_bytes(keysize)
    cipher = Salsa20.new(key=secret)
    _ = cipher.nonce + cipher.encrypt(plaintext)


@timing
def pycrypto_chacha20(keysize=32, data_size=1024):
    plaintext = get_random_bytes(data_size * 1024)
    secret = get_random_bytes(keysize)
    cipher = ChaCha20.new(key=secret)
    _ = cipher.nonce + cipher.encrypt(plaintext)


@timing
def pycrypto_blowfish(keysize=32, data_size=1024, mode_str="", mode=Blowfish.MODE_CBC):
    bs = Blowfish.block_size
    plaintext = get_random_bytes(data_size * 1024)
    key = get_random_bytes(keysize)
    cipher = Blowfish.new(key=key, mode=mode)
    plen = bs - len(plaintext) % bs
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)
    _ = cipher.iv + cipher.encrypt(plaintext + padding)

@timing
def pycrypto_aes(keysize=32, data_size=1024, mode_str="", mode=AES.MODE_EAX):
    plaintext = get_random_bytes(data_size * 1024)
    secret = get_random_bytes(keysize)
    cipher = AES.new(secret, mode)
    _ = cipher.encrypt(plaintext)

@timing
def cryptography_aes(keysize=32, data_size=1024, mode_str=""):
    backend = default_backend()
    key = os.urandom(keysize)
    mode = eval(mode_str)
    cipher = Cipher(algorithm=algorithms.AES(key), mode=mode(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()
    _ = encryptor.update(os.urandom(data_size) * 1024) + encryptor.finalize()

@timing
def cryptography_chacha20poly1305(keysize=32, data_size=1024):
    plaintext = get_random_bytes(data_size * 1024)
    aad = get_random_bytes(data_size * 1024)
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = get_random_bytes(12)
    _ = chacha.encrypt(nonce, plaintext, aad)

@timing
def cryptography_chacha20(keysize=32, data_size=1024):
    plaintext = get_random_bytes(data_size * 1024)
    key = get_random_bytes(keysize)
    nonce = get_random_bytes(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    _ = encryptor.update(plaintext)

@timing
def cryptography_blowfish(keysize=32, data_size=1024, mode_str=""):
    plaintext = get_random_bytes(data_size * 1024)
    key = get_random_bytes(keysize)
    algorithm = algorithms.Blowfish(key)
    mode = eval(mode_str)
    cipher = Cipher(algorithm, mode=mode(), backend=default_backend())
    encryptor = cipher.encryptor()
    _ = encryptor.update(plaintext)

@timing
def pycrypto_cast(keysize=32, data_size=1024, mode_str="", mode=CAST.MODE_CBC):
    plaintext = get_random_bytes(data_size * 1024)
    key = get_random_bytes(keysize)
    cipher = CAST.new(key, mode)
    _ = cipher.encrypt(plaintext)

if __name__ == "__main__":
    rows, columns = os.popen('stty size', 'r').read().split()
    columns = int(columns)
    pycrypto_rc4(keysize=64, nonce=16, data_size=1024)
    pycrypto_rc4(keysize=64, nonce=16, data_size=2048)
    pycrypto_rc4(keysize=64, nonce=16, data_size=4096)
    pycrypto_rc4(keysize=64, nonce=16, data_size=8192)
    print("="*columns)
    pycrypto_salsa20(keysize=32, data_size=1024)
    pycrypto_salsa20(keysize=32, data_size=2048)
    pycrypto_salsa20(keysize=32, data_size=4096)
    pycrypto_salsa20(keysize=32, data_size=8192)
    print("="*columns)
    pycrypto_chacha20(keysize=32, data_size=1024)
    pycrypto_chacha20(keysize=32, data_size=2048)
    pycrypto_chacha20(keysize=32, data_size=4096)
    pycrypto_chacha20(keysize=32, data_size=8192)
    print("="*columns)
    pycrypto_aes(keysize=16, data_size=1024, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=16, data_size=2048, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=16, data_size=4096, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=16, data_size=8192, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    print("="*columns)
    pycrypto_aes(keysize=24, data_size=1024, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=24, data_size=2048, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=24, data_size=4096, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=24, data_size=8192, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    print("="*columns)
    pycrypto_aes(keysize=32, data_size=1024, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=32, data_size=2048, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=32, data_size=4096, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    pycrypto_aes(keysize=32, data_size=8192, mode_str="AES.MODE_CFB", mode=AES.MODE_CFB)
    print("="*columns)
    pycrypto_aes(keysize=16, data_size=1024, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=16, data_size=2048, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=16, data_size=4096, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=16, data_size=8192, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    print("="*columns)
    pycrypto_aes(keysize=24, data_size=1024, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=24, data_size=2048, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=24, data_size=4096, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=24, data_size=8192, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    print("="*columns)
    pycrypto_aes(keysize=32, data_size=1024, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=32, data_size=2048, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=32, data_size=4096, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    pycrypto_aes(keysize=32, data_size=8192, mode_str="AES.MODE_CTR", mode=AES.MODE_CTR)
    print("="*columns)
    pycrypto_aes(keysize=16, data_size=1024, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=16, data_size=2048, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=16, data_size=4096, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=16, data_size=8192, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    print("="*columns)
    pycrypto_aes(keysize=24, data_size=1024, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=24, data_size=2048, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=24, data_size=4096, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=24, data_size=8192, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    print("="*columns)
    pycrypto_aes(keysize=32, data_size=1024, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=32, data_size=2048, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=32, data_size=4096, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    pycrypto_aes(keysize=32, data_size=8192, mode_str="AES.MODE_OFB", mode=AES.MODE_OFB)
    print("="*columns)
    pycrypto_aes(keysize=16, data_size=1024, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=16, data_size=2048, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=16, data_size=4096, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=16, data_size=8192, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    print("="*columns)
    pycrypto_aes(keysize=24, data_size=1024, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=24, data_size=2048, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=24, data_size=4096, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=24, data_size=8192, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    print("="*columns)
    pycrypto_aes(keysize=32, data_size=1024, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=32, data_size=2048, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=32, data_size=4096, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    pycrypto_aes(keysize=32, data_size=8192, mode_str="AES.MODE_GCM", mode=AES.MODE_GCM)
    print("="*columns)
    pycrypto_blowfish(keysize=32, data_size=1024, mode_str="Blowfish.MODE_CFB", mode=Blowfish.MODE_CFB)
    pycrypto_blowfish(keysize=32, data_size=2048, mode_str="Blowfish.MODE_CFB", mode=Blowfish.MODE_CFB)
    pycrypto_blowfish(keysize=32, data_size=4096, mode_str="Blowfish.MODE_CFB", mode=Blowfish.MODE_CFB)
    pycrypto_blowfish(keysize=32, data_size=8192, mode_str="Blowfish.MODE_CFB", mode=Blowfish.MODE_CFB)
    print("="*columns)
    pycrypto_cast(keysize=16, data_size=1024, mode_str="CAST.MODE_CFB", mode=CAST.MODE_CFB)
    pycrypto_cast(keysize=16, data_size=2048, mode_str="CAST.MODE_CFB", mode=CAST.MODE_CFB)
    pycrypto_cast(keysize=16, data_size=4096, mode_str="CAST.MODE_CFB", mode=CAST.MODE_CFB)
    pycrypto_cast(keysize=16, data_size=8192, mode_str="CAST.MODE_CFB", mode=CAST.MODE_CFB)
    print("="*columns)
    pycrypto_rc2(keysize=16, data_size=1024, mode_str="ARC2.MODE_CFB", mode=ARC2.MODE_CFB)
    pycrypto_rc2(keysize=16, data_size=2048, mode_str="ARC2.MODE_CFB", mode=ARC2.MODE_CFB)
    pycrypto_rc2(keysize=16, data_size=4096, mode_str="ARC2.MODE_CFB", mode=ARC2.MODE_CFB)
    pycrypto_rc2(keysize=16, data_size=8192, mode_str="ARC2.MODE_CFB", mode=ARC2.MODE_CFB)
    print("="*columns)
    print("="*columns)
    print("="*columns)
    cryptography_aes(keysize=32, data_size=1024, mode_str="modes.CBC")
    cryptography_aes(keysize=32, data_size=2048, mode_str="modes.CBC")
    cryptography_aes(keysize=32, data_size=4096, mode_str="modes.CBC")
    cryptography_aes(keysize=32, data_size=8192, mode_str="modes.CBC")
    print("="*columns)
    cryptography_aes(keysize=32, data_size=1024, mode_str="modes.CFB")
    cryptography_aes(keysize=32, data_size=2048, mode_str="modes.CFB")
    cryptography_aes(keysize=32, data_size=4096, mode_str="modes.CFB")
    cryptography_aes(keysize=32, data_size=8192, mode_str="modes.CFB")
    print("="*columns)
    cryptography_chacha20poly1305(keysize=32, data_size=1024)
    cryptography_chacha20poly1305(keysize=32, data_size=2048)
    cryptography_chacha20poly1305(keysize=32, data_size=4096)
    cryptography_chacha20poly1305(keysize=32, data_size=8192)
    print("="*columns)
    cryptography_chacha20(keysize=32, data_size=1024)
    cryptography_chacha20(keysize=32, data_size=2048)
    cryptography_chacha20(keysize=32, data_size=4096)
    cryptography_chacha20(keysize=32, data_size=8192)
    print("="*columns)
    cryptography_blowfish(keysize=32, data_size=1024, mode_str="modes.ECB")
    cryptography_blowfish(keysize=32, data_size=2048, mode_str="modes.ECB")
    cryptography_blowfish(keysize=32, data_size=4096, mode_str="modes.ECB")
    cryptography_blowfish(keysize=32, data_size=8192, mode_str="modes.ECB")


cipher_list = [
    "camellia-256-cfb",
    "camellia-192-cfb",
    "camellia-128-cfb",
    "des-cfb",
    "idea-cfb-py",
    "seed-cfb-py",
]
