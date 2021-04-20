from des import DesKey
from functools import wraps
import time


class MyTools:
    def info(name):

        def decorator(func):

            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                result = func(*args, **kwargs)
                end = time.perf_counter()
                print(f"{name} =>\tElapsed: {end - start:0.6f} seconds")
                return result

            return wrapper
        return decorator


class DES_Crypt(MyTools):

    def __init__(self, key: str, text: str):
        self.key = DesKey(bytes(key.encode('utf-8')))
        self.text = bytes(text.encode('utf-8'))

    @MyTools.info("encrypt")
    def encrypt(self):
        self.encrypted = self.key.encrypt(self.text, padding=True)
        return self.encrypted

    @MyTools.info("decrypt")
    def decrypt(self):
        self.decrypted = self.key.decrypt(self.encrypted, padding=True)
        return self.decrypted


if __name__ == "__main__":
    keys = {
        "single": "some key",
        "triple": "a key for TRIPLE",
        "bytes_24": "a 24-byte key for TRIPLE",
        "realistic_key": "1234567812345678REAL_KEY"
    }
    text = "emin and robert project, testing for speed"

    for i in keys:
        single = DES_Crypt(keys[i], text)
        print("Testing key: \t{}: {}".format(i, keys[i]))
        print("Plain text: \t{}\n".format(text))
        print("Encrypted: \t{}\n".format(single.encrypt()))
        print("Decrypted: \t{}\n".format(
            single.decrypt()), end='------------------\n')
