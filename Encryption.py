"""

DES AES and 3DES Testing Encryption Zone

Margin of Error: +- 0.05s

"""

from des import DesKey
import pyaes
from functools import wraps
import time


class MyTools:
    @staticmethod
    def info(name: str):
        def decorator(func):
            def wrapper(*args, **kwargs):
                start = time.perf_counter()
                result = func(*args, **kwargs)
                end = time.perf_counter()
                print(f"{name} =>\tElapsed: {end - start:0.6f} seconds")
                return result
            return wrapper
        return decorator

    @staticmethod
    def print_stats(key, label, temp_object):
        print("Testing key: \t{}: {}".format(label, key))
        print("Plain text: \t{}\n".format(text))
        print("Encrypted: \t{}\n".format(temp_object.encrypt()))
        print("Decrypted: \t{}\n".format(
            temp_object.decrypt()), end='------------------\n')

    @staticmethod
    def aes_test_zone(keys: str, text: str):
        for i in keys:
            temp = AES_Crypt(keys[i], text)
            MyTools.print_stats(keys[i], i, temp)

    @staticmethod
    def des_test_zone(keys: str, text: str):
        for i in keys:
            temp = DES_Crypt(keys[i], text)
            MyTools.print_stats(keys[i], i, temp)


class DES_Crypt():

    def __init__(self, key: str, text: str):
        self.key = DesKey(bytes(key.encode('utf-8')))
        self.text = bytes(text.encode('utf-8'))

    @MyTools.info("T encrypt")
    def encrypt(self):
        self.encrypted = self.key.encrypt(self.text, padding=True)
        return self.encrypted

    @MyTools.info("T decrypt")
    def decrypt(self):
        self.decrypted = self.key.decrypt(self.encrypted, padding=True)
        return self.decrypted


class AES_Crypt():

    def __init__(self, key: str, text: str):
        self.key = key.encode('utf-8')
        self.text = bytes(text.encode('utf-8'))

    @MyTools.info("T encrypt")
    def encrypt(self):
        aes = pyaes.AESModeOfOperationCTR(self.key)
        self.encrypted = aes.encrypt(text)
        return self.encrypted

    @MyTools.info("T decrypt")
    def decrypt(self):
        aes = pyaes.AESModeOfOperationCTR(self.key)
        self.decrypted = aes.decrypt(self.encrypted).decode('utf-8')
        return self.decrypted


if __name__ == "__main__":

    keys = {
        "single": "some key",
        "triple": "a key for TRIPLE",
        "bytes_24": "a 24-byte key for TRIPLE",
        "realistic_key": "1234567812345678REAL_KEY",
    }

    byte16 = {
        "key0_16byte": "m2G2hb*XVnC#&=:@",
        "key1_16byte": "2:[cNLKX89N#j9^+",
        "key2_16byte": "+D8eS'K#8*25(My$",
        "key3_16byte": "Z;Y2Fe.PNx8h~]eV",
        "key4_16byte": "pt4YNLb9+M^m^w**",
        "key5_16byte": "x4eRGWXFv56m=E-x",
        "key6_16byte": "wvyEc@Ub9-AXSj3%",
        "key7_16byte": "&vb!FBFp=SWZ4k$+",
        "key8_16byte": "N7QbKdm2*3?meVKk",
        "key9_16byte": "YQ3!@2vr6y2!4dV9",
    }
    text = "emin and robert project, testing for speed"

    MyTools.aes_test_zone(byte16, text)
    MyTools.des_test_zone(byte16, text)
    MyTools.des_test_zone(keys, text)
