"""
DES AES and 3DES Testing Encryption Zone
Margin of Error: +- 0.05s
"""
from des import DesKey
import pyaes
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
                return (result, end - start)
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
    def dump_stats(info, filename):
        with open('dump.txt', 'w') as f:
            f.write(info)

    @staticmethod
    def Builder(eType, key, label, temp_object, build):
        build += "Type:\t\t\t{}\n".format(eType)
        build += "Testing key:\t{} => {}\n".format(label, key)
        build += "Plain text:\t\t{}\n".format(text)
        encrypted, time = temp_object.encrypt()
        build += "Encrypted:\t\t{}\n".format(encrypted)
        build += "Delta Time =>\t{}s\n".format(time)
        decrypted, time2 = temp_object.decrypt()
        build += "Decrypted:\t\t{}\n".format(decrypted)
        build += "Delta Time =>\t{}s\n------------------\n".format(time2)

        return build

    @staticmethod
    def aes_test_zone(keys: str, text: str):
        for i in keys:
            temp = AES_Crypt(keys[i], text)
            MyTools.print_stats(keys[i], i, temp)

    @staticmethod
    def des_test_zone(keys: str, text: str, dump=False):
        for i in keys:
            temp = DES_Crypt(keys[i], text)
            MyTools.print_stats(keys[i], i, temp)

    @staticmethod
    def dump(keys: str, text: str, filename: str):
        build = ""
        for i in keys:
            aes_temp = AES_Crypt(keys[i], text)
            build = MyTools.Builder("AES", keys[i], i, aes_temp, build)
            des_temp = DES_Crypt(keys[i], text)
            des_type = "DES Single" if des_temp.is_single() else "DES Triple"
            build = MyTools.Builder(des_type, keys[i], i, des_temp, build)

        MyTools.dump_stats(build, filename)


class DES_Crypt():

    def __init__(self, key: str, text: str):
        """
        :key: private key, will be encoded into bytes
        :text: plaintext, will be encoded into bytes
        """
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

    def is_single(self):
        return self.key.is_single()


class AES_Crypt():

    def __init__(self, key: str, text: str):
        """
        :key: private key
        :text: plaintext, will be encoded into bytes
        """
        self.key = key.encode('utf-8')
        self.text = bytes(text.encode('utf-8'))

    @MyTools.info("T encrypt")
    def encrypt(self):
        aes = pyaes.AESModeOfOperationCTR(self.key)
        self.encrypted = aes.encrypt(self.text)
        return self.encrypted

    @MyTools.info("T decrypt")
    def decrypt(self):
        aes = pyaes.AESModeOfOperationCTR(self.key)
        self.decrypted = aes.decrypt(self.encrypted).decode('utf-8')
        return self.decrypted

def main():
    keys = {
    "single": "some key",
    "triple": "a key for TRIPLE",
    "bytes_24": "a 24-byte key for TRIPLE",
    "realistic_key": "1234567812345678REAL_KEY",
    }

    byte16 = {
        "key0_16_bytes": "m2G2hb*XVnC#&=:@",
        "key1_16_bytes": "2:[cNLKX89N#j9^+",
        "key2_16_bytes": "+D8eS'K#8*25(My$",
        "key3_16_bytes": "Z;Y2Fe.PNx8h~]eV",
        "key4_16_bytes": "pt4YNLb9+M^m^w**",
        "key5_16_bytes": "x4eRGWXFv56m=E-x",
        "key6_16_bytes": "wvyEc@Ub9-AXSj3%",
        "key7_16_bytes": "&vb!FBFp=SWZ4k$+",
        "key8_16_bytes": "N7QbKdm2*3?meVKk",
        "key9_16_bytes": "YQ3!@2vr6y2!4dV9",
    }
    text = "emin and robert project, testing for speed"

    MyTools.aes_test_zone(byte16, text)
    MyTools.des_test_zone(byte16, text)
    MyTools.des_test_zone(keys, text)
    MyTools.dump(byte16, text, "dump.txt")

if __name__ == "__main__":
    
    main()

