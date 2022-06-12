import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import base64
import sys
import time

def take():
    time.sleep(6)
class AESCipher(object):
# credit to https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()



    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encryptedOutput = ''+(base64.b64encode(iv + cipher.encrypt(raw.encode()))).decode('utf-8')
        return encryptedOutput

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        print(iv,enc)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def newencrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encryptedOutput = 'AES'+(base64.b64encode(iv)).decode('utf-8')+'||'+(base64.b64encode(cipher.encrypt(raw.encode()))).decode('utf-8')
        return encryptedOutput

    def newdecrypt(self, enc):
        array = enc[3:].split('||')
        ciphertext = base64.b64decode(array[1])
        iv = base64.b64decode(array[0])
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        output = self._unpad(cipher.decrypt((ciphertext)))
        return (output).decode()

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

if __name__ == "__main__":
    print('==============\nLOCKBYTES File Decryptor\n============')
    print('Copyright Mark Bosco 2022\n\n')
    try:
        key = str(sys.argv[1])
        path = str(sys.argv[2])
    except:
        print("USAGE: python <path to script> key path")
    x = AESCipher(key)
    with open(path,'r') as myfile:
        y = myfile.read()
    output = x.newdecrypt(y)
    print("===DECRYPTION IN PROGRESS===")
    n =1
    take()
    with open(str(path+'.dec'),'w') as myfile:
        y = myfile.write(output)
    print('Decryption Successful!\n=============')
    print('Decrypted file is ',str(path+'.dec'))
# x = AESCipher('P@ssw0rd')
#
#
# y = x.encrypt('u')
# print(y)
# p = x.decrypt(y)
# print(p)
#
# y = x.newencrypt('u')
# print(y)
# u = x.newdecrypt(y)

