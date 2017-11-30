import sys
from .helpers import pad, unpad, generateIV, chunkMessage, XOR, Fk, readFiles, writeFile

blockSize = 16 # bytes

'''
Encrypts message using key with cbc mode.
Appends IV to beginning of ciphertext. If IV isn't provided, one is generated.
'''
def encrypt(message, key, IV = None):
    if (message is None) or (len(message) == 0):
        raise ValueError('message cannot be null or empty')
    if type(key) is not bytes:
        raise TypeError('key must be of type bytes')
    if IV is None:
        IV = generateIV(blockSize)
    
    cipherText = bytes(IV)

    paddedMessage = pad(message, blockSize)
    blocks = chunkMessage(paddedMessage, blockSize)
    for block in blocks:
        # update the IV to be the newly encrypted ciphertext.
        IV = encryptBlock(block, key, IV)
        cipherText += IV
    
    return cipherText

'''
Encrypts a single block using cbc mode.
XORs the message with the IV and passes it through AES.
'''
def encryptBlock(block, key, IV):
    xoredMessage = XOR(block, IV)
    return Fk(xoredMessage, key, True)

'''
Decrypts message via cbc with key given the ciphertext generated from encrypt.
cipherText is prepended with the IV created from encrypt.
'''
def decrypt(cipherText, key):
    if (cipherText is None) or (len(cipherText) == 0):
        raise ValueError('cipherText cannot be null or empty')

    IV, *blocks = chunkMessage(cipherText, blockSize)
    
    plainText = bytes()
    for block in blocks:
        plainText += decryptBlock(block, key, IV)
        IV = block # IV becomes current ciphertext

    return unpad(plainText)

'''
Decrypt block via cbc.
'''
def decryptBlock(block, key, IV):
    return XOR(Fk(block, key, False), IV)

def test():
    key = 'abcdefghijklmnopqrstuvwxyz123456' 
    m = bytes('Attack at dawn! Attack at dawn! Attack at dawn! Attack at dawn! Attack at dawn! ', 'utf8')
    cipherText = encrypt(m, key)
    print(cipherText)
    plainText = decrypt(cipherText, key)
    print(plainText)


# usage python cbc.py <e|d> inputFile outputFile keyFile [IVFile]
if __name__ == "__main__":
    enc, input, key, iv = readFiles(sys.argv)
    if enc:
        output = encrypt(input, key, iv)
    else:
        output = decrypt(input, key)
    
    writeFile(output, sys.argv)