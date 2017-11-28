import sys
from Crypto.Cipher import AES
from multiprocessing.dummy import Pool as ThreadPool 
from helpers import generateIV, chunkMessage, XOR, getCtrs, Fk, readFiles, writeFile


blockSize = 16 # bytes

'''
Ecncrypts message with key using ctr mode.
If IV is specified, it is used as the initial IV. Otherwise, one is generated randomly.
'''
def encrypt(message, key, IV = None):
    if (message is None) or (len(message) == 0):
        raise ValueError('message cannot be null or empty')
    if IV is None:
        IV = generateIV(blockSize)
    blocks = chunkMessage(message, blockSize)
    ctrs = getCtrs(IV, len(blocks))

    cipherText = bytes(IV)

    with ThreadPool(4) as pool:
        cipherText += b''.join(pool.map(lambda x: encryptBlock(x[0], x[1], key), zip(blocks, ctrs)))
    
    return cipherText

'''
encrypts a single block given the correct counter for that block and the key.
'''
def encryptBlock(block, ctr, key):
    return XOR(block, Fk(ctr, key, True))

'''
Decrypts messages that were encrypted using ctr.
'''
def decrypt(cipherText, key):
    if (cipherText is None) or (len(cipherText) == 0):
        raise ValueError('cipherText cannot be null or empty')

    IV, *blocks = chunkMessage(cipherText, blockSize)
    ctrs = getCtrs(IV, len(blocks))
    
    plainText = bytes()

    with ThreadPool(4) as pool:
        plainText = b''.join(pool.map(lambda x: decryptBlock(x[0], x[1], key), zip(blocks, ctrs)))

    return plainText

'''
decrypts a single block given the correct counter and key.
'''
def decryptBlock(block, ctr, key):
    # encrypt set to True because it's going forward through the cipher.
    return XOR(block, Fk(ctr, key, True))
    
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