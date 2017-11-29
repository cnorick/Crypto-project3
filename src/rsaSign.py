from lib.rsa.helpers import Key, modExp 
from Crypto.Hash import SHA256 as SHA

def hash(message, key):
    '''
    Hashes message to an element in ZN*.
    '''
    if type(message) is not bytes:
        raise TypeError('message must be of type bytes')
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    
    h = SHA.new(message).digest()
    h = int.from_bytes(h, byteorder="big")
    return h % key.N

def sign(message, key):
    '''
    Creates an RSA signature for message using key.
    '''
    if type(message) is not bytes:
        raise TypeError('message must be of type bytes')
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    
    # return H(m)^d modN
    return modExp(hash(message, key), key)

def validate(sig, message, key):
    '''
    Validates that sig is a valid signature for message.
    '''
    if type(message) is not bytes:
        raise TypeError('message must be of type bytes')
    if type(sig) is not int:
        raise TypeError('sig must be of type int')
    if type(key) is not Key:
        raise TypeError('key must be of type Key')

    # s^e = H(m)modN
    return modExp(sig, key) == hash(message, key)

def signFromFileToFile(messageFile, keyFile, outFile):
    '''
    Pulls the key and message from the specified files and writes the signature to outFile.
    '''
    with open(messageFile, 'r') as file:
        message = bytes(file.read(), 'utf-8')

    with open(keyFile, 'r') as file:
        (numBits, N, d) = [int(line) for line in file.readlines()]
        key = Key(numBits, N, d=d)

    with open(outFile, 'w') as out:
        out.write(str(sign(message, key)))

def test():
    privKey = Key(12, 3233, d=413)
    pubKey = Key(12, 3233, e=17)
    m = b'hi'
    s = sign(m, privKey)
    v = validate(s, m, pubKey)
    assert v == True

signFromFileToFile('../test/message','../test/privkey', '../test/out')