from lib.rsa.src.helpers import Key, modExp 
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

def test():
    privKey = Key(12, 3233, d=413)
    pubKey = Key(12, 3233, e=17)
    m = b'hi'
    s = sign(m, privKey)
    v = validate(s, m, pubKey)
    assert v == True
