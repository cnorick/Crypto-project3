import sys
from helpers import Key, addRandom, removeRandom, modExp, getPrime, modInverse
from fractions import gcd

def enc(m, key):
    '''
    encrypts <m> with public key <key> to element in ZN*.
    m must not exceed key.n / 2 - 2 bits.
    '''
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    if type(m) is not int:
        raise TypeError('m must be of type int')
    
    # mhat is an element in ZN*.
    mhat = addRandom(m, key)

    return modExp(mhat, key)

def dec(c, key):
    '''
    decrypts <c> with private key <key>.
    '''
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    if type(c) is not int:
        raise TypeError('m must be of type int')

    mhat = modExp(c, key)

    return removeRandom(mhat, key)

def keygen(n):
    '''
    Creates a valid Key object that can be used with enc/dec.
    '''
    # Try 10 times to find p and q that are different.
    for i in range(10):
        p = getPrime(n)
        q = getPrime(n)

        if p != q:
            break;
    else:
        raise Exception('could not produce 2 unique primes after 10 tries.')

    N = p * q
    order = (p - 1) * (q - 1)

    # e will be set to one of the first 8 primes. If none of these are coprime with order, then stop execution.
    smallPrimes = [3, 5, 7, 11, 13, 17, 19, 23]
    for e in smallPrimes:
        if gcd(e, order) == 1:
            break;
    else:
        raise Exception('could not a small number coprime to {}.'.format(order))

    d = modInverse(e, order)
    
    return Key(n, N, e=e, d=d)

def test():
    '''
    Tests enc and dec for the given keys.
    '''
    N = 3233
    numBits = 12
    for message in range(2**(numBits - numBits // 2 - 2)):
        privKey = Key(numBits, N, e=413)
        pubKey = Key(numBits, N, d=17)
        e = enc(message, pubKey)
        d = dec(e, privKey)
        if d != message:
            print('d: {d}, message: {message}'.format(d=d, message=message))
            raise Exception("IT'S BROKEN")

def testKeyGen():
    '''
    Tests keygen, enc, and dec for all n-bit messages for n up to 24.
    '''
    for numBits in range(3, 25):
        for message in range(1, 2**(numBits - numBits // 2 - 2) - 1):
            for i in range(1):
                k = keygen(numBits)
                print('numBits {}, message: {}, k.d: {}, k.e: {}, k.N: {}'.format(numBits, message, k.d, k.e, k.N))

                # Ensure that e and d are inverses of each other mod N.
                assert pow(message, k.e * k.d, k.N) == message

                privKey = Key(k.numBits, k.N, d=k.d)
                pubKey = Key(k.numBits, k.N, e=k.e)

                e = enc(message, pubKey)
                d = dec(e, privKey)
                if d != message:
                    print('numBits {}, d: {}, message: {}, k.d: {}, k.e: {}, k.N: {}'.format(numBits, d, message, k.d, k.e, k.N))
                    raise Exception("IT'S BROKEN")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("usage: python rsa.py e | d keyFile inputFile outputFile\n\
       python rsa.py k publicKeyFile secretKeyFile numBits")
        sys.exit()
    
    mode = sys.argv[1]
    if mode == 'k':
        (publicFileName, secretFileName, numBits) = sys.argv[2:5]

        key = keygen(int(numBits))

        with open(publicFileName, 'w') as publicFile:
            publicFile.write(str(key.numBits) + '\n')
            publicFile.write(str(key.N) + '\n')
            publicFile.write(str(key.e) + '\n')

        with open(secretFileName, 'w') as secretFile:
            secretFile.write(str(key.numBits) + '\n')
            secretFile.write(str(key.N) + '\n')
            secretFile.write(str(key.d) + '\n')
        
    else:
        (keyFileName, inputFileName, outputFileName) = sys.argv[2:5]

        with open(keyFileName, 'r') as keyFile:
            (numBits, N, ed) = [int(line) for line in keyFile.readlines()]

        with open(inputFileName, 'r') as inputFile:
            message = int(inputFile.read())

        if mode == 'e': # encryption
            output = str(enc(message, Key(numBits, N, e=ed)))
        elif mode == 'd': # decryption
            output = str(dec(message, Key(numBits, N, d=ed)))
        else:
            raise ValueError("mode must be e (encrypt), d (decrypt), or k (keygen)")
        
        with open(outputFileName, 'w') as outputFile:
            outputFile.write(output)