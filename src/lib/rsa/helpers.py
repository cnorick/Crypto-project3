from Crypto.Util import number
from random import getrandbits, randrange
from fractions import gcd

class Key (object):
    '''
    Object to hold keys. To use with enc/dec, only one of e and d may be specified.
    '''
    def __init__(self, numBits, N, e=None, d=None):
        if type(numBits) is not int:
            raise TypeError('numBits must be of type int. got type {}'.format(type(numBits)))
        if numBits <= 0:
            raise ValueError('numBits must be positive. got value {}'.format(numBits))
        if type(N) is not int:
            raise TypeError('N must be of type int. got type {}'.format(type(N)))

        self.numBits = numBits
        self.N = N
        self.e = e
        self.d = d

def getRandom(r):
    '''
    Returns random int with r bits.
    '''
    return getrandbits(r)

def addRandom(m, key):
    '''
    Adds randomness to the m and returns r||m of total bit length key.numBits.
    Randomness is half of the total length.
    '''
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    if type(m) is not int:
        raise TypeError('m must be of type int')

    numRandBits = key.numBits // 2
    numMessageBits = key.numBits - numRandBits - 2
    r = getRandom(numRandBits)

    # Concat the randomness and the message.
    return (r << numMessageBits) | m

def removeRandom(m, key):
    '''
    Removes the randomness added to m by addRandom().
    '''
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    if type(m) is not int:
        raise TypeError('m must be of type int')

    numRandBits = key.numBits // 2
    numMessageBits = key.numBits - numRandBits - 2

    # Remove the randomness from the message.
    return ((2 ** numMessageBits) - 1) & m

def modExp(m, key):
    '''
    Performs modular exponentiation using right-to-left binary method.
    Calculates [m^(key.ed) mod key.N].
    Only one of key.e and key.d may be specified.
    '''
    if type(key) is not Key:
        raise TypeError('key must be of type Key')
    if type(m) is not int:
        raise TypeError('m must be of type int')
    if key.e != None and key.d != None:
        raise ValueError('it is ambiguous whether key is private or public')

    ed = key.e if key.e != None else key.d
    if key.N == 1:
        return 0
    
    result = 1
    m %= key.N
    while ed > 0:
        if ed & 1: # If ed is odd...
           result = (result * m) % key.N
        ed = ed >> 1
        m = (m ** 2) % key.N
    return result

def getPrime(n):
    '''
    Returns a random n-bit prime number.
    '''
    if type(n) is not int:
        raise TypeError('n must be of type int. Got value {}'.format(type(n)))
    if n < 0:
        raise ValueError('n must be positive. Got value {}'.format(n))

    r = getRandom(n)
    while not isProbablePrime(r):
        r = getRandom(n)

    return r

def egcd(a, b):
    '''
    Extended Euclidean Algorithm
    return (g, x, y) a*x + b*y = gcd(x, y)
    '''
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modInverse(a, N):
    '''
    Returns the multiplicative inverse of a mod N.
    '''
    g, x, y = egcd(a, N)
    if g != 1:
        raise Exception('No modular inverse')
    return x%N

numBases = 40 # number of bases to try
def isProbablePrime(n):
    """
    Miller-Rabin primality test.
    False means composite, True means probably prime.
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # write n-1 as 2^r * d.
    r = 0
    d = n-1
    while True:
        quo, rem = divmod(d, 2)
        if rem == 1:
            break
        r += 1
        d = quo

    # test whether the base a is a witness for the compositeness of n.
    def tryComposite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(r):
            if pow(a, 2**i * d, n) == n - 1:
                return False
        return True # n is definitely composite

    for i in range(numBases):
        a = randrange(2, n)
        if tryComposite(a):
            return False
 
    return True # no base tested showed n as composite
