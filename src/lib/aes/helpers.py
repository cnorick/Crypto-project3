import random
from binascii import unhexlify
from sys import exit
from Crypto.Cipher import AES

'''
pads message to be a multiple of blocksize.
message is a byte array.
'''
def pad(message, blockSize):
    if (message is None) or (len(message) == 0):
        raise ValueError('message cannot be null or empty')
    if type(message) is not bytes:
        raise ValueError('message must be bytes')
    message = bytearray(message)
    paddingNeeded = blockSize - (len(message) % blockSize)

    paddedMessage = message[:]
    for i in range(paddingNeeded):
        paddedMessage.append(paddingNeeded)

    return bytes(paddedMessage)

'''
Unpads a message padded by calling pad().
message must be a byte array.
'''
def unpad(message):
    if type(message) is not bytes:
        raise ValueError('message must be a bytes')
    message = bytearray(message)
    numPadding = message[-1]
    return bytes(message[:-numPadding])

'''
Generates n pseudorandom bytes.
'''
def generateIV(n):
    if n < 1:
        raise ValueError('n must be greater than 0')
    return bytes(random.getrandbits(8) for _ in range(n))

'''
Divides message into chunks of size n. The last message may be shorter than n.
'''
def chunkMessage(message, n):
    return [message[i:i+n] for i in range(0, len(message), n)]

'''
bitwise XORs m1 and m2.
'''
def XOR(m1, m2):
    return bytes(a ^ b for a, b in zip(m1, m2))

'''
Fk is a pseudorandom function keyed on <key>. It takes message as input
and outputs its encrypted ciphertext if <encrypt> is true. Otherwise it
pushes the ciphertext back through the pseudorandom function and outputs the plaintext.
'''
def Fk(input, key, encrypt = True):
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    if encrypt:
        return bytes(cipher.encrypt(input))
    else:
        return bytes(cipher.decrypt(input))

'''
Creates n CTRs starting at IV and incrementing by one each time.
'''
def getCtrs(IV, n):
    if type(IV) is not bytes:
        raise ValueError('IV must be bytes')
    IVasInt = int.from_bytes(IV, 'big')
    return [i.to_bytes(len(IV), 'big') for i in range(IVasInt, IVasInt + n)]

'''
Reads from the input, key, the IV file (if it is provided), and whether to decrypt or encrypt
File order is <e|d> input output key [IV]
Returns the file contents as bytes converted from utf8.
Return order (encrypt, input, key, IV). IV is none if not provided. encrypt is boolean.
'''
def readFiles(argv):
    if len(argv) < 5:
        print('All parameters not specified')
        exit(1)
    if len(argv) > 6:
        print('Too many parameters specified')
        exit(1)

    if argv[1] == 'e':
        encrypt = True
    elif argv[1] == 'd':
        encrypt = False
    else:
        print('first argument must be e for encrypt or d for decrypt')
        exit(1)

    inputFileName = argv[2]
    keyFileName = argv[4]

    if len(argv) == 6:
        IVFileName = argv[5]
        with open(IVFileName, 'r') as f:
            iv = unhexlify(f.read())
    else:
        iv = None

    with open(inputFileName, 'rb') as f:
        input = f.read()

    with open(keyFileName, 'r') as f:
        key = unhexlify(f.read())

    return encrypt, input, key, iv 

'''
Writes message to the output file specified in argv.
Output file must be at argv[2].
'''
def writeFile(message, argv):
    if type(message) is not bytes:
        raise ValueError('message must be bytes')
    outputFileName = argv[3]
    with open(outputFileName, 'wb') as f:
        f.write(message)

'''
Test that unpad correctly reverses pad.
'''
def paddingTest():
    m = bytes('abcde', 'utf8')
    for i in range(1, 11):
        assert m == (unpad(pad(m, i)))