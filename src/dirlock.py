from Crypto.Hash import SHA256 as SHA
from rsaSign import validate, generateThumbprint, createCert, signToFile
from lib.rsa.helpers import Key
import random
import os
import lib.rsa.rsa as rsa
import lib.aes.cbc as cbc
import cbcmac as mac
import sys

skmFilename = 'symmetric_key_manifest'

class IntegrityError(Exception):
    pass

def getRandomAESKey():
    '''
    Returns random 256-bit key.
    '''
    numBits = 256
    return random.getrandbits(numBits)

def aesKeyToBytes(key):
    '''
    Turns an integer aes key into a bytes object.
    '''
    if type(key) is not int:
        raise TypeError('key must be of type int')
    return key.to_bytes((key.bit_length() + 7) // 8, 'big')

def encryptFile(filename, key):
    '''
    Overwrites filename with its aes-cbc encryption using key as the aes key.
    Returns the encrypted file contents.
    '''
    with open(filename, 'rb') as file:
        content = file.read()
    
    # If file is empty, skip it; there is nothing to encrypt.
    if not content:
        return

    encryptedContent = cbc.encrypt(content, key)

    with open(filename, 'wb') as file:
        file.write(encryptedContent)
    
    return encryptedContent

def decryptFile(filename, key):
    ''' 
    Overwrites filename with its aes-cbc decryption using key as the aes key.
    ''' 
    with open(filename, 'rb') as file:
        encryptedContent = file.read()
    
    # If file is empty, skip it; there is nothing to decrypt.
    if not encryptedContent:
        return

    content = cbc.decrypt(encryptedContent, key)

    with open(filename, 'wb') as file:
        file.write(content)


def lock(directory, unlockPubKey, lockPrivKey, unlockSig, validatingKey):
    '''
    Encrypts all the files in directory using a random aes key. The aes key
    is encrypted with the unlocking party's public key and stored in symmetric_key_manifest.
    All the files are tagged using cbc-mac and the aes key.
    '''
    # Verify unlocker's public key integrity.
    thumbprint = generateThumbprint(unlockPubKey)
    if not validate(unlockSig, thumbprint, validatingKey):
        raise IntegrityError('Unable to validate the integrity of the unlocking party’s public key information')

    # Get random AES key.
    aesKey = getRandomAESKey()

    # Create symmetric key manifest and signature for that file.
    encryptedAesKey = str(rsa.enc(aesKey, unlockPubKey))
    with open(skmFilename, 'w') as skm:
        skm.write(encryptedAesKey)
    signToFile(bytes(encryptedAesKey, 'utf-8'), lockPrivKey, skmFilename + '_sig')

    files = os.listdir(directory)
    for file in files:
        # Encrypt all files in directory.
        encryptedContent = encryptFile(directory + '/' + file, aesKeyToBytes(aesKey))

        # Create Macs for each of the encrypted files.
        tag = mac.tag(encryptedContent, aesKeyToBytes(aesKey))
        with open(directory + '/' + file + '_tag', 'wb') as tagFile:
            tagFile.write(tag)

def unlock(directory, lockPubKey, unlockPrivKey, lockSig, validatingKey):
    '''
    Decrypts all the files in directory that were previously encrypted using lock.
    '''
    # Verify locker's public key.
    thumbprint = generateThumbprint(lockPubKey)
    if not validate(lockSig, thumbprint, validatingKey):
        raise IntegrityError('Unable to validate the integrity of the locking party’s public key information')
    
    # Verify the integrity of the symmetric key manifest.
    with open(skmFilename, 'r') as file:
        skm = file.read()
    with open(skmFilename + '_sig', 'r') as file:
        skmSig = file.read()
    if not validate(int(skmSig), bytes(skm, 'utf-8'), lockPubKey):
        raise IntegrityError('Unable to validate the integrity of the symmetric key manifest')

    # Get AES key from skm.
    aesKey = rsa.dec(int(skm), unlockPrivKey)

    files = os.listdir(directory)
    for file in files:
        if file[-4:] == '_tag':
            continue
        # Verify the integrity of the encrypted files.
        tagFilename = directory + '/' + file + '_tag'
        with open(tagFilename, 'rb') as tagFile:
            tag = tagFile.read()
        with open(directory + '/' + file, 'rb') as f:
            content = f.read()
        if not mac.validate(content, tag, aesKeyToBytes(aesKey)):
            raise IntegrityError('Unable to validate the integrity of file: {}'.format(file))
        os.remove(tagFilename)

        # Decrypt encrypted files.
        decryptFile(directory + '/' + file, aesKeyToBytes(aesKey))

    # Delete manifest
    os.remove(skmFilename)
    os.remove(skmFilename + '_sig')

def test():
    (sPubKey, sPrivKey, _) = createCert(numBits = 516)
    (lPubKey, lPrivKey, lSig) = createCert(signer = sPrivKey, numBits = 516) # 516 to fit the 256 bit aes key.
    (uPubKey, uPrivKey, uSig) = createCert(numBits = 516, signer=sPrivKey)

    lock('../test/foo/', uPubKey, lPrivKey, uSig, sPubKey)
    unlock('../test/foo/', lPubKey, uPrivKey, lSig, sPubKey)

if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("usage: python dirlock.py l | u directory actionPublicKey actionPrivateKey validatingPublicKey")
        sys.exit()

    (mode, directory, actPubKeyFile, actPrivKeyFile, valPubKeyFile) = sys.argv[1:]
    
    with open(actPubKeyFile, 'r') as file:
        (numBits, N, e) = [int(line) for line in file.readlines()]
        actPubKey = Key(numBits, N, e=e)
    with open(actPrivKeyFile, 'r') as file:
        (numBits, N, d) = [int(line) for line in file.readlines()]
        actPrivKey = Key(numBits, N, d=d)
    with open(valPubKeyFile, 'r') as file:
        (numBits, N, e) = [int(line) for line in file.readlines()]
        valPubKey = Key(numBits, N, e=e)

    actPubKeySigFile = actPubKeyFile + '-casig'
    with open(actPubKeySigFile, 'r') as file:
        actPubKeySig = int(file.read())

    if mode == 'l':
        lock(directory, actPubKey, actPrivKey, actPubKeySig, valPubKey)
    else:
        unlock(directory, actPubKey, actPrivKey, actPubKeySig, valPubKey)
