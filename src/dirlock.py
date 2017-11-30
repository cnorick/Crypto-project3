from Crypto.Hash import SHA256 as SHA
from rsaSign import validate, generateThumbprint, createCert, signToFile
import random
import os
import lib.rsa.rsa as rsa
import lib.aes.cbc as cbc

skmFilename = 'symmetric_key_manifest'

def getRandomAESKey():
    '''
    Returns random 256-bit key.
    '''
    numBits = 256
    return random.getrandbits(numBits)

def encryptFile(filename, key):
    '''
    Overwrites filename with its aes-cbc encryption using key as the aes key.
    '''
    with open(filename, 'r') as file:
        content = file.read()
    
    # If file is empty, skip it; there is nothing to encrypt.
    if not content:
        return

    encryptedContent = cbc.encrypt(bytes(content, 'utf-8'), key)

    with open(filename, 'wb') as file:
        file.write(encryptedContent)

def lock(directory, unlockPubKey, lockPrivKey, unlockSig):
    # Verify unlocker's public key integrity.
    thumbprint = generateThumbprint(unlockPubKey)
    if not validate(unlockSig, thumbprint, unlockPubKey):
        raise Exception('Unable to validate the integrity of the unlocking party’s public key information')

    # Get random AES key.
    aesKey = getRandomAESKey()

    # Create symmetric key manifest and signature for that file.
    encryptedAesKey = str(rsa.enc(aesKey, unlockPubKey))
    with open(skmFilename, 'w') as skm:
        skm.write(encryptedAesKey)
    signToFile(bytes(encryptedAesKey, 'utf-8'), lockPrivKey, skmFilename + '_sig')

    # Encrypt all files in directory.
    files = os.listdir(directory)
    for file in files:
        encryptFile(directory + '/' + file, aesKey.to_bytes((aesKey.bit_length() + 7) // 8, 'big'))

    # TODO: Create Macs for each of the encrypted files.

(lPubKey, lPrivKey, lSig) = createCert()
(uPubKey, uPrivKey, uSig) = createCert()

lock('../test/foo/', uPubKey, lPrivKey, uSig)
