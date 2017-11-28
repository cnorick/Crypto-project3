import lib.aes.cbc as cbc

def cbcmacTag(message, key):
    '''
    Generates a tag for the message using cbc-mac.
    '''
    if type(message) is not bytes:
        raise TypeError('message must be of type bytes')

    length = len(message)

    # Prepend length to message, making sure the length is one block.
    message = length.to_bytes(cbc.blockSize, byteorder="big") + message

    # Just use encrypt with IV=0.
    return cbc.encrypt(message, key, (0).to_bytes(cbc.blockSize, "big"))

def cbcmacValidate(message, tag, key):
    '''
    Checks that tag is a valid cbc-mac tag for the message.
    '''
    return tag == cbcmacTag(message, key)

def test():
    m = b'hello'
    key = 'asdfalsdkfjasldkfjaddsfasdfahsdfhasdfh'
    tag = cbcmacTag(m, key)
    v = cbcmacValidate(m, tag, key)
    assert v
