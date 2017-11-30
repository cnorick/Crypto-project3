import lib.aes.cbc as cbc

def tag(message, key):
    '''
    Generates a tag for the message using cbc-mac and key as aes key.
    '''
    if type(message) is not bytes:
        raise TypeError('message must be of type bytes')

    length = len(message)

    # Prepend length to message, making sure the length is one block.
    message = length.to_bytes(cbc.blockSize, byteorder="big") + message

    # Just use encrypt with IV=0.
    return cbc.encrypt(message, key, (0).to_bytes(cbc.blockSize, "big"))

def validate(message, t, key):
    '''
    Checks that t is a valid cbc-mac tag for the message.
    '''
    return t == tag(message, key)

def test():
    m = b'hello'
    key = 'asdfalsdkfjasldkfjaddsfasdfahsdfhasdfh'
    tag = tag(m, key)
    v = validate(m, tag, key)
    assert v
