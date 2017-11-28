import lib.aes.src.cbc as cbc

def cbcmacTag(message, key):
    if type(message) is not bytes:
        raise TypeError('message must be of type bytes')

    length = len(message)

    # Prepend length to message, making sure the length is one block.
    message = length.to_bytes(cbc.blockSize, byteorder="big") + message

    # Just use encrypt with IV=0.
    return cbc.encrypt(message, key, (0).to_bytes(cbc.blockSize, "big"))

def cbcmacValidate(message, tag, key):
    return tag == cbcmacTag(message, key)

def test():
    m = b'hello'
    key = 'asdfalsdkfjasldkfjaddsfasdfahsdfhasdfh'
    tag = cbcmacTag(m, key)
    v = cbcmacValidate(m, tag, key)
    assert v
