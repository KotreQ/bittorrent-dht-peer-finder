def bytes_xor(bytesA: bytes, bytesB: bytes) -> bytes:
    assert len(bytesA) == len(bytesB)
    return bytes([byteA ^ byteB for byteA, byteB in zip(bytesA, bytesB)])
