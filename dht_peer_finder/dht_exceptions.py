class KBucketError(Exception):
    pass


class KBucketSpaceError(KBucketError):
    pass


class IncorrectKBucketDistanceError(KBucketError):
    pass


class TooHighKBucketDistanceError(IncorrectKBucketDistanceError):
    pass


class TooLowKBucketDistanceError(IncorrectKBucketDistanceError):
    pass


class KRPCPacketError(Exception):
    pass


class InvalidKRPCPacket(KRPCPacketError):
    pass


class InvalidKRPCEncodedData(KRPCPacketError):
    pass


class KRPCRequestError(Exception):
    pass
