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
