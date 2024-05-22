class KBucketError(Exception):
    pass


class KBucketSpaceError(KBucketError):
    pass


class IncorrectKBucketDistance(KBucketError):
    pass


class TooHighKBucketDistance(IncorrectKBucketDistance):
    pass


class TooLowKBucketDistance(IncorrectKBucketDistance):
    pass
