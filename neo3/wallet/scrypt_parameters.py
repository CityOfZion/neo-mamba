class ScryptParameters(object):

    instance = None

    @staticmethod
    def default():
        if ScryptParameters.instance is None:
            ScryptParameters.instance = ScryptParameters(16384, 8, 8, 64)
        return ScryptParameters.instance

    def __init__(self, n, r, p, length):
        self.n = n
        self.r = r
        self.p = p
        self.length = length
