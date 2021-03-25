class ScryptParameters:

    @staticmethod
    def default():
        return ScryptParameters(16384, 8, 8)

    def __init__(self, n, r, p):
        self.n = n
        self.r = r
        self.p = p
