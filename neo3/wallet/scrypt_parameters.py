class ScryptParameters(object):

    def __init__(self,
                 n: int = 16384,
                 r: int = 8,
                 p: int = 8):

        self.n = n
        self.r = r
        self.p = p
