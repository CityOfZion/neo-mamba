class ScryptParameters(object):

    def __init__(self,
                 n: int = 16384,
                 r: int = 8,
                 p: int = 8,
                 length: int = 64):

        self.n = n
        self.r = r
        self.p = p
        self.length = length
