import secrets

INF = None  # Represents the point at infinity

class Curve:
    def __init__(self, name, p, a, b, G, n):
        self.name = name
        self.p = p      # Field characteristic
        self.a = a      # Curve parameter a (-3 for P-256)
        self.b = b      # Curve parameter b
        self.G = G      # Generator point (x, y)
        self.n = n      # Order of generator G

# P-256 Standard Parameters
P256 = Curve(
    name="P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    G=(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
       0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)

def is_on_curve(C, point):
    """
    Vérifie si un point (x, y) appartient bien à la courbe elliptique C
    et n'est pas le point à l'infini (INF).
    Équation : y^2 = x^3 + a*x + b (mod p)
    """
    if point is INF:
        return False
    x, y = point
    left = (y * y) % C.p
    right = (x**3 + C.a * x + C.b) % C.p
    return left == right

def add(C, P, Q):
    """Adds two points P and Q on the elliptic curve C."""
    if P is INF: return Q
    if Q is INF: return P
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and (y1 + y2) % C.p == 0:
        return INF
        
    if P == Q:
        lam = (3 * x1 * x1 + C.a) * pow(2 * y1, -1, C.p) % C.p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, C.p) % C.p
        
    x3 = (lam * lam - x1 - x2) % C.p
    y3 = (lam * (x1 - x3) - y1) % C.p
    return (x3, y3)

def mul(C, k, P):
    """Scalar multiplication k * P using double-and-add."""
    k %= C.n
    R = INF
    while k:
        if k & 1:
            R = add(C, R, P)
        P = add(C, P, P)
        k >>= 1
    return R