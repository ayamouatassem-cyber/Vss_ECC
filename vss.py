import secrets
from curve import P256, mul, add, INF

def eval_poly(coeffs, x, prime):
    """Évalue un polynôme de coefficients donnés en un point x modulo prime."""
    res = 0
    for coeff in reversed(coeffs):
        res = (res * x + coeff) % prime
    return res

def split_secret(secret, t, n_participants, prime):
    """
    Divise un secret en n_participants parts avec un seuil t.
    - secret : l'entier à cacher (ex: une clé privée)
    - t : le seuil minimal de parts requises pour reconstruire
    - n_participants : le nombre total de parts créées
    - prime : le modulo de corps (ex: P256.n)
    """
    

    if t > n_participants:
        raise ValueError("Le seuil (t) ne peut pas dépasser le nombre total de participants.")

    if (prime - 1) % (t - 1) != 0:
        raise ValueError("Paramètre de seuil invalide : (n - 1) mod (k - 1) doit être égal à 0.")
    
    # 1. Génération des coefficients du polynôme (le terme constant a_0 = secret)
    coeffs = [secret] + [secrets.randbelow(prime) for _ in range(t - 1)]
    
    # 2. Génération des parts (x, y = f(x)) pour chaque participant
    shares = []
    for i in range(1, n_participants + 1):
        x = i
        y = eval_poly(coeffs, x, prime)
        shares.append((x, y))
        
    return coeffs, shares

def lagrange_interpolate(x, points, prime):
    """
    Interpole le polynôme de Lagrange en un point x (généralement x=0 pour le secret)
    à partir d'un sous-ensemble de points (parts).
    """
    k = len(points)
    x_s = [p[0] for p in points]
    y_s = [p[1] for p in points]
    
    acc = 0
    for i in range(k):
        numerator, denominator = 1, 1
        for j in range(k):
            if i != j:
                numerator = (numerator * (x - x_s[j])) % prime
                denominator = (denominator * (x_s[i] - x_s[j])) % prime
        
        # Calcul du polynôme de base de Lagrange L_i(x) modulo prime
        lagrange_basis = (numerator * pow(denominator, -1, prime)) % prime
        term = (y_s[i] * lagrange_basis) % prime
        acc = (acc + term) % prime
        
    return acc

def reconstruct_secret(shares, prime):
    """Reconstruit le secret original f(0) à partir de t parts valides."""
    return lagrange_interpolate(0, shares, prime)

def generate_feldman_commitments(coeffs, C, G):
    """
    Génère les engagements publics de Feldman : C_j = a_j * G
    pour chaque coefficient du polynôme.
    """
    return [mul(C, coeff, G) for coeff in coeffs]

def verify_share(share, commitments, C, G):
    """
    Vérifie qu'une part (x, y) est valide par rapport aux engagements publics de Feldman.
    Vérification : y * G == Somme( x^j * C_j )
    """
    x, y = share
    
    # 1. Côté gauche : y * G
    left_side = mul(C, y, G)
    
    # 2. Côté droit : Somme des (x^j * C_j) pour j de 0 à t-1
    right_side = INF
    x_pow = 1
    for commitment in commitments:
        term = mul(C, x_pow, commitment)
        right_side = add(C, right_side, term)
        x_pow = (x_pow * x) % C.n
        
    return left_side == right_side