from curve import P256, mul, INF
from cryptography.hazmat.primitives.asymmetric import ec

from vss import split_secret, reconstruct_secret
from curve import P256

secret_test = 424242424242
t_seuil = 3      # Il faut au moins 3 parts
n_parts = 5      # Sur 5 parts distribuées

# 1. Partage
coeffs, all_shares = split_secret(secret_test, t_seuil, n_parts, P256.n)
print(f"Secret original : {secret_test}")
print(f"Parts générées  : {all_shares}")

# 2. Reconstruction avec un sous-ensemble valide (ex: 3 parts prises au hasard parmi les 5)
subset_shares = [all_shares[0], all_shares[2], all_shares[4]] # Parts 1, 3 et 5
recovered_secret = reconstruct_secret(subset_shares, P256.n)
print(f"Secret reconstruit : {recovered_secret}")

assert recovered_secret == secret_test
print("[+] Succès : Le secret a été parfaitement reconstruit !")


"""def run_checks():
    print("==================================================")
    print("  LANCEMENT DES VALIDATIONS - COURBE P-256 (curve.py)")
    print("==================================================")

    print("[*] Test 1 : Vérification de l'ordre n du générateur (n * G = INF)...")
    n_G = mul(P256, P256.n, P256.G)

    if n_G == INF:
        print("[+] Succès : n * G donne bien le point à l'infini (INF).")
    else:
        print(f"[-] Échec : n * G ne donne pas INF. Résultat : {n_G!r}")

    print("\n[*] Test 2 : Comparaison de d * G avec la bibliothèque cryptography...")
    d_test = 123456789789456123

    my_pub_point = mul(P256, d_test, P256.G)
    print(f"[DEBUG] my_pub_point retourné = {my_pub_point!r}")

    try:
        private_key = ec.derive_private_key(d_test, ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        expected_pub = (numbers.x, numbers.y)
    except ValueError as exc:
        print(f"[-] Scalaire de test invalide : {exc}")
        return

    if my_pub_point == INF:
        print("[-] Erreur : la multiplication a renvoyé le point à l'infini.")
    elif (
        isinstance(my_pub_point, (tuple, list))
        and len(my_pub_point) == 2
        and tuple(my_pub_point) == expected_pub
    ):
        print("[+] Succès : le point d * G correspond à cryptography.")
        print(f"    - Coordonnée X : {hex(my_pub_point[0])}")
        print(f"    - Coordonnée Y : {hex(my_pub_point[1])}")
    else:
        print("[-] Échec : les résultats ne correspondent pas.")
        print(f"    - Attendu : {expected_pub}")
        print(f"    - Obtenu  : {my_pub_point!r}")

    print("\n==================================================")


if __name__ == "__main__":
    #run_checks()"""
