from curve import P256, INF, is_on_curve
from vss import split_secret, reconstruct_secret, generate_feldman_commitments, verify_share

def run_e2e_simulation():
    print("==================================================")
    print("  SIMULATION DE SÉCURITÉ E2E - P-256 / VSS FELDMAN")
    print("==================================================")

    # 1. Paramètres du système (Seuil t, et nombre de participants n)
    # Note : (P256.n - 1) % (t - 1) doit être égal à 0 pour respecter votre règle algébrique.
    # Pour P256.n, un seuil t = 3 donne (n-1) % 2 == 0 (car n est impair).
    t = 3
    n_participants = 5
    
    # Simuler un secret (ex: un entier représentant une clé privée valide < P256.n)
    secret_key = 0x123456789abcdef123456789abcdef
    print(f"[*] Secret initial (Clé privée) : {hex(secret_key)}")
    print(f"[*] Configuration : Seuil t = {t}, Participants n = {n_participants}")

    # 2. Le Dealer découpe le secret et génère les coefficients
    try:
        coeffs, shares = split_secret(secret_key, t, n_participants, P256.n)
        print("[+] Succès : Partage du secret effectué sans biais (RUSTSEC-2024-0398 mitigé).")
    except ValueError as e:
        print(f"[-] Erreur de paramètre : {e}")
        return

    # 3. Le Dealer génère les engagements publics de Feldman (C_j = a_j * G)
    commitments = generate_feldman_commitments(coeffs, P256, P256.G )
    print(f"[+] Succès : {len(commitments)} engagements publics Feldman générés.")

    # 4. Simulation de la vérification par les participants (Feldman VSS)
    print("\n[*] Étape de vérification individuelle des parts...")
    valid_shares = []
    
    for idx, share in enumerate(shares, start=1):
        x, y = share
        # Vérification de validité de courbe et de Feldman
        point_derived = (x, y) # Dans un système réel, on convertit x en point si besoin, ici share est (x, y)
        
        # Vérification cryptographique via Feldman
        is_valid = verify_share(share, commitments, P256, P256.G)
        
        if is_valid:
            print(f"    - Participant {idx} (x={x}) : Part VALIDÉE par Feldman VSS.")
            valid_shares.append(share)
        else:
            print(f"    - Participant {idx} (x={x}) : Part CORROMPUE ou invalide !")

    # 5. Simulation de la reconstruction du secret par t participants
    print("\n[*] Tentative de reconstruction du secret avec un sous-ensemble de t parts...")
    # On prend exactement t parts valides (ex: les 3 premières)
    subset = valid_shares[:t]
    
    reconstructed_secret = reconstruct_secret(subset, P256.n)
    print(f"[*] Secret reconstruit : {hex(reconstructed_secret)}")

    # 6. Assertion finale
    if reconstructed_secret == secret_key:
        print("\n[+] VALIDATION TOTALE : Le secret reconstruit correspond exactement à l'original !")
    else:
        print("\n[-] ÉCHEC : Le secret reconstruit ne correspond pas !")

    print("==================================================")

if __name__ == "__main__":
    run_e2e_simulation()