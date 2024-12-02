import random
from sympy import mod_inverse, isprime, primitive_root


def generate_keys(prime):
    """
    Generate ElGamal keys.
    :param prime: A prime number `p`.
    :return: (public_key, private_key)
    """
    if not isprime(prime):
        raise ValueError("p must be a prime number.")

    g = primitive_root(prime)  # Choose primitive root `g`
    d = random.randint(1, prime - 2)  # Private key (1 ≤ d ≤ p - 2)
    e2 = pow(g, d, prime)  # Public key component

    public_key = (g, e2, prime)
    private_key = d
    return public_key, private_key


def sign_message(message, private_key, public_key):
    """
    Sign a message.
    :param message: The message to be signed (integer).
    :param private_key: Alice's private key `d`.
    :param public_key: Alice's public key `(g, e2, p)`.
    :return: (S1, S2) - the signature.
    """
    g, _, p = public_key
    d = private_key

    # Choose random `r` such that gcd(r, p-1) = 1
    r = random.randint(1, p - 2)
    while gcd(r, p - 1) != 1:
        r = random.randint(1, p - 2)

    S1 = pow(g, r, p)  # S1 = g^r mod p
    r_inv = mod_inverse(r, p - 1)  # r^-1 mod (p-1)
    S2 = (r_inv * (message - d * S1)) % (p - 1)  # S2 = (M - d*S1)*r^-1 mod (p-1)

    return S1, S2


def verify_signature(message, signature, public_key):
    """
    Verify a signature.
    :param message: The message to verify (integer).
    :param signature: The signature (S1, S2).
    :param public_key: Alice's public key `(g, e2, p)`.
    :return: True if valid, False otherwise.
    """
    g, e2, p = public_key
    S1, S2 = signature

    # Check bounds
    if not (0 < S1 < p and 0 < S2 < p - 1):
        return False

    # Compute verification components
    V1 = pow(g, message, p)  # V1 = g^M mod p
    V2 = (pow(e2, S1, p) * pow(S1, S2, p)) % p  # V2 = e2^S1 * S1^S2 mod p

    return V1 == V2


def gcd(a, b):
    """Compute the greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


# Main Execution
if __name__ == "__main__":
    print("=== ElGamal Digital Signature Scheme ===")

    # Alice's Key Generation
    p = int(input("Alice: Enter a prime number (p): "))
    public_key, private_key = generate_keys(p)
    print("\nAlice's Public Key:", public_key)
    print("Alice's Private Key:", private_key)

    # Alice signs a message
    M = int(input("\nAlice: Enter the message to be signed (integer M): "))
    signature = sign_message(M, private_key, public_key)
    print("Alice's Signature (S1, S2):", signature)

    # Alice sends M, S1, S2 to Bob
    print("\nAlice sends the following to Bob:")
    print("Message:", M)
    print("Signature:", signature)

    # Bob verifies the signature
    print("\n=== Bob's Verification Process ===")
    received_message = int(input("Bob: Enter the received message (integer): "))
    received_S1 = int(input("Bob: Enter the received S1: "))
    received_S2 = int(input("Bob: Enter the received S2: "))
    received_signature = (received_S1, received_S2)

    is_valid = verify_signature(received_message, received_signature, public_key)
    print("\nBob's Verification Result:", "Valid Signature" if is_valid else "Invalid Signature")
