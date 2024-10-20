from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def main():
    # ----- KEY GENERATION ----- 
    # select p, q (both prime, p != q)
    p = number.getPrime(2048)
    print("p is: ", p)
    q = number.getPrime(2048)
    print("q is: ", q)
    # calculate n = p * q
    n = p * q
    # calculate phi(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    # select integer e
    e = 65537
    # calculate d: de % phi(n) = 1
    # d = int(1 / (e % phi_n))
    d = number.inverse(e, phi_n)
    print("d is: ", d)
    # public key (PU = {e, n})
    public = {e, n}
    # private key (PR = {d, n})
    private = {d, n}

    # ----- ENCRYPTION -----
    message = get_random_bytes(16)
    print(f"message {message}")

    iv = get_random_bytes(16)

    bob_cipher = AES.new(message, AES.MODE_CBC, iv)
    # message_hex = ''.join([hex(ord(char))[2:] for char in message])
    message_hex = message.hex()
    message_int = int(message_hex, 16)
    print("my message in hex: ", message_int)
    assert message_int < n

    # generate ciphertext (C = M^e (mod n))
    ciphertext = pow(message_int, e, n)
    print("ciphertext: ", ciphertext)

    # decrypt ciphertext (M = C^d (mod n))
    plaintext_int = pow(ciphertext, d, n)
    print("plaintext int: ", plaintext_int)

    plaintext_hex = hex(plaintext_int)[2:]
    plaintext_ascii_bytes = bytes.fromhex(plaintext_hex)

    alice_ciper = AES.new(plaintext_ascii_bytes, AES.MODE_CBC, iv)
    print(f"alcie {plaintext_ascii_bytes}")

    assert message == plaintext_ascii_bytes

    example = b'hello from space'
    ciphered = alice_ciper.encrypt(example)

    example2 = bob_cipher.decrypt(ciphered)

    assert example == example2

    print("plaintext string: ", plaintext_ascii_bytes)


if __name__ == "__main__":
    main()
