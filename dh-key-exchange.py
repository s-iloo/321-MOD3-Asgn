from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

q = bytes.fromhex(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838E"
    "F1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5"
    "644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
)

a = bytes.fromhex(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E6"
    "90F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A"
    "091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
)


class DiffieHellman:
    def __init__(self, q, a):
        self.q = q
        self.a = a

    def gen_random_private(self):
        return randint(1, self.q - 1)

    def gen_public(self, a, x, q):
        return pow(a, x, q)


def main():
    # length of the global public elements should be 128 bytes (1024 bits) 
    assert len(a) == 128
    assert len(q) == 128

    # converting global public elements into integers
    q_int = int.from_bytes(q, byteorder='big')
    a_int = int.from_bytes(a, byteorder='big')

    # creating diffie_hellman objects for alice and bob with global public elements
    alice = DiffieHellman(q_int, a_int)
    bob = DiffieHellman(q_int, a_int)

    # generating alices private and public keys
    alice_private = alice.gen_random_private()
    alice_public = alice.gen_public(a_int, alice_private, q_int)
    print("alice public: ", alice_public)

    # generating bobs private and public keys
    bob_private = bob.gen_random_private()
    bob_public = bob.gen_public(a_int, bob_private, q_int)
    print("bob public: ", bob_public)

    # alice uses bobs public key and her private key to generate the symmetric key
    alice_s = alice.gen_public(bob_public, alice_private, q_int)
    print("alice symmetric key: ", alice_s)

    # bob uses alices public key and his private to generate the symmetric key
    bob_s = bob.gen_public(alice_public, bob_private, q_int)
    print("bob symmetric key: ", bob_s)

    # generate SHA-256 hash object for alice using symmetric key (truncate to 16 bytes)
    alice_s = SHA256.new(alice_s.to_bytes(128, byteorder='big')).digest()[:16]
    # generate SHA-256 hash object for bob using symmetric key
    bob_s = SHA256.new(bob_s.to_bytes(128, byteorder='big')).digest()[:16]

    # check if bob and alices symmetric key are equal (they should be)
    if alice_s == bob_s:
        print("their symmetric keys are equal!")
    else:
        print("their symmetric keys are NOT equal!")
    print(alice_s)
    print(bob_s)

    iv = get_random_bytes(16)
    print(f"iv is {iv.hex()}")

    alice_encr = alice_encryption(alice_s, iv)
    print(f"alice's encrypted message is {alice_encr}")

    bob_decr = bob_decryption(bob_s, iv, alice_encr)
    print(f"bobs's decrypted message is {bob_decr}")


def alice_encryption(alice_s, iv):
    # generate a cipher for alice
    alice_cipher = AES.new(alice_s, AES.MODE_CBC, iv)
    plaintext = b'very secret info do not allow anyone to see thus'
    print(f"alice's original message is {plaintext}")

    # add padding to plaintext
    plaintext = plaintext + (16 - len(plaintext) % 16) * b' '  # Padding
    return alice_cipher.encrypt(plaintext)


def bob_decryption(bob_s, iv, alice_encr):
    # generate a cipher for bob using the same iv
    bob_cipher = AES.new(bob_s, AES.MODE_CBC, iv)
    return bob_cipher.decrypt(alice_encr).strip()


# function that adds padding when a byte array isn't equally dividable into chunks of 16 bytes
def add_padding(content, file_size):
    padding = b""
    if file_size % 16 != 0:
        padding_size = 16 - file_size % 16
        print(f"padding_size is {padding_size}")
        padding = bytes([padding_size] * padding_size)
    return content + padding


if __name__ == "__main__":
    main()
