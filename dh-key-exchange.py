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

    print("\nMallory intercepts YA and YB")

    # creating diffie_hellman objects for alice and bob with global public elements
    alice = DiffieHellman(q_int, a_int)
    bob = DiffieHellman(q_int, a_int)
    # mallory enters
    mallory = DiffieHellman(q_int, a_int)

    # generating alices private and public keys
    alice_private = alice.gen_random_private()
    alice_public = alice.gen_public(a_int, alice_private, q_int)
    print("alice public: ", alice_public)

    # generating bobs private and public keys
    bob_private = bob.gen_random_private()
    bob_public = bob.gen_public(a_int, bob_private, q_int)
    print("bob public: ", bob_public)

    # Simulate MITM attack
    # -mallory tampers with the public key exchange
    # -mallory intercepts and sends q_int to Bob instead of YA
    alice_public = q_int
    # mallory intercepts and sends q_int to Alice instead of YB
    bob_public = q_int

    # TODO is this possibly confusing? Using generate public
    # alice uses bobs public key and her private key to generate the symmetric key
    alice_sym = alice.gen_public(bob_public, alice_private, q_int)
    print("alice symmetric key: ", alice_sym)

    # bob uses alices public key and his private to generate the symmetric key
    bob_sym = bob.gen_public(alice_public, bob_private, q_int)
    print("bob symmetric key: ", bob_sym)

    # generate SHA-256 hash object for alice using symmetric key (truncate to 16 bytes)
    alice_sym = SHA256.new(alice_sym.to_bytes(128, byteorder='big')).digest()[:16]
    # generate SHA-256 hash object for bob using symmetric key
    bob_sym = SHA256.new(bob_sym.to_bytes(128, byteorder='big')).digest()[:16]

    # check if bob and alices symmetric key are equal (they should be)
    if alice_sym == bob_sym:
        print("their symmetric keys are equal!")
    else:
        print("their symmetric keys are NOT equal!")
    print(alice_sym)
    print(bob_sym)

    # mallory can compute the shared secret as well
    mallory_private = mallory.gen_random_private()  # Mallory's private key
    mallory_public = q_int  # uses q_int because mallory knows bob and alice are using it for public keys
    mallory_sym = mallory.gen_public(mallory_public, mallory_private, q_int)
    mallory_sym = SHA256.new(mallory_sym.to_bytes(128, byteorder='big')).digest()[:16]
    print(f"Mallory's symmetric key is {mallory_sym}")

    iv = get_random_bytes(16)
    print(f"iv is {iv.hex()}")

    alice_encr = alice_encrypt(alice_sym, iv)
    print(f"alice's encrypted message is {alice_encr}")

    mallory_decr = mallory_decrypt(mallory_sym, iv, alice_encr)
    print(f"Mallory decrypted Alice's message is {mallory_decr}")

    bob_decr = bob_decrypt(bob_sym, iv, alice_encr)
    print(f"bobs's decrypted message is {bob_decr}")

    # task 2 part 2
    print("starting task 2...")
    # mallory tampers with the alpha global public element and makes it 1
    new_a = 1

    # creating the DiffieHellman classes for alice and bob and mallory
    alice = DiffieHellman(q_int, new_a)
    bob = DiffieHellman(q_int, new_a)
    mallory = DiffieHellman(q_int, new_a)


    # alice generates her private and public integers 
    alice_private = alice.gen_random_private()
    alice_public = alice.gen_public(new_a, alice_private, q_int)
    print("alice public: ", alice_public)

    # bob generates her private and public integers
    bob_private = bob.gen_random_private()
    bob_public = bob.gen_public(new_a, bob_private, q_int)
    print("bob public: ", bob_public)

    # mallory can compute the shared secret as well
    mallory_private = mallory.gen_random_private()  # Mallory's private key
    # since mallory knows that 1 mod/power any number is always 1 she knows bobs and alices public 
    # number that they're sending to each other must be 1
    mallory_sym = 1
    mallory_sym = SHA256.new(mallory_sym.to_bytes(128, byteorder='big')).digest()[:16]
    print(f"Mallory's symmetric key is {mallory_sym}")

    # alice uses bobs public key and her private key to generate the symmetric key
    alice_sym = alice.gen_public(bob_public, alice_private, q_int)
    print("alice symmetric key: ", alice_sym)

    # bob uses alices public key and his private to generate the symmetric key
    bob_sym = bob.gen_public(alice_public, bob_private, q_int)
    print("bob symmetric key: ", bob_sym)

    # generate SHA-256 hash object for alice using symmetric key (truncate to 16 bytes)
    alice_sym = SHA256.new(alice_sym.to_bytes(128, byteorder='big')).digest()[:16]
    # generate SHA-256 hash object for bob using symmetric key
    bob_sym = SHA256.new(bob_sym.to_bytes(128, byteorder='big')).digest()[:16]

    if mallory_sym == bob_sym:
        print("mallory's symmetric key is equal to bobs!")
    else: 
        print("not equal")

    iv = get_random_bytes(16)
    print(f"iv is {iv.hex()}")

    alice_encr = alice_encrypt(alice_sym, iv)
    print(f"alice's encrypted message is {alice_encr}")

    mallory_decr = mallory_decrypt(mallory_sym, iv, alice_encr)
    print(f"Mallory decrypted Alice's message is {mallory_decr}")

    bob_decr = bob_decrypt(bob_sym, iv, alice_encr)
    print(f"bobs's decrypted message is {bob_decr}")




def alice_encrypt(alice_s, iv):
    # generate a cipher for alice
    alice_cipher = AES.new(alice_s, AES.MODE_CBC, iv)
    plaintext = b'very secret info do not allow anyone to see this'  # lol its 48 exactly I did that on accident
    print(f"alice's original message is {plaintext}")

    # add padding to plaintext
    plaintext = add_padding(plaintext)
    return alice_cipher.encrypt(plaintext)


def bob_decrypt(bob_s, iv, alice_encr):
    # generate a cipher for bob using the same iv
    bob_cipher = AES.new(bob_s, AES.MODE_CBC, iv)
    return bob_cipher.decrypt(alice_encr)


def mallory_decrypt(mallory_s, iv, alices_encr_message):
    # mallory decrypts alice's message using her symmetric key
    mallory_cipher = AES.new(mallory_s, AES.MODE_CBC, iv)
    return mallory_cipher.decrypt(alices_encr_message)


# function that adds padding when a byte array isn't equally dividable into chunks of 16 bytes
def add_padding(content):
    padding = b""
    if len(content) % 16 != 0:
        padding_size = 16 - len(content) % 16
        print(f"padding_size is {padding_size}")
        padding = bytes([padding_size] * padding_size)
    return content + padding

# padding remover based on how we pad in add_padding
def remove_padding(padded_data):
    # the last byte indicates the padding length
    padding_len = padded_data[-1]
    if len(set(padded_data[-padding_len:])) == 1:
        return padded_data[:-padding_len]
    return padded_data


if __name__ == "__main__":
    main()
