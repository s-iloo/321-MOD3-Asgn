from random import randint
from Crypto.Hash import SHA256

q = bytes.fromhex("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371")
a = bytes.fromhex("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5")

class diffie_hellman: 
    def __init__(self, q, a):
        self.q = q
        self.a = a
    def gen_random_private(self): 
        return randint(1, self.q - 1)
    def gen_public(self, a, x, q):
        return pow(a, x, q)



def main(): 
    # length of the global public elements should be 128 bytes (1024 bits) 
    print(len(a))
    print(len(q))

    # converting global public elements into integers
    q_int = int.from_bytes(q, byteorder='big')
    a_int = int.from_bytes(a, byteorder='big')

    # creating diffie_hellman objects for alice and bob with global public elements
    alice = diffie_hellman(q_int, a_int)
    bob = diffie_hellman(q_int, a_int)

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

    # TODO: have bob and alice exchange encrypted messages using their symmetric key (CBC encryption) (same IV)



if __name__ == "__main__":
    main()