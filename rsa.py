from Crypto.Util import number


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
    d = 1 / (e % phi_n)
    # public key (PU = {e, n})
    public = {e, n}
    # private key (PR = {d, n})
    private = {d, n}

    # ----- ENCRYPTION ----- 
    message = "this is my private message!"
    # message_hex = ''.join([hex(ord(char))[2:] for char in message])
    message_ascii = message.encode('ascii')
    message_hex = message_ascii.hex()
    message_int = int(message_hex, 16)
    print("my message in hex: ", message_int)
    if message_int < n: 
        print("message is less than n")

    
if __name__ == "__main__":
    main()