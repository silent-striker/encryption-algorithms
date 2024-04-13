# helper functions
# checking if numbers are prime
# concept: if number has factors they lie around the sqrt(number)
    # so there are factors that are less than or equal to sqrt(number)
def isPrime(num):
    if num == 2:
        return True
    if num == 3:
        return True
    if num <= 1 or num % 2 == 0 or num % 3 == 0:
        return False
    
    i = 2
    while i*i <= num:
        if num % i == 0:
            return False
        i += 1
    
    return True

# to find gcd of two numbers using euclidean algorithm
def gcd(a,b):
    gcdValue = a if a >= b else b 
    
    first = a
    second = b

    while True:
        if second > first:
            temp = a
            first = second
            second = temp

        if second == 0:
            gcdValue = first
            break

        temp = first
        first = second
        second = temp % second

    return gcdValue

# modular exponentiation
# a*b mod n = ((a mod n)*(b mod n))  mod n
def modExp(base, exp, num):
    iterations = exp.bit_length()
    result = 1
    temp = exp
    total = base % num

    i = 0
    while i < iterations:
        if temp % 2 == 1:
            result = ((result % num) * (total % num)) % num

        i += 1
        temp = temp >> 1
        total = ((total % num) * (total % num)) % num
    
    return result

# converting string to bytes for encryption, when plaintext is not all digits
def encodeMsg(plaintext):
    utf8_bytes = plaintext.encode("utf-8")
    return int.from_bytes(utf8_bytes, byteorder="big")

# bytes back to string
def decodeMsg(result_int, original_text_length):
    byteSeq = int.to_bytes(result_int, length=original_text_length, byteorder="big")
    return byteSeq.decode('utf-8')
# -------------------------------------------------------------------------------

# generate public key, 1 < e < n and co-prime with (p-1)*(q-1)
def generatePublicKey(n, phi_n):
    e = 2
    while e < n:
        # e and phi_n must have gcd = 1
        if gcd(e, phi_n) == 1:
            break
        e += 1
    
    return e

# generate private key
def generatePrivateKey(e, phi_n):
    d = 2
    while d < phi_n:
        if ((e % phi_n) * (d % phi_n)) % phi_n == 1:
            break
        d += 1
    return d


# driver code
if __name__ == "__main__":
    p = -1
    while True:
        num = input("Please enter a prime number, p\n")

        if num == "exit":
            exit(1)
        elif not num.isdigit():
            print("Input provided is not a valid number, please try again or type exit to quit")
        elif not isPrime(int(num)):
            print("Input provided is not a prime number, please try again or type exit to quit")
        else:
            p = int(num)
            break

    q = -1
    while True:
        num = input("Please enter a prime number, q\n")

        if num == "exit":
            exit(1)
        elif not num.isdigit():
            print("Input provided is not a valid number, please try again or type exit to quit")
        elif not isPrime(int(num)):
            print("Input provided is not a prime number, please try again or type exit to quit")
        else:
            q = int(num)
            break

    print("Calculating RSA values ........")

    n = int(p*q)

    # phi_n = (p-1)*(q-1)
    phi_n = int((p-1)*(q-1))

    e = int(generatePublicKey(n, phi_n))
    print("public key (e,n):", "(",e,",",n,")")

    d = int(generatePrivateKey(e, phi_n))
    print("private key (d,n):", "(",d,",", n, ")")

    plaintext = input("give a message to encrypt\n")
    plain_text_length = len(plaintext)
    
    encoded_plainText = -1
    if not plaintext.isdigit():
        encoded_plainText = encodeMsg(plaintext)
        print("encoded plaintext in UTF-8 for encryption:", encoded_plainText)
    else:
        encoded_plainText = int(plaintext)

    if encoded_plainText > n:
        print("Encoded plaintext value is larger than number 'n', there will be a loss in message data. Exiting .....")
        exit(2)

    # encryption
    cipher = modExp(encoded_plainText, e, n)
    print("cipher text:", cipher)

    # decryption
    decodedValue = modExp(cipher, d, n)
    print("decoded message value:", decodedValue)

    message = decodedValue
    if not plaintext.isdigit():
        message = decodeMsg(decodedValue, plain_text_length)
    
    print("final plaintext: ", message)
