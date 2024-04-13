# remove non-alpha characters and convert to UPPER case
def cleanInput(input):
    return ("".join([char for char in input if char.isalpha()])).upper()

# generate 5x5 key matrix using a secret key
# Assumption: secret key has only letters
# default skip char is J and replace with I
def genKeyMatrix(secret, skip='J', replace='I'):
    allChars = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 
                'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    skipChar = skip
    charSeq = []
    charPresentMap = {}
    # initially all chars are not present
    for char in allChars:
        charPresentMap[char] = False
    
    # to skip a character
    charPresentMap[skipChar] = True

    updatedSecret = secret.replace(skip, replace)
    # from secret key
    for char in updatedSecret:
        if(charPresentMap[char] == False):
            charSeq.append(char)
            charPresentMap[char] = True
    
    # remaining alphabets
    for char in allChars:
        if(charPresentMap[char] == False):
            charSeq.append(char)
            charPresentMap[char] = True
    
    matrix = []
    count = 0
    maxLimit = len(charSeq)

    for rwIdx in range(5):
        if count >= maxLimit:
            break

        row = []
        for colIdx in range(5):
            row.append(charSeq[count])
            count+=1
        matrix.append(row)
    
    return matrix


# find row and col of a char in matrix
def findLocation(matrix, char):
    row = 0
    col = 0
    rowLimit = len(matrix)
    colLimit = len(matrix[0])
    for rid in range(rowLimit):
        for cid in range(colLimit):
            if(char == matrix[rid][cid]):
                row = rid
                col = cid
                return [row, col]
    return [row, col]


# encrypt pair of strings
def encrypt(matrix, pairString):
    encryptedPair = ''

    firstChar = pairString[0]
    secondChar = pairString[1]

    fcRow, fcCol = findLocation(matrix, firstChar)
    scRow, scCol = findLocation(matrix, secondChar)

    rowLimit = len(matrix)
    colLimit = len(matrix[0])

    # chars in same row
    if fcRow == scRow:
        newFirstChar = matrix[fcRow][(fcCol+1) % colLimit]
        newSecondChar = matrix[scRow][(scCol+1) % colLimit]
        encryptedPair = newFirstChar + newSecondChar
    
    # chars in same col
    elif fcCol == scCol:
        newFirstChar = matrix[(fcRow+1) % rowLimit][fcCol]
        newSecondChar = matrix[(scRow+1) % rowLimit][scCol]
        encryptedPair = newFirstChar + newSecondChar
    
    # chars corner of rectangle, get the horizontal opposite
    else:
        newFirstChar = matrix[fcRow][scCol]
        newSecondChar = matrix[scRow][fcCol]
        encryptedPair = newFirstChar + newSecondChar

    return encryptedPair


# encryption using playfair cipher
def encryption(plaintext, matrix, skip='J', replace='I', paddingChar = 'X'):
    if(len(plaintext) == 0):
        return ""
    
    # replace skip character by its replacement
    updatedPlainText = plaintext.replace(skip, replace)

    # split plain text into pair of chars
    pairList = []
    plainTextLen = len(updatedPlainText)
    index = 0

    while index < plainTextLen:
        pairString = ''
        # no char after the current one
        if (index+1 == plainTextLen) or (index+1 < plainTextLen and updatedPlainText[index] == updatedPlainText[index+1]):
            pairString = updatedPlainText[index]+paddingChar
            index+=1
        elif index+1 < plainTextLen and updatedPlainText[index] != updatedPlainText[index+1]:
            pairString = updatedPlainText[index] + updatedPlainText[index+1]
            index+=2
        pairList.append(pairString)
    
    return "".join([encrypt(matrix, pair) for pair in pairList])


# decrypting pair using key matrix
def decrypt(matrix, pairString):
    decryptedPair = ''

    firstChar = pairString[0]
    secondChar = pairString[1]

    fcRow, fcCol = findLocation(matrix, firstChar)
    scRow, scCol = findLocation(matrix, secondChar)

    rowLimit = len(matrix)
    colLimit = len(matrix[0])

    # chars in same row
    if fcRow == scRow:
        newFirstChar = matrix[fcRow][(fcCol-1 if fcCol-1 >= 0 else fcCol-1+colLimit) % colLimit]
        newSecondChar = matrix[scRow][(scCol-1 if scCol-1 >= 0 else scCol-1+colLimit) % colLimit]
        decryptedPair = newFirstChar + newSecondChar
    
    # chars in same col
    elif fcCol == scCol:
        newFirstChar = matrix[(fcRow-1 if fcRow - 1 >= 0 else fcRow-1+rowLimit) % rowLimit][fcCol]
        newSecondChar = matrix[(scRow-1 if scRow-1 >= 0 else scRow-1+rowLimit) % rowLimit][scCol]
        decryptedPair = newFirstChar + newSecondChar
    
    # chars corner of rectangle, get the horizontal opposite
    else:
        newFirstChar = matrix[fcRow][scCol]
        newSecondChar = matrix[scRow][fcCol]
        decryptedPair = newFirstChar + newSecondChar

    return decryptedPair

# decryption of encrypted text
def decryption(ciphertext, matrix):
    pairList = []
    cipherTextLen = len(ciphertext)

    # ciphertext is always of even length
    for index in range(0, cipherTextLen, 2):
        pairList.append(ciphertext[index]+ciphertext[index+1])

    return "".join([decrypt(matrix, pair) for pair in pairList])



# starter code
if __name__ == "__main__":
    secretKey = cleanInput(input("Enter a secret key\n"))
    if(len(secretKey) == 0):
        print("No alphabet characters in the secret key, exiting please try again........")
        exit(1)
    print("This is your secret key:", secretKey)
    print()

    print("Enter message to encrypt (press Enter again to finish)")
    inputStr = ""
    lines = []
    # for multi line input
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    inputStr = "".join(lines)
    print("Plaintext:", inputStr, sep='\n')
    print()

    plaintext = cleanInput(inputStr)

    if(len(plaintext) == 0):
        print("No alphabet characters in the plaintext, exiting please try again.........")
        exit(1)
    print("Plaintext after cleaning:", plaintext, sep='\n')
    print()

    matrix = genKeyMatrix(secretKey)

    print("Generated key matrix: ")
    for i in range(len(matrix)):
        print(matrix[i])

    print()
    ciphertext = encryption(plaintext, matrix)
    print("encrypted message:", ciphertext, sep="\n")

    print()
    decryptedtext = decryption(ciphertext, matrix)
    print("decrypted message: ", decryptedtext, sep="\n")