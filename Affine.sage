import argparse
import re
from helper import l2n, n2l, normalize_input, split, wordlist

coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

""" Generates a random element coprime to 26 """
def random_coprime():
    return coprimes[ZZ.random_element(len(coprimes))]
""" To encrypt in Affine """
def affineEncrypt(line, a, b):
    return ''.join([ n2l(a*l2n(c) + b) for c in line ])

""" To decrypt in Affine """
def affineDecrypt(line, a, b):
    return ''.join([ n2l(inverse_mod(a, 26)*(l2n(d) - b)) for d in line ])

def attackAffine_brute(ciphertext):
    #Open Dictionary of words
    words = wordlist()
    possiblePlaintexts = []

    # For all coprimes as a
    for a in coprimes:
        # For all possible values of b
        for b in range(1, 27):
            # Decrypt using a and b
            plaintext = affineDecrypt(ciphertext, a, b)
            plaintext = split(plaintext)
            cost = 0
            # find cost of each generated plaintext
            for word in plaintext:
                if word.lower() in words:
                    cost += len(word)
            # The plaintext with lesser no of words are more probable
            possiblePlaintexts.append([cost/len(plaintext), ' '.join(plaintext), a, b])

    # Plaintext with highest cost is the most probable one
    possiblePlaintexts.sort(reverse=True, key = lambda x:x[0])
    print("Most probable plaintexts are\n")
    # Print top 3 outputs
    for i in range(3):
        print("Key A = ", str(possiblePlaintexts[i][2]), ", Key B = ", str(possiblePlaintexts[i][3]))
        print("Possible Plaintext: ", possiblePlaintexts[i][1])

def attackAffince_chosenPT(ciphertext):
    # Take chosen plaintext as input
    known_pt = normalize_input(input("Enter known plaintext: "))
    known_ct = normalize_input(input("Enter corresponding ciphertext: "))

    # Error handling
    if len(known_pt) < 2:
        print("ERROR: Chosen Plaintext should be atleast 2 characters long")
        return
    elif len(known_pt) != len(known_ct):
        print("ERROR: Chosen Plaintext & corresponding ciphertext length does not match")
        return
    
    # Generate sage matrix from plaintext input
    ptMatrix = matrix(Integers(26), 2, 2, [l2n(known_pt[0]), 1, l2n(known_pt[1]), 1])
    ctMatrix = matrix(Integers(26), 2, 1, [l2n(known_ct[0]), l2n(known_ct[1])])

    # Check if given plaintext is invertible in matrix form
    if not ptMatrix.is_invertible():
        print("The given plaintext cannot be used to decrypt")
        return

    # generate the key
    keyMatrix = (ptMatrix.inverse()*ctMatrix).mod(26).list()
    # Decrypt and print using the key
    print("Key A = ", keyMatrix[0], ", Key B = ", keyMatrix[1])
    print("Possible Plaintext: ", affineDecrypt(ciphertext, int(keyMatrix[0]), int(keyMatrix[1])))

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt','analysis'], help="Encrypt or Decrypt the file")
    parser.add_argument("-a", type=int, help="Coefficient A (optional for encrypt)")
    parser.add_argument("-b", type=int, help="Coefficient B (optional for encrypt)")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    normalizedInput = normalize_input(inputFile.read())

    if args.mode == 'analysis':
        choice = ''
        print("Choose one of the attacks:")
        print("a. Brute Force")
        print("b. Chosen Plaintext")
        choice = input("Enter your choice:")

        if choice == 'a':
            attackAffine_brute(normalizedInput);
        elif choice == 'b':
            attackAffince_chosenPT(normalizedInput)
        else:
            print("Not a valid choice.")

    #if decryption Coefficient is mandatory
    elif args.mode == "decrypt" and (args.a is None or args.b is None):
        print("Keys are required for Decryption")
        return

    else:
        # if Coefficient A is not given, generate random element
        if args.a is None:
            args.a = random_coprime()
        # if Coefficient B is not given, generate random element
        if args.b is None:
            args.b = ZZ.random_element(1, 27)
        # Check if 'a' is co-prime with 26
        if gcd(args.a, 26) != 1:
            print("Error: 'a' is not co-prime with 26")
            return

        #encrypt or decrypt depending on mode flag
        if args.mode == "encrypt":
            print("Plaintext: ", normalizedInput)
            print("A = ", args.a)
            print("B = ", args.b)
            print("Ciphertext: ", affineEncrypt(normalizedInput, args.a, args.b))
        elif args.mode == "decrypt":
            print("Ciphertext: ", normalizedInput)
            print("A = ", args.a)
            print("B = ", args.b)
            print("Plaintext: ", affineDecrypt(normalizedInput, args.a, args.b))

    inputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
