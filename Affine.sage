import argparse
import re
from helper import l2n, n2l, normalize_input, split

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
    words = open('../wordlist').read().split()
    words = dict((i,1) for i in words)

    possiblePlaintexts = []

    for a in coprimes:
        for b in range(1, 27):
            plaintext = affineDecrypt(ciphertext, a, b)
            plaintext = split(plaintext)
            cost = 0
            for word in plaintext:
                if word.lower() in words:
                    cost += len(word)
            possiblePlaintexts.append([cost/len(plaintext), ' '.join(plaintext), a, b])

    return possiblePlaintexts

def attackAffince_chosenPT(ciphertext, known_pt, known_ct):
    known_pt = normalize_input(known_pt)
    known_ct = normalize_input(known_ct)
    if len(known_pt) < 2:
        err = "ERROR: Chosen Plaintext should be atleast 2 characters long"      
        print(err)
        return err
    elif len(known_pt) != len(known_ct):
        err = "ERROR: Chosen Plaintext & corresponding ciphertext length does not match"      
        print(err)
        return err
    
    ptMatrix = matrix(Integers(26), 2, 2, [l2n(known_pt[0]), 1, l2n(known_pt[1]), 1])
    ctMatrix = matrix(Integers(26), 2, 1, [l2n(known_ct[0]), l2n(known_ct[1])])
    keyMatrix = (ptMatrix.inverse()*ctMatrix).mod(26).list()
    print(keyMatrix)
    return "err"
    return affineDecrypt(ciphertext, keyMatrix[0], keyMatrix[1])

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt','analysis'], help="Encrypt or Decrypt the file")
    parser.add_argument("-a", type=int, help="Coefficient A (optional for encrypt)")
    parser.add_argument("-b", type=int, help="Coefficient B (optional for encrypt)")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    if args.mode == 'analysis':
        choice = ''
        print("Choose one of the attacks:")
        print("a. Brute Force")
        print("b. Chosen Plaintext")
        choice = input("Enter your choice:")

        if choice == 'a':
            validPlaintexts = attackAffine_brute(normalizedInput);
            validPlaintexts.sort(reverse=True, key = lambda x:x[0])
            print("Most probable plaintexts are\n")
            for p in validPlaintexts:
                if validPlaintexts.index(p) < 3:
                    print(p[1] + " with key a=" + str(p[2]) + " b=" + str(p[3]))
                outputFile.write(p[1] + '\n')
            print("\nAll other combinations have been written to the output file in order of decreasing probability")

        elif choice == 'b':
            known_pt = input("Enter known plaintext: ")
            known_ct = input("Enter corresponding ciphertext: ")
            plaintext = attackAffince_chosenPT(normalizedInput, known_pt, known_ct)
            outputFile.write(plaintext + '\n')

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
        
        keyFile = open("key_"+args.output_file, "wt")

        #encrypt or decrypt depending on mode flag
        if args.mode == "encrypt":
            outputFile.write(affineEncrypt(normalizedInput, args.a, args.b) + "\n")
        elif args.mode == "decrypt":
            plaintext = affineDecrypt(normalizedInput, args.a, args.b)
            outputFile.write(' '.join(split(plaintext)))

        #write keys to keyFile
        keyFile.write("A = " + str(args.a) + "\n")
        keyFile.write("B = " + str(args.b) + "\n")
        keyFile.close()

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
