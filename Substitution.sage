import argparse
import string
import re
from helper import normalize_input, l2n, n2l, split

letterFreq = [
        ('E', 12.7),
        ('T', 9.1),
        ('A', 8.2),
        ('O', 7.5),
        ('I', 7.0),
        ('N', 6.7),
        ('S', 6.3),
        ('H', 6.1),
        ('R', 6.0),
        ('D', 4.3),
        ('L', 4.0),
        ('C', 2.8),
        ('U', 2.8),
        ('M', 2.4),
        ('W', 2.3),
        ('F', 2.2),
        ('G', 2.0),
        ('Y', 2.0),
        ('P', 1.9),
        ('B', 1.5),
        ('V', 1.0),
        ('K', 0.08),
        ('J', 0.02),
        ('Q', 0.01),
        ('X', 0.01),
        ('Z', 0.01)
        ]

""" Generate Frequency List from a given string """
def findFreq(text):
    freqList = []
    for c in string.ascii_uppercase:
        freqList.append((c, round((text.count(c)/len(text))*100, 2)))
    return freqList

""" Generate's a key based on freq. analysis and known plaintext """
def generateKey(freqListCT, freqListPT, knownPT, knownCT):
    possibleKey = [0]*26
    """ Known plaintext attack """
    if knownPT is not None:
        """ Cleaning the input """
        knownCT = normalize_input(knownCT)
        knownPT = normalize_input(knownPT)

        if len(knownPT) != len(knownCT):
            err = "\nKnown plaintext and ciphertext of different length\n"
            print(err)
            return err

        for i,c in enumerate(knownPT):
            possibleKey[l2n(c)] = knownCT[i]

        """ Deleting entries of known items from freq list """
        temp = []
        for i in freqListCT:
            if i[0] not in knownCT:
                temp.append(i)
        freqListCT = temp

        temp = []
        for i in freqListPT:
            if i[0] not in knownPT:
                temp.append(i)
        freqListPT = temp

    freqListCT.sort(key = lambda x: x[1])  
    freqListPT.sort(key = lambda x: x[1])
    for i,pair in enumerate(freqListPT):
        possibleKey[l2n(pair[0])] = freqListCT[i][0]
    print(possibleKey)
    return ''.join(possibleKey)

""" Generates the inverse of the key for decryption """
def inverseKey(key):
    inverseKey = [0]*26
    for i,c in enumerate(key):
        inverseKey[l2n(c)] = n2l(i)

    return ''.join(inverseKey)

""" Function to encrypt using given key """
def subEncrypt(line, key):
    return ''.join([ key[l2n(c)] for c in line ])

""" Function to decrypt by encrypting using inverse key """
def subDecrypt(line, key):
    return subEncrypt(line, inverseKey(key))

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt', 'decrypt', 'analysis'], help="Encrypt, Decryptor analyze the file")
    parser.add_argument("-k", "--key", help="Key for encryption/decryption")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    if args.mode == "analysis":
        freqList = findFreq(normalizedInput)

        """ Known Plaintext attack choice """
        choice = input("Do you have a known Plaintext? (y/n)")
        if choice == 'y':
            knownPT = input("Enter Known Plaintext: ")
            knownCT = input("Enter corresponding Ciphertext: ")
            possibleKey = generateKey(freqList, letterFreq, knownPT, knownCT)
        elif choice == 'n':
            possibleKey = generateKey(freqList, letterFreq, None, None)
            print(possibleKey)
        else:
            print("Invalid Choice.")
            return

        """ Decrypt based on generated key """
        possiblePlaintext = subDecrypt(normalizedInput, possibleKey)
        possiblePlaintext = ' '.join(split(possiblePlaintext))
        print("Possible Plaintext is \n")
        print(possiblePlaintext)
        outputFile.write(possiblePlaintext + "\n")

    else:
        if args.key is None:
            print("No key provided")
            return

        key = args.key.upper()
        if len(key) != 26:
            print("Key length should be 26")
            return
        #encrypt or decrypt depending on mode flag
        if args.mode == "encrypt":
            ciphertext = subEncrypt(normalizedInput, key) + "\n"
            print(ciphertext)
            outputFile.write(ciphertext)
        elif args.mode == "decrypt":
            plaintext = subDecrypt(normalizedInput, key) + "\n"
            print(plaintext)
            outputFile.write(plaintext)

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
