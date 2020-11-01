import argparse
import string
import re
""" Refer helper.py for details """
from helper import normalize_input, split, l2n, n2l, wordlist

def shiftEncryptLetter(letter, shift):
    """ Convert letter to corresponding number (0-25) and add the shift
    value to it and convert the number back to ASCII """
    return n2l(l2n(letter) + shift%26)

def shiftDecryptLetter(letter, shift):
    """ Decryption can be done by Encrypting using the additivine
    Inverse of the key """
    return shiftEncryptLetter(letter, 26 - shift%26)

def shiftEncrypt(line, shift):
    """ For each character in the given line, do encryption """
    return ''.join([shiftEncryptLetter(c,shift) for c in line])

def shiftDecrypt(line, shift):
    """ For each character in the given line, do decryption """
    return ''.join([shiftDecryptLetter(d,shift) for d in line])

def attackShift_brute(ciphertext):
    words = wordlist()
    possiblePlaintexts = []

    """ For each value from 0-25, decrypt the given ciphertext """
    for key in range(26):
        plaintext = shiftDecrypt(ciphertext, key)
        """ Split the generated plaintext into possible words """
        plaintext = split(plaintext)
        cost = 0
        """ If a word is present in wordlist, cost is incremented by
        word length """
        for word in plaintext:
            if word.lower() in words:
                cost += len(word)
        """ Append the cost, plaintext and key to the array """
        possiblePlaintexts.append([cost/len(plaintext), ' '.join(plaintext), key])

    """ Sort array based on cost """
    possiblePlaintexts.sort(reverse=True, key = lambda x:x[0])
    print("\nMost probable plaintexts(with probabilistic spaces added) are\n")

    """ Print elements with the largest cost """
    for i in range(3):
        print("Key: ", possiblePlaintexts[i][2])
        print("Plaintext: ", possiblePlaintexts[i][1])
    return

def attackShift_kwnPt(ciphertext):
    """ Accept known plaintext """
    knownPt = input("Enter known Plaintext: ")
    knownCt = input("Enter corresponding Ciphertext: ")

    """ Error check for empty input """
    if knownPt == '' or knownCt == '':
        print("You entered an empty string")

    """ First character of plaintext - First character of ciphertext is the key """
    key = (l2n(knownCt[0]) - l2n(knownPt[0]) + 26)%26
    print("Key: ", key)
    print("Plaintext: ", shiftDecrypt(ciphertext, key))

def findFreq(text):
    freqList = []
    """ Find the percentage of occurence of each character in string """
    for c in string.ascii_uppercase:
        freqList.append((c, round((text.count(c)/len(text))*100, 2)))
    return freqList

def attackShift_freq(ciphertext):
    """ Find frequency of each character """
    freqList = findFreq(ciphertext)
    """ Sort based on highest frequency """
    freqList.sort(reverse = True,key = lambda x: x[1])  
    """ Highest frequenct element will be 'E', generate key from that """
    predictedKey = (l2n(freqList[0][0]) - ord('E') + 26)%26
    print("Key: ", predictedKey)
    print("Plaintext: ", shiftDecrypt(ciphertext, predictedKey))

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt','analysis'])
    parser.add_argument("-k", "--key", type=int, help="Shift Key Value")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    normalizedInput = normalize_input(inputFile.read())

    if args.mode == 'analysis':
        print("1. BruteForce (Ciphertext only)")
        print("2. Freq Analysis (Ciphertext only)")
        print("3. Known Plaintext")
        choice = input("Enter your choice: ")
        if choice == '1':
            attackShift_brute(normalizedInput)
        elif choice == '2':
            attackShift_freq(normalizedInput)
        elif choice == '3':
            attackShift_kwnPt(normalizedInput)
        else:
            print("Invalid Choice")

    elif args.key is None:
        print("No Shift Key provided")
    else:
        #encrypt or decrypt depending on mode flag
        if args.mode == "encrypt":
            print("Plaintext: ", normalizedInput)
            print("Key: ", args.key)
            print("Ciphertext: ", shiftEncrypt(normalizedInput, args.key))
        elif args.mode == "decrypt":
            print("Ciphertext: ", normalizedInput)
            print("Key: ", args.key)
            print("Plaintext: ", shiftDecrypt(normalizedInput, args.key))

    inputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
