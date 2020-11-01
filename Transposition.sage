import argparse
import re
""" Refer helper.py for details """
from helper import normalize_input, split, wordlist

def transpositionEncrypt(plaintext, keyList, nColumns):
    ciphertext = ""
    blockLength = 0
    # block length is the key length or no.of Columns
    if keyList is not None:
        blockLength = len(keyList)
    else:
        blockLength = nColumns

    #to pad to make equal length blocks
    if len(plaintext)%blockLength != 0:
        plaintext += 'Z'*(blockLength - len(plaintext)%blockLength)

    # if Keyed
    if keyList is not None:
        for count in range(0, len(plaintext), blockLength):
            # swap recursively with indexes in keyList
            for k in keyList:
                ciphertext += plaintext[count + (k - 1)]
        plaintext = ciphertext

    # if keyless
    if nColumns is not None:
        ciphertext = ""
        # Join elements of same index in each block
        for i in range(blockLength):
            for j in range(i, len(plaintext), blockLength):
                ciphertext += plaintext[j]

    return ciphertext

def transpositionDecrypt(ciphertext, keyList, nColumns):
    plaintext = ""
    # if keyless
    if nColumns is not None:
        blockLength = int(len(ciphertext)/nColumns)
        # Join elements of same index in each block
        for i in range(blockLength):
            for j in range(i, len(ciphertext), blockLength):
                plaintext += ciphertext[j]
        ciphertext = plaintext

    # if keyed
    if keyList is not None:
        plaintext = ""
        #construct inverse key
        inverseKey = [0]*len(keyList)
        for k in keyList:
            inverseKey[k - 1] = keyList.index(k)

        for count in range(0, len(ciphertext), len(inverseKey)):
            # swap recursively with indexes in reverseKey
            for k in inverseKey:
                plaintext += ciphertext[count + k]

    return plaintext

def attackTransposition(ciphertext):
    words = wordlist()
    allDivisors = False
    possiblePlaintexts = []
    #Find divisors of the ciphertext length
    div = divisors(len(ciphertext))[:-1]
    #Find all possible keys for each divisor
    for d in div:
        if d > 7 and not allDivisors:
            print("Do you want to check keys with lenght more than 7?")
            print("This will take a significantly higher amount of time to process. (y/n):")
            temp = input()
            if temp == 'y':
                allDivisors = True
                continue
            else:
                break

        # Generate all keys that are possible with that key length
        keys = Permutations(d).list()
        for key in keys:
            cost = 0
            # decrypt using each key
            plaintext = transpositionDecrypt(ciphertext, key, len(key))
            plaintext = split(plaintext)
            # find cost of each generated plaintext
            for word in plaintext:
                if word.lower() in words:
                    cost += len(word)
            # The plaintext with lesser no of words are more probable
            possiblePlaintexts.append([cost/len(plaintext), ' '.join(plaintext), key])

    # Plaintext with highest cost is the most probable one
    possiblePlaintexts.sort(reverse=True, key = lambda x:x[0])
    print("\nMost probable plaintexts are\n")
    # Print top 3 outputs
    for i in range(3):
        print("Key: ", possiblePlaintexts[i][2])
        print("Columns: ", len(possiblePlaintexts[i][2]))
        print("Possible Plaintext: ", possiblePlaintexts[i][1])

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt', 'analysis'], help="Encrypt, Decrypt or Analyze the file")
    parser.add_argument("-k", "--key", type=int, help="The Key string (string of integers)")
    parser.add_argument("-c", "--columns", type=int, help="No.of columns for encryption")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    args = parser.parse_args()

    # changing key into uppercase
    inputFile = open(args.input_file, "rt")
    normalizedInput = normalize_input(inputFile.read())

    if args.mode == "analysis":
        attackTransposition(normalizedInput);
    else:
        # either key or columsn or both should be given
        if (args.key is None) and (args.columns is None):
            print("One or both of the arguments, Key and Columns should be provided")
            return
        
        if (args.key is not None) and (args.columns is not None) and (len(str(args.key)) != args.columns):
            print("Length of Key and Number of columns should be same")
            return

        keyList = None

        if args.key is not None:
            # Making a list of integers from key
            keyList = [int(c) for c in str(args.key)]
            # Check if its a valid key (should be continuous set of integers starting from 1)
            for idx,val in enumerate(sorted(keyList)):
                if val != (idx + 1):
                    print("Not a valid key.")
                    return

        #encrypt or decrypt depending on mode flag
        if args.mode == "encrypt":
            print("Plaintext: ", normalizedInput)
            print("Key: ", keyList)
            print("Columns: ", args.columns)
            print("Plaintext: ", transpositionEncrypt(normalizedInput, keyList, args.columns))
        elif args.mode == "decrypt":
            print("Ciphertext: ", normalizedInput)
            print("Key: ", keyList)
            print("Columns: ", args.columns)
            print("Plaintext: ", transpositionDecrypt(normalizedInput, keyList, args.columns))

    inputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
