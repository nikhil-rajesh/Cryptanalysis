import argparse
import re

def normalize_input(input_string):
    """ Helper function to remove non alphanumeric characters """
    output = re.sub(r'\W+', '', input_string)
    return output.upper()

def transpositionEncrypt(plaintext, keyList, nColumns):
    ciphertext = ""
    blockLength = 0
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

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt'], help="Encrypt or Decrypt the file")
    parser.add_argument("-k", "--key", type=int, help="The Key string (string of integers)")
    parser.add_argument("-c", "--columns", type=int, help="No.of columns for encryption")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    # either key or columsn or both should be given
    if (args.key is None) and (args.columns is None):
        print("One or both of the arguments, Key and Columns should be provided")
        return
    
    if (args.key is not None) and (args.columns is not None) and (len(str(args.key)) != args.columns):
        print("Length of Key and Number of columns should be same")
        return

    # changing key into uppercase
    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())
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
        outputFile.write(transpositionEncrypt(normalizedInput, keyList, args.columns) + "\n")
    elif args.mode == "decrypt":
        outputFile.write(transpositionDecrypt(normalizedInput, keyList, args.columns) + "\n")

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
