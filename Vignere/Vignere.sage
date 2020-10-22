import argparse
import re

def normalize_input(input_string):
    """ Helper function to remove non alphanumeric characters """
    output = re.sub(r'\W+', '', input_string)
    return output.upper()

def letterToNumber(letter):
    return ord(letter.upper()) - ord('A')

def numberToLetter(number):
    return chr(number%26 + ord('A'))

### To encrypt a line
def vignereEncrypt(plaintext, key):
    ciphertext = ""
    keyIndex = 0
    for c in plaintext:
        ciphertext += numberToLetter(letterToNumber(c) + letterToNumber(key[keyIndex]))
        keyIndex = (keyIndex + 1)%len(key)

    return ciphertext

### To decrypt a line
def vignereDecrypt(ciphertext, key):
    inverseKey = []
    for c in key:
        inverseKey.append(26 - letterToNumber(c))

    plaintext = ""
    keyIndex = 0
    for letter in ciphertext:
        plaintext += numberToLetter(letterToNumber(letter) + inverseKey[keyIndex])
        keyIndex = (keyIndex + 1)%len(key)

    return plaintext

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt'], help="Encrypt or Decrypt the file")
    parser.add_argument("-k", "--key", required=True, help="The Key string")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    # changing key into uppercase
    key = args.key.upper()
    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    #encrypt or decrypt depending on mode flag
    if args.mode == "encrypt":
        outputFile.write(vignereEncrypt(normalizedInput, key) + "\n")
    elif args.mode == "decrypt":
        outputFile.write(vignereDecrypt(normalizedInput, key) + "\n")

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
