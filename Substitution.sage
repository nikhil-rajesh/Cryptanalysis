import argparse
import re
from helper import normalize_input, l2n, n2l

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
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt'], help="Encrypt or Decrypt the file")
    parser.add_argument("-k", "--key", required=True, help="Key for encryption/decryption")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    key = args.key.upper()
    if len(key) != 26:
        print("Key length should be 26")
        return

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    #encrypt or decrypt depending on mode flag
    if args.mode == "encrypt":
        outputFile.write(subEncrypt(normalizedInput, key) + "\n")
    elif args.mode == "decrypt":
        outputFile.write(subDecrypt(normalizedInput, key) + "\n")

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
