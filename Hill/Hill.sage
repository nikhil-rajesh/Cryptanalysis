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

def hillEncrypt(plaintext, key):
    if not key.is_square() :
        return "Key is not a square matrix"
    blockLength = key.dimensions()[0]
    #to pad to make equal length blocks
    if len(plaintext)%blockLength != 0:
        plaintext += 'Z'*(blockLength - len(plaintext)%blockLength)
    ptNumberList = [ord(c) - ord('A') for c in plaintext]
    ptMatrix = matrix(Integers(26), ZZ(len(ptNumberList)/blockLength), blockLength, ptNumberList)
    ctMatrix = (ptMatrix*key).mod(26)
    return "".join([numberToLetter(int(c)) for c in ctMatrix.list()])

def hillDecrypt(ciphertext, key):
    if not key.is_square() :
        return "Key is not a square matrix"
    blockLength = key.dimensions()[0]
    keyInverse = key.inverse()
    ctNumberList = [ord(c) - ord('A') for c in ciphertext]
    ctMatrix = matrix(Integers(26), ZZ(len(ctNumberList)/blockLength), blockLength, ctNumberList)
    ptMatrix = (ctMatrix*keyInverse).mod(26)
    return "".join([numberToLetter(int(c)) for c in ptMatrix.list()])

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt'], help="Encrypt or Decrypt the file")
    parser.add_argument("-k", "--key", required=True, help="Key file (n space separated integers, where n is a perfect square)")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    # changing key into uppercase
    keyFile = open(args.key, "rt")
    # make a list from key file
    key = keyFile.readline()[:-1].split(" ")

    if not ZZ(len(key)).is_square():
        print("Key length is not a perfect square")
        return

    # change key entries from str to int
    key = [int(n) for n in key] 

    key_matrix = matrix(Integers(26), ZZ(len(key)).sqrt(), ZZ(len(key)).sqrt(), key)

    if not key_matrix.is_invertible():
        print("Key Matrix is not invertible")
        return

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    #encrypt or decrypt depending on mode flag
    if args.mode == "encrypt":
        outputFile.write(hillEncrypt(normalizedInput, key_matrix) + "\n")
    elif args.mode == "decrypt":
        outputFile.write(hillDecrypt(normalizedInput, key_matrix) + "\n")

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
