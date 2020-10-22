import argparse
import re

def normalize_input(input_string):
    """ Helper function to remove non alphanumeric characters """
    output = re.sub(r'\W+', '', input_string)
    return output.upper()

### To encrypt a single letter
def shiftEncryptLetter(letter, shift):
    # (a + shift)%26
    return chr((ord(letter.upper()) - ord('A') + shift)%26 + ord('A'))

### To decrypt a single letter
def shiftDecryptLetter(letter, shift):
    # do encryption with additive inverse of shift
    return shiftEncryptLetter(letter, 26 - shift)

### To encrypt a line
def shiftEncrypt(line, shift):
    return ''.join([shiftEncryptLetter(c,shift) for c in line])

### To decrypt a line
def shiftDecrypt(line, shift):
    return ''.join([shiftDecryptLetter(d,shift) for d in line])

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt'], help="Encrypt or Decrypt the file")
    parser.add_argument("-s", "--shift", required=True, type=int, help="Shift Value")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    #encrypt or decrypt depending on mode flag
    if args.mode == "encrypt":
        outputFile.write(shiftEncrypt(normalizedInput, args.shift) + "\n")
    elif args.mode == "decrypt":
        outputFile.write(shiftDecrypt(normalizedInput, args.shift) + "\n")

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
