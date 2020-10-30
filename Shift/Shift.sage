import argparse
import re
import wordninja

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

def attackShift(ciphertext):
    #Open Dictionary of words
    words = open('../wordlist').read().split()
    words = dict((i,1) for i in words)

    possiblePlaintexts = []

    for key in range(26):
        plaintext = shiftDecrypt(ciphertext, key)
        plaintext = wordninja.split(plaintext)
        cost = 0
        for word in plaintext:
            if word.lower() in words:
                cost += len(word)
        possiblePlaintexts.append((cost/len(plaintext), ' '.join(plaintext)))

    return possiblePlaintexts

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt','analysis'], help="Encrypt or Decrypt the file")
    parser.add_argument("-s", "--shift", type=int, help="Shift Value")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    normalizedInput = normalize_input(inputFile.read())

    if args.mode == 'analysis':
        validPlaintexts = attackShift(normalizedInput);
        validPlaintexts.sort(reverse=True, key = lambda x:x[0])
        print("Most probable plaintexts are\n")
        for p in validPlaintexts:
            if validPlaintexts.index(p) < 3:
                print(p[1])
            outputFile.write(p[1] + '\n')
        print("\nAll other combinations have been written to the output file in order of decreasing probability")

    elif args.shift is None:
        print("No Shift Key provided")
    else:
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
