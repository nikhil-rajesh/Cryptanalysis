import argparse

### To encrypt a single letter
def subEncryptLetter(letter, key):
    # if not an alphabet dont encrypt
    if not letter.isalpha():
        return ''
    # return corresponding character in key
    return key[ord(letter.upper()) - ord('A')]

### To decrypt a single letter
def subDecryptLetter(letter, key):
    if not letter.isalpha():
        return ''

    # return character corresponding to index of letter in key
    return chr(key.index(letter.upper()) + ord('A'))

### To encrypt a line
def subEncrypt(line, key):
    return ''.join([subEncryptLetter(c, key) for c in line])

### To decrypt a line
def subDecrypt(line, key):
    return ''.join([subDecryptLetter(d, key) for d in line])

### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt'], help="Encrypt or Decrypt the file")
    parser.add_argument("-k", "--key", required=True, help="File containing key")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    parser.add_argument("-o", "--output-file", required=True, help="Output file name")
    args = parser.parse_args()

    keyFile = open(args.key, "rt")
    # [:-1] is to remove newline at end
    key = keyFile.readline().upper()[:-1]

    if len(key) != 26:
        print("Key length should be 26")
        return

    inputFile = open(args.input_file, "rt")
    outputFile = open(args.output_file, "wt")

    #encrypt or decrypt depending on mode flag
    if args.mode == "encrypt":
        for line in inputFile:
            outputFile.write(subEncrypt(line, key) + "\n")
    elif args.mode == "decrypt":
        for line in inputFile:
            outputFile.write(subDecrypt(line, key) + "\n")

    inputFile.close()
    outputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
