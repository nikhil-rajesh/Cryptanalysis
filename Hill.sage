import argparse
import re
from helper import normalize_input, n2l, l2n

def hillEncrypt(plaintext, key):
    if not key.is_square() :
        return "Key is not a square matrix"
    blockLength = key.dimensions()[0]
    #to pad to make equal length blocks
    if len(plaintext)%blockLength != 0:
        plaintext += 'Z'*(blockLength - len(plaintext)%blockLength)
    ptNumberList = [l2n(c) for c in plaintext]
    ptMatrix = matrix(Integers(26), ZZ(len(ptNumberList)/blockLength), blockLength, ptNumberList)
    ctMatrix = (ptMatrix*key).mod(26)
    return "".join([n2l(int(c)) for c in ctMatrix.list()])

def hillDecrypt(ciphertext, key):
    if not key.is_square() :
        return "Key is not a square matrix"
    blockLength = key.dimensions()[0]
    keyInverse = key.inverse()
    ctNumberList = [l2n(c) for c in ciphertext]
    ctMatrix = matrix(Integers(26), ZZ(len(ctNumberList)/blockLength), blockLength, ctNumberList)
    ptMatrix = (ctMatrix*keyInverse).mod(26)
    return "".join([n2l(int(c)) for c in ptMatrix.list()])

def attackHill(ciphertext):
    m = int(input("Enter the no.of columns: "))
    kwnPt = []
    kwnCt = []
    for i in range(m):
        pt = input("Enter Known Plaintext: " + str(i+1) + ": ")
        kwnPt.append(normalize_input(pt))
        ct = input("Enter Corresponding Ciphertext: " + str(i+1) + ": ")
        kwnCt.append(normalize_input(ct))

        if len(kwnPt[i]) != m or len(kwnCt[i]) != m:
            print("Known Plaintext and Ciphertext should be of length m")
            return

    kwnPtList = [[l2n(c) for c in pt] for pt in kwnPt]
    kwnCtList = [[l2n(c) for c in ct] for ct in kwnCt]
    kwnPtMatrix = matrix(Integers(26), m, m, kwnPtList)
    kwnCtMatrix = matrix(Integers(26), m, m, kwnCtList)
    
    if not kwnPtMatrix.is_invertible():
        print("Known Plaintext matrix is not invertible. Try with another combination")
        return

    keyMatrix = kwnPtMatrix.inverse()*kwnCtMatrix
    print("Key: ")
    print(keyMatrix)
    print("Plaintext: ", hillDecrypt(ciphertext, keyMatrix))
    
### Main Function
def main():
    # Arguments parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required=True, choices=['encrypt','decrypt', 'analysis'])
    parser.add_argument("-k", "--key", help="Key file (n space separated integers, where n is a perfect square)")
    parser.add_argument("-i", "--input-file", required=True, help="Input file with plaintext or ciphertext")
    args = parser.parse_args()

    inputFile = open(args.input_file, "rt")
    normalizedInput = normalize_input(inputFile.read())

    if args.mode == 'analysis':
        attackHill(normalizedInput)
    else:
        keyFile = open(args.key, "rt")
        # make a list from key file
        key = keyFile.readline()[:-1].split(" ")

        if not ZZ(len(key)).is_square():
            print("Key length is not a perfect square")
            return

        # change key entries from str to int
        key = [int(n) for n in key] 
        # converting to matrix
        key_matrix = matrix(Integers(26), ZZ(len(key)).sqrt(), ZZ(len(key)).sqrt(), key)

        if not key_matrix.is_invertible():
            print("Key Matrix is not invertible")
            return
        
        #encrypt or decrypt depending on mode flag
        if args.mode == "encrypt":
            print("Ciphertext: ", hillEncrypt(normalizedInput, key_matrix))
        elif args.mode == "decrypt":
            print("Plaintext: ", hillDecrypt(normalizedInput, key_matrix))

    inputFile.close()

if __name__ == '__main__':
    main()
### Code is written by Nikhil R
