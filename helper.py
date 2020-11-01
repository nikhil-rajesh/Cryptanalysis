from math import log
import re

wordDict = open("wordlist", "rt")
words = wordDict.read().split()
wordCost =  dict((k, log((i+1)*log(len(words)))) for i,k in enumerate(words))
maxWord = max(len(x) for x in words)

""" Helper function that returns a dictionary of words """
def wordlist():
    return wordCost

""" Helper function that splits a sentence without words """
def split(s):
    def best_match(i):
      candidates = enumerate(reversed(cost[max(0, i-maxWord):i]))
      return min((c + wordCost.get(s[i-k-1:i].lower(), 9e999), k+1) for k,c in candidates)
    # Build the cost array.
    cost = [0]
    lengthArray = [0]
    for i in range(1,len(s)+1):
        c,k = best_match(i)
        cost.append(c)
        lengthArray.append(k)
    # Backtrack to recover the minimal-cost string.
    out = []
    i = len(s)
    while i>0:
        out.append(s[i-lengthArray[i]:i])
        i -= lengthArray[i]

    return [word for word in reversed(out)]

""" Helper function to convert Letter to Number """
def l2n(letter):
    return ord(letter.upper()) - ord('A')

""" Helper function to convert Number to Letter """
def n2l(number):
    return chr(number%26 + ord('A'))

""" Helper function to remove non alphanumeric characters """
def normalize_input(input_string):
    output = re.sub(r'\W+', '', input_string)
    return output.upper()
