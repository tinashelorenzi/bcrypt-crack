#!/bin/bash/python3
import argparse
import bcrypt

def check_if_bcrypt_hash(test_string):
    #Check to see if a string is a bcrypt hash
    try:
        bcrypt.hashpw(test_string, bcrypt.gensalt())
        return True
    except ValueError:
        return False
def load_hashes_from_file(hash_file):
    hashes = []
    with open(hash_file, 'r') as f:
        for line in f:
            hashes.append(line.strip())
    return hashes
def insert_hash_to_list(hash):
    hashes = []
    hashes.append(hash)
    return hashes
def wordlist_cracker(hash, wordlist):
    """Crack given bcrypt hash with given wordlist by converting each word in wordlist to bcrypt hash
    and comparing it to the given hash. 
    Returns the word that matches the hash or None if no match is found.
    """
    with open(wordlist, 'r') as f:
        for line in f:
            word = line.strip()
            hash = bcrypt.hashpw(word.encode('utf-8'), bcrypt.gensalt())
            if hash == hash:
                return word
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', help='File containing bcrypt hashes to crack', required=False)
    parser.add_argument('--hash', help='Hash to crack', required=False)
    parser.add_argument('--wordlist', help='Wordlist to use', required=True)
    args = parser.parse_args()
    #Check if a file was specified or a hash was specified and set flags accordingly
    if args.file:
        flag = "file"
    elif args.hash:
        flag = "hash"
    else:
        print("No hash or file specified")
        exit()
    

if __name__ == "__main__":
    main()