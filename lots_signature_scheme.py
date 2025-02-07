"""
Lamport One-Time Signature Implementation

Overview:
    - Generate a public and private key pair
    - Sign a message
    - Verify the signature using the private key

1. Generate keys:
    - python lots_signature_scheme.py lots_genkeys

2. Sign a message: 
    - python lots_signature_scheme.py lots_sign message.txt private_key.lots

3. Verify a signature:
    - python lots_signature_scheme.py lots_verify message.txt public_key.lots signature.lots
"""

import os
import sys
import hashlib

KEY_SIZE = 512
HASH_SIZE = 64


def sha512(data):
    """Compute SHA-512 hash using OpenSSL"""
    return hashlib.sha512(data).digest()



def generate_keys():
    """Generates and stores a new Lamport public/private key pair."""
    private_key_0 = [os.urandom(HASH_SIZE) for p in range(KEY_SIZE)]  #Used if i-th bit is 0 in hashed message
    private_key_1 = [os.urandom(HASH_SIZE) for p in range(KEY_SIZE)]  #used for 1 bits in the hashed message


    #Hashing the private keys using SHA-512 to generate the public keys
    public_key_0 = [sha512(k) for k in private_key_0]
    public_key_1 = [sha512(k) for k in private_key_1]

    #For each bit contatonate both 64-byte private keys together
    with open("private_key.lots", "wb") as f:
        for k0, k1 in zip(private_key_0, private_key_1):
            f.write(k0 + k1)
    #Writes the public keys in the file
    with open("public_key.lots", "wb") as f:
        for pk0 in public_key_0:
            f.write(pk0)
        for pk1 in public_key_1:
            f.write(pk1)


def get_bit(message_hash, i):
    """Extracts the i-th bit from the SHA-512 hash."""
    byte_index = i // 8  #Finds the byte that holds the bit
    bit_position = 7 - (i % 8)  # Find the bit position within the byte
    bit = (message_hash[byte_index] >> bit_position) & 1  # Extract the bit
    return bit


def sign_message(message_file, private_key_file):
    """Signs a message using a Lamport one-time signature."""

    #Reads message file and and hashes it
    with open(message_file, "rb") as f:
        message_hash = sha512(f.read())

    #Load the private key
    with open(private_key_file, "rb") as f:
        private_key = f.read()

    signature = []
    #Iterat over each bit of the hashed message
    for i in range(KEY_SIZE):
        bit = get_bit(message_hash, i)
        #Selects the corresponding private key value based on the bit value
        sig_part = private_key[(2 * i + bit) * HASH_SIZE:(2 * i + bit + 1) * HASH_SIZE]
        signature.append(sig_part)

    with open("signature.lots", "wb") as f:
        for sig in signature:
            f.write(sig)


def verify_signature(message_file, public_key_file, signature_file):
    """Verifies a Lamport one-time signature."""

    #Read message, public key, and signature files
    with open(message_file, "rb") as f:
        message_hash = sha512(f.read())
    with open(public_key_file, "rb") as f:
        public_key = f.read()
    with open(signature_file, "rb") as f:
        signature = f.read()

    #Loop through each of the 512 bits of message_hash
    for i in range(KEY_SIZE):
        bit = bit = get_bit(message_hash, i)
        #Extracts the corresonding part of the signature
        sig_part = signature[i * HASH_SIZE:(i + 1) * HASH_SIZE]
        
        #Extraxts the expected hash value of the private key used for signing the bit
        expected_hash = public_key[(bit * KEY_SIZE + i) * HASH_SIZE:(bit * KEY_SIZE + i + 1) * HASH_SIZE]
        if sha512(sig_part) != expected_hash:
            print("INVALID")
            return
    print("VALID")

#Command line interface
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: lots_genkeys | lots_sign <message> <private_key.lots> | lots_verify <message> <public_key.lots> <signature.lots>")
        sys.exit(1)
    
    command = sys.argv[1]
    if command == "lots_genkeys":
        generate_keys()
    elif command == "lots_sign" and len(sys.argv) == 4:
        sign_message(sys.argv[2], sys.argv[3])
    elif command == "lots_verify" and len(sys.argv) == 5:
        verify_signature(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print("Invalid command or arguments.")
        sys.exit(1)