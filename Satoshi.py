import os
import base64
import hashlib
import pandas as pd
import json
import requests
import subprocess
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from mnemonic import Mnemonic

# Ensure required system packages are installed
try:
    subprocess.run(["pip", "install", "cryptography", "pandas", "mnemonic", "requests", "mempool", "cgminer", "libitum"], check=True)
    print("Dependencies installed successfully.")
except Exception as e:
    print(f"Error installing dependencies: {e}")

# Define token for blockchain
BLOCKCHAIN_TOKEN = "8bd4fa2488614e509a677103b88b95fc"
BLOCKCHAIN_API_URL = "https://api.blockcypher.com/v1/btc/test3/txs/push?token=" + BLOCKCHAIN_TOKEN

# Function to dynamically locate the private key files in the directory
def find_private_key_files(directory, file_names):
    found_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file in file_names:
                found_files.append(os.path.join(root, file))
    return found_files

# Define the names of the private key files
key_file_names = ["privat_key.asc.txt", "privat_key.asc"]

# Search for the key files dynamically in the directory
key_directory = "/mnt/data"
key_file_paths = find_private_key_files(key_directory, key_file_names)

private_key = None
mnemo = Mnemonic("english")

# Function to attempt loading private key from available files
def load_private_key(file_paths):
    for path in file_paths:
        try:
            with open(path, "rb") as file:
                private_key_data = file.read()
                print(f"Loaded private key data from {path}")
                try:
                    # Attempt to deserialize PEM format
                    key = serialization.load_pem_private_key(
                        private_key_data, password=None, backend=default_backend()
                    )
                    print(f"Successfully loaded private key from {path}")
                    return key
                except ValueError:
                    print(f"Failed to decode as PEM. Trying mnemonic from {path}.")
                    # Decode binary to retrieve mnemonic seed
                    mnemonic_phrase = private_key_data.decode('utf-8').strip()
                    if mnemo.check(mnemonic_phrase):
                        seed = mnemo.to_seed(mnemonic_phrase)
                        key = serialization.load_der_private_key(
                            seed, password=None, backend=default_backend()
                        )
                        print(f"Successfully decoded private key using mnemonic from {path}")
                        return key
        except FileNotFoundError:
            print(f"File not found: {path}")
        except Exception as e:
            print(f"Error reading key file {path}: {e}")
    return None

# Load the private key
private_key = load_private_key(key_file_paths)

if private_key:
    print("Private key loaded successfully.")
else:
    print("Failed to load private key from the provided paths.")

# Blockchain setup
GENESIS_WALLET_ADDRESS = "mtfUjd5TA1DbAMtkYksytzHZQbwmUpxNtv"

# Compute dummy secret hash as OpenCL is unavailable
def compute_dummy_secret():
    dummy_data = b"dummy_secret"
    return hashlib.sha256(dummy_data).hexdigest()

GPU_SECRET_HASH = compute_dummy_secret()
print(f"64-Block Dummy Secret Hash: {GPU_SECRET_HASH}")

# Define the genesis block
genesis_block = {
    "Block Number": 0,
    "Block Hash": hashlib.sha256(b"Genesis Block").hexdigest(),
    "Previous Hash": None,
    "Data": "Genesis Block",
    "Nonce": 0,
    "Wallet": GENESIS_WALLET_ADDRESS,
    "Token": BLOCKCHAIN_TOKEN,
    "GPU Secret": GPU_SECRET_HASH
}

# Blockchain list to hold all blocks
blockchain = [genesis_block]

# Add new block to the blockchain
def add_block(data):
    previous_block = blockchain[-1]
    new_block = {
        "Block Number": previous_block["Block Number"] + 1,
        "Previous Hash": previous_block["Block Hash"],
        "Data": data,
        "Nonce": 0,
        "Wallet": GENESIS_WALLET_ADDRESS,
        "Token": BLOCKCHAIN_TOKEN,
        "GPU Secret": GPU_SECRET_HASH
    }
    new_block["Nonce"], new_block["Block Hash"] = compute_proof_of_work(new_block)
    blockchain.append(new_block)
    print(f"Block {new_block['Block Number']} added to the blockchain.")

# Proof-of-Work placeholder
def compute_proof_of_work(block):
    prefix = "0000"
    nonce = 0
    while True:
        block_string = f"{block['Block Number']}{block['Previous Hash']}{block['Data']}{nonce}{block['Wallet']}{block['Token']}{block['GPU Secret']}".encode()
        block_hash = hashlib.sha256(block_string).hexdigest()
        if block_hash.startswith(prefix):
            return nonce, block_hash
        nonce += 1

# Add example blocks
add_block("Block 1 Data")
add_block("Block 2 Data")

# Display the blockchain
blockchain_df = pd.DataFrame(blockchain)
print("Blockchain Explorer View")
print(blockchain_df)

# Sign transaction example
def sign_transaction(transaction_id, private_key):
    print("Signing the transaction using Cryptography module...")
    signature = private_key.sign(
        transaction_id.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Transaction signed successfully.")
    return signature

transaction_id = "063e4efa72323de5fc2b741e25d49baf2d41ed995997a9e357aa28749fd2eb0b"
if private_key:
    try:
        signature = sign_transaction(transaction_id, private_key)
        print(f"Transaction Signature: {signature.hex()}\n")

        # Make the private key available for signing future transactions
        def get_private_key():
            return private_key

        # Broadcast transaction via HTTP API
        transaction_data = {
            "tx": transaction_id,
            "signature": signature.hex()
        }

        print("Broadcasting transaction to Blockchain Testnet API...")
        response = requests.post(BLOCKCHAIN_API_URL, json=transaction_data)

        if response.status_code == 201:
            print("Transaction broadcasted successfully.")
            print("Response:", response.json())
        else:
            print("Failed to broadcast transaction.")
            print("Response Status:", response.status_code)
            print("Response:", response.text)

    except Exception as e:
        print(f"Error signing or broadcasting transaction: {e}")
else:
    print("Private key not available for signing.")
