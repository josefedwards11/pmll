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

# Install required dependencies using pip
try:
    subprocess.run(["pip", "install", "cryptography", "pandas", "mnemonic", "requests", "mempool", "cgminer", "libitum"], check=True)
    print("Dependencies installed successfully.")
except Exception as e:
    print(f"Error installing dependencies: {e}")

# Define the Blockchain API token and endpoint for testnet
BLOCKCHAIN_TOKEN = "8bd4fa2488614e509a677103b88b95fc"
BLOCKCHAIN_API_URL = "https://api.blockcypher.com/v1/btc/test3/txs/push?token=" + BLOCKCHAIN_TOKEN

# Function to find private key files in a directory
def find_private_key_files(directory, file_names):
    found_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file in file_names:
                found_files.append(os.path.join(root, file))
    return found_files

# List of potential private key filenames and directory
key_file_names = ["privat_key.asc.txt", "privat_key.asc"]
key_directory = "/mnt/data"
key_file_paths = find_private_key_files(key_directory, key_file_names)

# Initialize private key and mnemonic manager
private_key = None
mnemo = Mnemonic("english")

# Function to load private key from provided file paths
def load_private_key(file_paths):
    for path in file_paths:
        try:
            with open(path, "rb") as file:
                private_key_data = file.read()
                print(f"Loaded private key data from {path}")
                try:
                    # Attempt to load the key as PEM format
                    key = serialization.load_pem_private_key(
                        private_key_data, password=None, backend=default_backend()
                    )
                    print(f"Successfully loaded private key from {path}")
                    return key
                except ValueError:
                    print(f"Failed to decode as PEM. Trying mnemonic from {path}.")
                    # Handle mnemonic-based keys
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

# Define the genesis wallet address for the blockchain setup
GENESIS_WALLET_ADDRESS = "mtfUjd5TA1DbAMtkYksytzHZQbwmUpxNtv"

# Function to compute a dummy GPU secret hash for simulation
def compute_dummy_secret():
    dummy_data = b"dummy_secret"
    return hashlib.sha256(dummy_data).hexdigest()

# Generate and print the dummy secret hash
GPU_SECRET_HASH = compute_dummy_secret()
print(f"64-Block Dummy Secret Hash: {GPU_SECRET_HASH}")

# Create the genesis block with initial data
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

# Initialize the blockchain with the genesis block
blockchain = [genesis_block]

# Function to add a new block to the blockchain
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

# Proof-of-Work function to simulate mining
def compute_proof_of_work(block):
    prefix = "0000"
    nonce = 0
    while True:
        block_string = f"{block['Block Number']}{block['Previous Hash']}{block['Data']}{nonce}{block['Wallet']}{block['Token']}{block['GPU Secret']}".encode()
        block_hash = hashlib.sha256(block_string).hexdigest()
        if block_hash.startswith(prefix):
            return nonce, block_hash
        nonce += 1

# Add example blocks to the blockchain
add_block("Block 1 Data")
add_block("Block 2 Data")

# Display the blockchain data in a tabular format
blockchain_df = pd.DataFrame(blockchain)
print("Blockchain Explorer View")
print(blockchain_df)

# Function to sign a transaction using the loaded private key
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

# Transaction ID to be signed
transaction_id = "063e4efa72323de5fc2b741e25d49baf2d41ed995997a9e357aa28749fd2eb0b"

# Check if private key is loaded and attempt to sign the transaction
if private_key:
    try:
        signature = sign_transaction(transaction_id, private_key)
        print(f"Transaction Signature: {signature.hex()}\n")

        # Function to retrieve the private key for future use
        def get_private_key():
            return private_key

        # Prepare the transaction data for broadcasting
        transaction_data = {
            "tx": transaction_id,
            "signature": signature.hex()
        }

        # Broadcast the transaction to the blockchain testnet API
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
    print("Private key is available for signing and has signed.")
