import requests
import json
import logging
from web3 import Web3
import time
from colorama import init, Fore, Style
import re

# Initialize Colorama
init(autoreset=True)

# Helper Functions
def is_valid_private_key(private_key):
    # Check if the private key is exactly 64 characters long and contains only hex characters
    return bool(re.fullmatch(r'^[0-9a-fA-F]{64}$', private_key))

def refresh_access_token(refresh_token):
    url = f"https://securetoken.googleapis.com/v1/token?key=AIzaSyDipzN0VRfTPnMGhQ5PSzO27Cxm3DohJGY"

    headers = {
        "Content-Type": "application/json",
    }

    body = json.dumps({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })

    response = requests.post(url, headers=headers, data=body)

    if response.status_code != 200:
        error_response = response.json()
        raise Exception(f"Failed to refresh access token: {error_response['error']}")

    return response.json()

def validate_tx_hash(tx_hash):
    if not isinstance(tx_hash, str) or not tx_hash.startswith('0x') or len(tx_hash) != 66:
        raise ValueError(f"Invalid transaction hash format: {tx_hash}")
    if any(c not in '0123456789abcdefABCDEF' for c in tx_hash[2:]):
        raise ValueError(f"Transaction hash contains invalid characters: {tx_hash}")

def sync_transaction(tx_hash, chain_id, access_token):
    url = "https://hanafuda-backend-app-520478841386.us-central1.run.app/graphql"
    query = """
        mutation SyncEthereumTx($chainId: Int!, $txHash: String!) {
          syncEthereumTx(chainId: $chainId, txHash: $txHash)
        }
    """
    variables = {
        "chainId": chain_id,
        "txHash": tx_hash
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {access_token}"
    }
    
    response = requests.post(url, json={"query": query, "variables": variables}, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to sync transaction: {response.json()}")
    return response.json()

def load_refresh_token_from_file():
    try:
        with open("tokens.json", "r") as token_file:
            tokens = json.load(token_file)
            return tokens[0].get("refresh_token")
    except FileNotFoundError:
        logging.error("File 'tokens.json' not found.")
        print(Fore.RED + Style.BRIGHT + "File 'tokens.json' tidak ditemukan.")
        exit()
    except json.JSONDecodeError:
        logging.error("Error decoding JSON from 'tokens.json'.")
        exit()

# Configuration
RPC_URL = "https://mainnet.base.org"
CONTRACT_ADDRESS = "0xC5bf05cD32a14BFfb705Fb37a9d218895187376c"
AMOUNT_ETH = 0.0000000001
num_transactions = 999999
chain_id = 8453

# Initialize Web3
web3 = Web3(Web3.HTTPProvider(RPC_URL))
if not web3.is_connected():
    print(Fore.RED + "Failed to connect to Ethereum node.")
    exit()

# Load Private Keys
private_keys = [line.strip() for line in open("pvkey.txt") if line.strip()]

# Validate Private Keys
valid_private_keys = []
for key in private_keys:
    if is_valid_private_key(key):
        valid_private_keys.append(key)
    else:
        print(Fore.RED + f"Invalid private key found and skipped: {key[:4]}...{key[-4:]}")

if not valid_private_keys:
    print(Fore.YELLOW + "No valid private keys found. Retrying validation...")
    print(Fore.MAGENTA + "Exiting without sending transactions.")
    exit()  # Exit gracefully if no valid private keys are found

print(Fore.GREEN + f"Found {len(valid_private_keys)} valid private keys.")

# Initialize Nonces
nonces = {}
for key in valid_private_keys:
    try:
        address = web3.eth.account.from_key(key).address
        nonce = web3.eth.get_transaction_count(address)
        nonces[key] = nonce
        print(Fore.CYAN + f"Initialized nonce for address {address[:4]}...{address[-4:]}: {nonce}")
    except Exception as e:
        print(Fore.RED + f"Failed to initialize nonce for private key {key[:4]}...{key[-4:]}: {str(e)}")

# Contract ABI
contract_abi = '''
[
    {
        "constant": false,
        "inputs": [],
        "name": "depositETH",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    }
]
'''

amount_wei = web3.to_wei(AMOUNT_ETH, 'ether')
contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=json.loads(contract_abi))

# Load Refresh Token
refresh_token = load_refresh_token_from_file()

# Main Transaction Loop
if not valid_private_keys:
    print(Fore.YELLOW + "No valid private keys available. Exiting without sending transactions.")
else:
    for i in range(num_transactions):
        for private_key in valid_private_keys:
            from_address = web3.eth.account.from_key(private_key).address
            short_from_address = from_address[:4] + "..." + from_address[-4:]

            try:
                # Refresh Access Token
                access_token_info = refresh_access_token(refresh_token)
                access_token = access_token_info["access_token"]
                refresh_token = access_token_info.get("refresh_token", refresh_token)

                # Build Transaction
                transaction = contract.functions.depositETH().build_transaction({
                    'from': from_address,
                    'value': amount_wei,
                    'gas': 50000,
                    'gasPrice': web3.eth.gas_price,
                    'nonce': nonces[private_key],
                })

                # Sign and Send Transaction
                signed_txn = web3.eth.account.sign_transaction(transaction, private_key=private_key)
                tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)

                # Wait for Transaction Receipt
                tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
                tx_hash_hex = tx_receipt['transactionHash'].hex()

                print(Fore.GREEN + f"Transaction {i + 1} sent from {short_from_address} with hash: {tx_hash_hex}")

                # Validate and Sync Transaction
                validate_tx_hash(tx_hash_hex)
                sync_response = sync_transaction(tx_hash_hex, chain_id, access_token)

                if sync_response.get('data', {}).get('syncEthereumTx'):
                    print(Fore.CYAN + f"Sync {short_from_address} successful with hash: {tx_hash_hex}")
                else:
                    print(Fore.RED + "Sync failed!")

                # Update Nonce
                nonces[private_key] += 1

                time.sleep(1)

            except Exception as e:
                if 'nonce too low' in str(e):
                    print(Fore.RED + f"Nonce too low for {short_from_address}. Fetching the latest nonce...")
                    nonces[private_key] = web3.eth.get_transaction_count(from_address)
                else:
                    print(Fore.RED + f"Error sending transaction from {short_from_address}: {str(e)}")

print(Fore.MAGENTA + "Finished processing.")
