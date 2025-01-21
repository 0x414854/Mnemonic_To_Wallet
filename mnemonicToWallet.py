import hashlib
import hmac
import binascii
import os
import random
import sqlite3
from dotenv import load_dotenv
from ecdsa import SigningKey, SECP256k1
from shadePy import Colors
from tqdm import tqdm

# Add Segwit Address (P2WPKH) & SegWit Wrapped (P2SH-P2WPKH)
# Add other chains
    # ETH
    # SOL
# Save all information in the DB (sqlite)
    # All wallet info (seed, master private key, chain code, address)
    # Seed
# Add Logging
# ✅ Add a check on the generated address against all the addresses
# ✅ Add plusieurs taille de mnemonic 12-24

GREEN, RED, BRIGHT_GREY, YELLOW, RESET = (
    Colors.GREEN, Colors.RED, Colors.BRIGHTGREY,
    Colors.YELLOW, Colors.RESET
)

load_dotenv()

BIP39_FILE = os.getenv("BIP39_FILE")
ALL_LEGACY_BTC_WALLET_DB_FILE = os.getenv("ALL_LEGACY_BTC_DB_WALLET_FILE")
WALLETS_DB_FILE = os.getenv("WALLETS_DB_FILE")

RESULT_FILE = os.getenv("RESULT_FILE")

with open(BIP39_FILE, 'r') as file:
    WORDS = file.read().splitlines()

# Generate the mnemonic
def GetUniqueMnemonic(len_seeds):
    len_seed = random.choice(len_seeds)
    while True:
        mnemonic = ' '.join(random.sample(WORDS, len_seed))
        # if mnemonic not in generated_mnemonics:
        #     generated_mnemonics.add(mnemonic)
        return mnemonic

# Generate the seed
def mnemonic_to_seed(mnemonic, passphrase):
    salt = "mnemonic" + passphrase
    seed = hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic.encode('utf-8'),
        salt.encode('utf-8'),
        2048,
        dklen=64
    )
    return seed

# Generate the Master Private Key and the Chain Code
def seed_to_master_key(seed):
    key = b"Bitcoin seed"
    hmac_result = hmac.new(key, seed, hashlib.sha512).digest()
    master_private_key = hmac_result[:32]  # The first 32 bytes
    chain_code = hmac_result[32:]         # The last 32 bytes
    return master_private_key, chain_code

# Generate the Bitcoin address from the Master Private Key
def generate_address_from_private_key(private_key):
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key = b'\x04' + verifying_key.to_string()
    # SHA-256 hash followed by RIPEMD-160
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    # Add the network prefix (0x00 for Bitcoin Mainnet)
    prefix = b'\x00'
    prefixed_key = prefix + public_key_hash
    # Calculate the checksum (double SHA-256 of the previous data)
    checksum = hashlib.sha256(hashlib.sha256(prefixed_key).digest()).digest()[:4]
    # Add the checksum and encode in Base58
    final_key = prefixed_key + checksum
    return base58_encode(final_key)

def base58_encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, 'big')
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    # Add initial zeros (bytes starting with 0x00)
    padding = len(data) - len(data.lstrip(b'\x00'))
    return '1' * padding + encoded

def is_address_in_db(db_path, address):
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Prepare and execute the SQL query
        query = "SELECT 1 FROM addresses WHERE address = ? LIMIT 1"
        cursor.execute(query, (address,))
        
        # Check if a result was returned
        result = cursor.fetchone()
        
        # Close the connection
        conn.close()
        
        if result:
            return True  # Address found
        return False  # Address not found
    except sqlite3.OperationalError as e:
        print(f"{RED}ERROR: SQL Error : {e}{RESET}")
        return False
    except Exception as e:
        print(f"{RED}ERROR: Error checking the address : {e}{RESET}")
        return False

def save_wallet_info(mnemonic, seed, master_private_key, chain_code, address):
    try:
        with open(RESULT_FILE, 'w') as file:
            file.write(f"Mnemonic : {mnemonic}\n")
            file.write(f"Seed (hex) : {binascii.hexlify(seed).decode('utf-8')}\n")
            file.write(f"Master Private Key : {binascii.hexlify(master_private_key).decode('utf-8')}\n")
            file.write(f"Chain Code : {binascii.hexlify(chain_code).decode('utf-8')}\n")
            file.write(f"Bitcoin Address : {address}\n")
        print(f"{GREEN}Wallet information saved to {RESULT_FILE}.{RESET}")
    except Exception as e:
        print(f"{RED}ERROR: Error saving wallet information : {e}{RESET}")

def main():
    len_seeds = [12, 24]
    while True:
        mnemonic = GetUniqueMnemonic(len_seeds)
        # mnemonic = "orange rain model just very jar pumpkin resource surge pledge dolphin rapid"
        print(f"{BRIGHT_GREY}Mnemonic :{RESET} {mnemonic}")
        passphrase = ""

        # Generate the raw seed
        seed = mnemonic_to_seed(mnemonic, passphrase)
        # print(f"{BRIGHT_GREY}Seed (hex) :{RESET} {binascii.hexlify(seed).decode('utf-8')}")

        # Generate the Master Private Key and the Chain Code
        master_private_key, chain_code = seed_to_master_key(seed)
        # print(f"{BRIGHT_GREY}Master Private Key :{RESET} {binascii.hexlify(master_private_key).decode('utf-8')}")
        # print(f"{BRIGHT_GREY}Chain Code :{RESET} {binascii.hexlify(chain_code).decode('utf-8')}")

        # Generate a Bitcoin address (P2PKH)
        address = generate_address_from_private_key(master_private_key)
        print(f"{BRIGHT_GREY}Bitcoin Address :{RESET} {address}")

        # Check if the address is in the database
        if is_address_in_db(ALL_LEGACY_BTC_WALLET_DB_FILE, address):
            print(f"{GREEN}Address found in the database : {address}{RESET}")
        else:
            print(f"{RED}Address not found in the database : {address}{RESET}")


if __name__ == "__main__":
    main()
