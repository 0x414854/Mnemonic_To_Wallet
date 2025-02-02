import binascii
import hashlib
import hmac
import logging
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
# Create table in DB to get unique mnemonic



GREEN, RED, BRIGHT_GREY, YELLOW, RESET = (
    Colors.GREEN, Colors.RED, Colors.BRIGHTGREY,
    Colors.YELLOW, Colors.RESET
)

load_dotenv()

ALL_LEGACY_BTC_WALLET_DB_FILE = os.getenv("ALL_LEGACY_BTC_DB_WALLET_FILE")
BIP39_FILE = os.getenv("BIP39_FILE")
WALLETS_DB_FILE = os.getenv("WALLETS_DB_FILE")

LOG_FILE = os.getenv("LOG_FILE")
RESULT_FILE = os.getenv("RESULT_FILE")

log_dir = os.path.dirname(LOG_FILE)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

with open(BIP39_FILE, 'r') as file:
    WORDS = file.read().splitlines() 

def create_wallets_table(db_path):
    if os.path.exists(db_path):
        logging.info(f"Database file '{db_path}' already exists.")
    else:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mnemonic TEXT UNIQUE NOT NULL,
                    seed TEXT NOT NULL,
                    master_private_key TEXT NOT NULL,
                    chain_code TEXT NOT NULL,
                    address TEXT NOT NULL
                )
            """)
            conn.commit()
            print(f"{GREEN}Table 'wallets' has been created{RESET}")
            logging.info(f"Database '{db_path}' initialized.")
        except sqlite3.OperationalError as e:
            print(f"{RED}ERROR: Could not create table 'wallets': {e}{RESET}")
            logging.error(f"Could not create table 'wallets': {e}")
        finally:
            conn.close()

def GetUniqueMnemonic(len_seeds):
    len_seed = random.choice(len_seeds)
    while True:
        mnemonic = ' '.join(random.sample(WORDS, len_seed))
        # if mnemonic not in generated_mnemonics:
        #     generated_mnemonics.add(mnemonic)
        return mnemonic

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

def seed_to_master_key(seed):
    key = b"Bitcoin seed"
    hmac_result = hmac.new(key, seed, hashlib.sha512).digest()
    master_private_key = hmac_result[:32]
    chain_code = hmac_result[32:]
    return master_private_key, chain_code

def generate_address_from_private_key(private_key):
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key = b'\x04' + verifying_key.to_string()
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    # Add the network prefix (0x00 for Bitcoin Mainnet)
    prefix = b'\x00'
    prefixed_key = prefix + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(prefixed_key).digest()).digest()[:4]
    final_key = prefixed_key + checksum
    return base58_encode(final_key)

def base58_encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, 'big')
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    padding = len(data) - len(data.lstrip(b'\x00'))
    return '1' * padding + encoded

def is_address_in_db(db_path, address):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        query = "SELECT 1 FROM addresses WHERE address = ? LIMIT 1"
        cursor.execute(query, (address,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return True 
        return False
    except sqlite3.OperationalError as e:
        print(f"{RED}ERROR: SQL Error : {e}{RESET}")
        logging.error(f"ERROR: SQL Error : {e}")
        return False
    except Exception as e:
        print(f"{RED}ERROR: Error checking the address : {e}{RESET}")
        logging.error(f"ERROR: Error checking the address : {e}")
        return False
    
def save_wallets_to_db(mnemonic, seed, master_private_key, chain_code, address):
    conn = sqlite3.connect(WALLETS_DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO wallets (mnemonic, seed, master_private_key, chain_code, address)
            VALUES (?, ?, ?, ?, ?)
        """, (
            mnemonic,
            binascii.hexlify(seed).decode('utf-8'),
            binascii.hexlify(master_private_key).decode('utf-8'),
            binascii.hexlify(chain_code).decode('utf-8'),
            address
        ))
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"{RED}ERROR: Duplicate mnemonic or address. Details : {e}{RESET}")
        logging.error(f"Duplicate mnemonic or address: {mnemonic}")
    finally:
        conn.close()


def save_wallet_info(mnemonic, seed, master_private_key, chain_code, address):
    try:
        with open(RESULT_FILE, 'w') as file:
            file.write(f"Mnemonic : {mnemonic}\n")
            file.write(f"Seed (hex) : {binascii.hexlify(seed).decode('utf-8')}\n")
            file.write(f"Master Private Key : {binascii.hexlify(master_private_key).decode('utf-8')}\n")
            file.write(f"Chain Code : {binascii.hexlify(chain_code).decode('utf-8')}\n")
            file.write(f"Bitcoin Address : {address}\n")
        print(f"{GREEN}Wallet information saved to {RESULT_FILE}.{RESET}")
        logging.info(f"Result found for wallet {address} !")
    except Exception as e:
        print(f"{RED}ERROR: Error saving wallet information : {e}{RESET}")
        logging.error(f"ERROR: Error saving wallet information : {e}")

def main():
    create_wallets_table(WALLETS_DB_FILE)
    len_seeds = [12, 24]
    while True:
        mnemonic = GetUniqueMnemonic(len_seeds)
        print(f"{BRIGHT_GREY}Mnemonic :{RESET} {mnemonic}")
        passphrase = ""

        seed = mnemonic_to_seed(mnemonic, passphrase)
        # print(f"{BRIGHT_GREY}Seed (hex) :{RESET} {binascii.hexlify(seed).decode('utf-8')}")
        master_private_key, chain_code = seed_to_master_key(seed)
        # print(f"{BRIGHT_GREY}Master Private Key :{RESET} {binascii.hexlify(master_private_key).decode('utf-8')}")
        # print(f"{BRIGHT_GREY}Chain Code :{RESET} {binascii.hexlify(chain_code).decode('utf-8')}")
        address = generate_address_from_private_key(master_private_key)
        print(f"{BRIGHT_GREY}Bitcoin Address :{RESET} {address}")

        save_wallets_to_db(mnemonic, seed, master_private_key, chain_code, address)

        if is_address_in_db(ALL_LEGACY_BTC_WALLET_DB_FILE, address):
            print(f"{GREEN}Address found in the database : {address}{RESET}")
            logging.info(f"Address found in the database : {address}")
            save_wallet_info(mnemonic, seed, master_private_key, chain_code, address)
        else:
            print(f"{RED}Address not found in the database : {address}{RESET}")
        


if __name__ == "__main__":
    main()
