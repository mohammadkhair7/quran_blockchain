import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import pandas as pd
import os
from tqdm import tqdm
from termcolor import colored

"""
Quran Blockchain Implementation

This script implements a hierarchical blockchain structure for storing the Quran.
It consists of a main chain for suras (chapters) and individual chains for ayas (verses) within each sura.

Key Components:
1. SHA-256 hashing for block integrity
2. Proof of Work (PoW) consensus mechanism
3. RSA encryption for data security
4. Digital signatures for authentication

Blockchain Configuration Parameters:
- Difficulty: Determines the complexity of the PoW puzzle (default: 4)
- Block Structure: Contains index, timestamp, data, previous hash, nonce, and current hash
- Chain Validation: Ensures integrity of the entire blockchain structure

Encryption Algorithms:
- RSA: Used for asymmetric encryption and digital signatures
- SHA-256: Used for hashing blocks and as part of the PoW mechanism

References:
1. Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System.
   https://bitcoin.org/bitcoin.pdf
2. Zheng, Z., Xie, S., Dai, H., Chen, X., & Wang, H. (2017). An Overview of Blockchain Technology: Architecture, Consensus, and Future Trends.
   IEEE International Congress on Big Data (BigData Congress), 557-564.
3. NIST FIPS 180-4: Secure Hash Standard (SHS)
   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
4. NIST FIPS 186-4: Digital Signature Standard (DSS)
   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
"""

"""
Definition: A nonce stands for "number used once" or "number once". It's a special number added to a block during the mining process.
Purpose: The nonce is used to find a valid hash for a block that meets the network's difficulty target. Miners repeatedly try different nonce values until they find one that produces a hash below the target.
Randomness: While often described as "random", the nonce is more accurately characterized as:
A "random or semi-random number" (GeeksforGeeks)
A "special, randomly generated number" (Intellipaat)
A value that miners "randomly choose" and then iterate through systematically (CoinCentral)
Generation process: Miners don't truly generate random nonces. Instead, they:
Start with an initial value (which could be random)
Systematically increment or change the nonce
Test each nonce to see if it produces a valid block hash
Trial and error: Finding the correct nonce involves a process of trial and error. Miners test millions of nonce values per second.
Not predictable: While not purely random, the correct nonce value is not predictable in advance, which is crucial for blockchain security.

"""
class JSONEncoderArabic(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, QuranBlock):
            return self.block_to_dict(obj)
        return super().default(obj)

    @staticmethod
    def block_to_dict(block):
        return {
            'index': block.index,
            'timestamp': block.timestamp,
            'data': block.data,
            'previous_hash': block.previous_hash,
            'nonce': block.nonce,
            'hash': block.hash
        }


class QuranBlock:
    """
    Represents a single block in the Quran blockchain.
    Each block contains data about a sura or an aya, along with metadata for the blockchain structure.
    """

    def __init__(self, index, timestamp, data, previous_hash, nonce=0, hash=None):
        """
        Initialize a new block.

        :param index: The position of the block in the chain
        :param timestamp: The time when the block was created
        :param data: The data stored in the block (sura or aya information)
        :param previous_hash: The hash of the previous block in the chain
        :param nonce: A value used in the mining process (default: 0)
        :param hash: The hash of this block (if None, it will be calculated)
        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()

    def calculate_hash(self):
        """
        Calculate the SHA-256 hash of the block.
        This ensures the integrity of the block's data.

        :return: Hexadecimal representation of the block's hash
        """
        block_dict = {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }
        block_string = json.dumps(block_dict, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def mine_block(self, difficulty):
        """
        Mine the block by finding a hash that starts with the required number of zeros.
        This implements the Proof of Work (PoW) consensus mechanism.

        :param difficulty: The number of leading zeros required in the hash
        """
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

class QuranBlockchain:
    """
    Represents a blockchain for storing Quran data.
    This class is used for both the main sura chain and individual aya chains.
    """

    def __init__(self, difficulty=4):
        """
        Initialize a new blockchain.

        :param difficulty: The mining difficulty (default: 4)
        """
        self.chain = []
        self.difficulty = difficulty
        self.create_genesis_block()
        self.private_key, self.public_key = self.generate_key_pair()

    def create_genesis_block(self):
        """
        Create the first block (genesis block) in the chain.
        This is a special block that doesn't point to a previous block.
        """
        genesis_block = QuranBlock(0, time.time(), "Genesis Block", "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def get_latest_block(self):
        """
        Get the most recent block in the chain.

        :return: The last block in the chain
        """
        return self.chain[-1]

    def add_block(self, data):
        """
        Add a new block to the chain with the given data.

        :param data: The data to be stored in the new block
        """
        previous_block = self.get_latest_block()
        new_block = QuranBlock(len(self.chain), time.time(), data, previous_block.hash)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self, show_progress=False, chain_name="Chain"):
        """
        Verify the integrity of the entire blockchain.

        :param show_progress: Whether to show progress bar
        :param chain_name: Name to display in progress bar
        :return: True if the chain is valid, False otherwise
        """
        chain_range = range(1, len(self.chain))
        if show_progress:
            chain_range = tqdm(chain_range, desc=colored(f"Validating {chain_name}", "cyan"),
                              bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
        
        for i in chain_range:
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                print(colored(f"\n[ERROR] Invalid hash for block {i}", "red"))
                print(colored(f"  Stored hash: {current_block.hash}", "red"))
                print(colored(f"  Calculated hash: {current_block.calculate_hash()}", "red"))
                return False

            if current_block.previous_hash != previous_block.hash:
                print(colored(f"\n[ERROR] Invalid previous_hash for block {i}", "red"))
                return False

            if current_block.hash[:self.difficulty] != "0" * self.difficulty:
                print(colored(f"\n[ERROR] Block {i} hasn't been mined properly", "red"))
                return False

        return True

    def generate_key_pair(self):
        """
        Generate an RSA key pair for encryption and digital signatures.

        :return: A tuple containing the private and public keys
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_data(self, data):
        """
        Encrypt data using the RSA public key.

        :param data: The data to be encrypted
        :return: The encrypted data
        """
        encrypted = self.public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_data(self, encrypted_data):
        """
        Decrypt data using the RSA private key.

        :param encrypted_data: The data to be decrypted
        :return: The decrypted data as a string
        """
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    def sign_data(self, data):
        """
        Sign data using the RSA private key.

        :param data: The data to be signed
        :return: The digital signature
        """
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data, signature):
        """
        Verify a digital signature using the RSA public key.

        :param data: The original data
        :param signature: The signature to verify
        :return: True if the signature is valid, False otherwise
        """
        try:
            self.public_key.verify(
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


class QuranHierarchicalBlockchain:
    def __init__(self, difficulty=4):
        self.difficulty = difficulty
        self.sura_chain = QuranBlockchain(difficulty)
        self.aya_chains = {}

    def add_sura(self, sura_number, sura_name):
        self.sura_chain.add_block({
            'sura_number': sura_number,
            'sura_name': sura_name
        })
        self.aya_chains[sura_number] = QuranBlockchain(self.sura_chain.difficulty)

    def add_aya(self, sura_number, aya_data):
        if sura_number not in self.aya_chains:
            raise ValueError(f"Sura {sura_number} does not exist in the blockchain.")
        self.aya_chains[sura_number].add_block(aya_data)

    def is_valid(self):
        print(colored("\n[VALIDATION] Starting blockchain validation...", "yellow"))
        
        print(colored("\n[STEP 1] Validating Sura chain...", "cyan"))
        if not self.sura_chain.is_chain_valid(show_progress=True, chain_name="Sura Chain"):
            print(colored("[ERROR] Sura chain is invalid", "red"))
            return False
        print(colored("[OK] Sura chain is valid", "green"))
        
        print(colored(f"\n[STEP 2] Validating {len(self.aya_chains)} Aya chains...", "cyan"))
        for sura_number, aya_chain in tqdm(self.aya_chains.items(), 
                                            desc=colored("Validating Aya Chains", "magenta"),
                                            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'):
            if not aya_chain.is_chain_valid(show_progress=False, chain_name=f"Sura {sura_number}"):
                print(colored(f"\n[ERROR] Aya chain for sura {sura_number} is invalid", "red"))
                return False
        
        print(colored("\n[SUCCESS] All chains validated successfully!", "green"))
        return True

    def save_to_file(self, filename):
        data = {
            'difficulty': self.difficulty,
            'sura_chain': [self.block_to_dict(block) for block in self.sura_chain.chain],
            'aya_chains': [
                {
                    'sura_number': sura_number,
                    'chain': [self.block_to_dict(block) for block in aya_chain.chain]
                }
                for sura_number, aya_chain in sorted(self.aya_chains.items())
            ]
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def block_to_dict(block):
        return {
            'index': block.index,
            'timestamp': block.timestamp,
            'data': block.data,
            'previous_hash': block.previous_hash,
            'nonce': block.nonce,
            'hash': block.hash
        }

    @classmethod
    def load_from_file(cls, filename):
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        blockchain = cls(difficulty=data['difficulty'])
        blockchain.sura_chain = QuranBlockchain(difficulty=data['difficulty'])
        blockchain.sura_chain.chain = [cls.dict_to_block(block_data) for block_data in data['sura_chain']]

        for aya_chain_data in data['aya_chains']:
            sura_number = aya_chain_data['sura_number']
            blockchain.aya_chains[sura_number] = QuranBlockchain(difficulty=data['difficulty'])
            blockchain.aya_chains[sura_number].chain = [cls.dict_to_block(block_data) for block_data in
                                                        aya_chain_data['chain']]

        return blockchain

    @staticmethod
    def dict_to_block(block_data):
        return QuranBlock(
            index=block_data['index'],
            timestamp=block_data['timestamp'],
            data=block_data['data'],
            previous_hash=block_data['previous_hash'],
            nonce=block_data['nonce'],
            hash=block_data['hash']
        )

    def load_from_excel(self, file_path):
        print(colored(f"\n[INFO] Loading Excel file: {file_path}", "cyan"))
        try:
            df = pd.read_excel(file_path)
            df = df.sort_values(['sura_number', 'aya_number'])  # Sort the dataframe
            print(colored(f"[INFO] Found {len(df)} rows to process", "cyan"))
        except Exception as e:
            print(colored(f"[ERROR] Failed to load Excel file: {e}", "red"))
            raise

        current_sura = None
        print(colored("\n[PROCESSING] Encrypting and adding blocks to blockchain...", "yellow"))
        
        for _, row in tqdm(df.iterrows(), total=len(df), desc=colored("Blockchain Encryption", "green"), 
                          bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]'):
            sura_number = int(row['sura_number'])
            sura_name = row['sura_name']

            if current_sura != sura_number:
                self.add_sura(sura_number, sura_name)
                current_sura = sura_number

            aya_data = {
                'sura_number': sura_number,
                'aya_number': int(row['aya_number']),
                'aya_text': row['aya_text'],
                'page_number': int(row['page_number']),
                'mekki_madani': row['mekki_madani'],
            }
            self.add_aya(sura_number, aya_data)

        print(colored(f"\n[SUCCESS] Loaded and encrypted {len(df)} verses from the Excel file.", "green"))

    def count_blocks(self):
        sura_blocks = len(self.sura_chain.chain) - 1  # Exclude genesis block
        aya_blocks_per_sura = {
            sura_number: len(chain.chain) - 1  # Exclude genesis block
            for sura_number, chain in self.aya_chains.items()
        }
        total_aya_blocks = sum(aya_blocks_per_sura.values())
        total_blocks = sura_blocks + total_aya_blocks
        return total_blocks, sura_blocks, aya_blocks_per_sura



def print_chain_info(blockchain, chain_name, number_of_chains=3):
    """
    Print information about the first few blocks in the sura chain and the first aya chain.

    :param blockchain: The QuranHierarchicalBlockchain object
    :param chain_name: A name to identify this blockchain in the output
    :param number_of_chains: The number of blocks to print for each chain (default: 3)
    """
    print(f"\n{chain_name} Sura Chain:")
    for i, block in enumerate(blockchain.sura_chain.chain[:number_of_chains]):
        print(f"Block {i}: Hash: {block.hash}..., Previous Hash: {block.previous_hash}...")

    print(f"\n{chain_name} First Aya Chain:")
    first_sura = next(iter(blockchain.aya_chains))
    for i, block in enumerate(blockchain.aya_chains[first_sura].chain[:number_of_chains]):
        print(f"Block {i}: Hash: {block.hash}..., Previous Hash: {block.previous_hash}...")

# Example usage
###################################################
# quran_blockchain = QuranHierarchicalBlockchain()
#
# # # Add Quran suras and ayas
# quran_blockchain.add_sura(1, 'Al-Fatihah')
# quran_blockchain.add_aya(1, {
#     'sura_number': 1,
#     'aya_number': 1,
#     'aya_text': 'In the name of Allah, the Entirely Merciful, the Especially Merciful.',
#     'hizb_number': 1,
#     'juz_number': 1,
#     'page_number': 1,
#     'mekk_madani': 'mekki'
# })
# quran_blockchain.add_aya(1, {
#     'sura_number': 1,
#     'aya_number': 2,
#     'aya_text': '[All] praise is [due] to Allah, Lord of the worlds -',
#     'hizb_number': 1,
#     'juz_number': 1,
#     'page_number': 1,
#     'mekk_madani': 'mekki'
# })
#
# # Add more suras and ayas...
#
# # Verify the chain
# print("Is blockchain valid?", quran_blockchain.is_valid())
#
# # Save the blockchain to a file
# quran_blockchain.save_to_file("quran_hierarchical_blockchain.json")

###################################################

if __name__ == "__main__":
    print(colored("=" * 60, "blue"))
    print(colored("  QURAN BLOCKCHAIN ENCRYPTION TOOL", "blue", attrs=['bold']))
    print(colored("=" * 60, "blue"))

    # Get the input Excel file name
    EXCEL_FILE = "Quran_77432.xlsx"

    try:
        # Create a new blockchain
        print(colored("\n[INFO] Initializing blockchain...", "cyan"))
        quran_blockchain = QuranHierarchicalBlockchain()
        print(colored("[OK] Blockchain initialized with genesis block", "green"))

        # Load data from the Excel file
        quran_blockchain.load_from_excel(EXCEL_FILE)

        # Verify the blockchain
        print(colored("\n[VALIDATION] Verifying blockchain integrity...", "yellow"))
        is_valid = quran_blockchain.is_valid()
        if is_valid:
            print(colored("[OK] Blockchain is valid", "green"))
        else:
            print(colored("[WARNING] Blockchain validation failed!", "red"))

        # Generate the output JSON file name
        json_file = os.path.splitext(EXCEL_FILE)[0] + "_utf8.json"

        # Save the blockchain to a file
        print(colored(f"\n[INFO] Saving blockchain to {json_file}...", "cyan"))
        quran_blockchain.save_to_file(json_file)
        print(colored(f"[SUCCESS] Blockchain saved to {json_file}", "green"))

        ##################################################

        # Print blockchain statistics
        total_blocks, sura_blocks, aya_blocks_per_sura = quran_blockchain.count_blocks()
        
        print(colored("\n" + "=" * 60, "blue"))
        print(colored("  BLOCKCHAIN STATISTICS", "blue", attrs=['bold']))
        print(colored("=" * 60, "blue"))
        print(colored(f"  Total blocks (excluding genesis): {total_blocks}", "white"))
        print(colored(f"  Sura blocks: {sura_blocks}", "white"))
        print(colored(f"  Total aya blocks: {sum(aya_blocks_per_sura.values())}", "white"))
        print(colored(f"  Number of suras: {len(aya_blocks_per_sura)}", "white"))

        # Verify the number of ayas
        if sum(aya_blocks_per_sura.values()) == 6236 and len(aya_blocks_per_sura) == 114:
            print(colored("\n  ✓ Successfully encoded all 6236 ayas across 114 suras!", "green", attrs=['bold']))
        else:
            print(colored("\n  ⚠ Warning: The number of encoded ayas or suras doesn't match the expected values.", "yellow"))
        
        print(colored("=" * 60, "blue"))
        
    except FileNotFoundError:
        print(colored(f"\n[ERROR] Excel file not found: {EXCEL_FILE}", "red"))
    except Exception as e:
        print(colored(f"\n[ERROR] An unexpected error occurred: {e}", "red"))