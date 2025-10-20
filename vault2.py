from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import argparse
import json
import os
import base64
import getpass
import secrets
import string
import sys
import time
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

# Creating a file to store the encrypted passwords
VAULT_FILE = "vault.json"

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
ITERATIONS = 480000
MAX_FAILED_ATTEMPTS = 5
VERSION = "1.0"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_success(message: str):
    print(f"{Colors.GREEN}{message}{Colors.END}")

def print_error(message: str):
    print(f"{Colors.RED}{message}{Colors.END}", file=sys.stderr)

def print_warning(message: str):
    print(f"{Colors.YELLOW}{message}{Colors.END}")

def print_info(message: str):
    print(f"{Colors.BLUE}{message}{Colors.END}")

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(key: bytes, data: dict) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    plaintext = json.dumps(data).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_data(key: bytes, encrypted: dict) -> dict:
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext = base64.b64decode(encrypted["ciphertext"])
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    except Exception as e:
        raise ValueError("Decryption failed - invalid password or corrupted data")

class VaultManager:
    def __init__(self, vault_file: str = VAULT_FILE):
        self.vault_file = vault_file
        self.vault = None
        self.key = None
    
    def vault_exists(self) -> bool:
        return os.path.exists(self.vault_file)
    
    def initialize_vault(self, master_password: str) -> bool:
        if self.vault_exists():
            print_error("Vault already exists, use 'change-master' to change the password")
            return False
        
        salt = os.urandom(SALT_LENGTH)
        self.key = derive_key(master_password, salt)
        self.vault = {
            "version": VERSION,
            "salt": base64.b64encode(salt).decode(),
            "failed_attempts": 0,
            "iterations": ITERATIONS,
            "entries": {}
        }
        self._save_vault()
        print_success("Vault initialized successfully")
        return True
    
    def unlock_vault(self, master_password: str) -> bool:
        if not self.vault_exists():
            print_error("Vault not found, run 'init' to create one")
            return False
        
        try:
            with open(self.vault_file, 'r') as f:
                self.vault = json.load(f)
        except Exception as e:
            print_error(f"Failed to read vault file: {e}")
            return False
        
        if self.vault.get("failed_attempts", 0) >= MAX_FAILED_ATTEMPTS:
            print_error(f"Vault locked due to {MAX_FAILED_ATTEMPTS} failed attempts")
            print_info("Delete vault.json to reset (all data will be lost)")
            return False
        
        try:
            salt = base64.b64decode(self.vault["salt"])
            self.key = derive_key(master_password, salt)
        except Exception as e:
            print_error(f"Failed to derive key: {e}")
            return False
        
        if self.vault["entries"]:
            try:
                first_entry = list(self.vault["entries"].values())[0]
                decrypt_data(self.key, first_entry)
                self.vault["failed_attempts"] = 0
                self._save_vault()
                return True
            except ValueError:
                self.vault["failed_attempts"] += 1
                self._save_vault()
                remaining = MAX_FAILED_ATTEMPTS - self.vault["failed_attempts"]
                print_error(f"Incorrect password. {remaining} attempts remaining")
                return False
        return True
    
    def _save_vault(self):
        """Save vault with robust file handling for Windows"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                # Creating a temporary file in the same directory
                temp_dir = os.path.dirname(self.vault_file) or '.'
                with tempfile.NamedTemporaryFile(
                    mode='w', 
                    dir=temp_dir, 
                    delete=False,
                    suffix='.tmp'
                ) as temp_file:
                    temp_path = temp_file.name
                    json.dump(self.vault, temp_file, indent=2)
                    temp_file.flush()
                    os.fsync(temp_file.fileno())
                
                # Replace the original file
                if os.path.exists(self.vault_file):
                    os.remove(self.vault_file)
                os.rename(temp_path, self.vault_file)
                break
                
            except PermissionError as e:
                # CleanING up temporary file if it exists
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    print_error(f"Failed to save vault after {max_retries} attempts: {e}")
                    raise
            except Exception as e:
                # Clean up temporary file if it exists
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                print_error(f"Unexpected error saving vault: {e}")
                raise
    
    def add_entry(self, website: str, username: str, password: str):
        if website in self.vault["entries"]:
            print_warning(f"Entry for '{website}' already exists")
            overwrite = input("Overwrite? (yes/no): ").lower()
            if overwrite != 'yes':
                print_info("Operation cancelled")
                return
        
        entry_data = {
            "username": username,
            "password": password,
            "created": time.time(),
            "modified": time.time()
        }
        encrypted_entry = encrypt_data(self.key, entry_data)
        self.vault["entries"][website] = encrypted_entry
        self._save_vault()
        print_success(f"Entry for '{website}' added successfully")
    
    def get_entry(self, website: str) -> Optional[Dict]:
        if website not in self.vault["entries"]:
            print_error(f"No entry found for '{website}'")
            return None
        
        encrypted_entry = self.vault["entries"][website]
        try:
            decrypted = decrypt_data(self.key, encrypted_entry)
            return decrypted
        except ValueError as e:
            print_error(str(e))
            return None
    
    def list_entries(self) -> list:
        return sorted(self.vault["entries"].keys())
    
    def delete_entry(self, website: str) -> bool:
        if website not in self.vault["entries"]:
            print_error(f"No entry found for '{website}'")
            return False
        
        del self.vault["entries"][website]
        self._save_vault()
        print_success(f"Entry for '{website}' deleted successfully")
        return True
    
    def update_entry(self, website: str, username: Optional[str] = None, password: Optional[str] = None) -> bool:
        entry = self.get_entry(website)
        if not entry:
            return False
        
        if username:
            entry["username"] = username
        if password:
            entry["password"] = password
        entry["modified"] = time.time()
        
        encrypted_entry = encrypt_data(self.key, entry)
        self.vault["entries"][website] = encrypted_entry
        self._save_vault()
        print_success(f"Entry for '{website}' updated successfully")
        return True
    
    def change_master_password(self, new_password: str):
        print_info("Re-encrypting vault with new password")
        
        # Decrypt all entries with old key
        decrypted_entries = {}
        for website, encrypted in self.vault["entries"].items():
            decrypted_entries[website] = decrypt_data(self.key, encrypted)
        
        # Generate new salt and key
        new_salt = os.urandom(SALT_LENGTH)
        new_key = derive_key(new_password, new_salt)
        
        # Re-encrypt all entries with new key
        new_entries = {}
        for website, data in decrypted_entries.items():
            new_entries[website] = encrypt_data(new_key, data)
        
        # Update vault
        self.vault["salt"] = base64.b64encode(new_salt).decode()
        self.vault["entries"] = new_entries
        self.vault["failed_attempts"] = 0
        self.key = new_key
        self._save_vault()
        print_success("Master password changed successfully!")

def generate_password(length: int = 16, use_uppercase: bool = True,
                     use_lowercase: bool = True, use_digits: bool = True,
                     use_special: bool = True) -> str:
    #Generate cryptographically secure random password
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    if not characters:
        raise ValueError("At least one character set must be enabled")
    
    password = []
    if use_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_special:
        password.append(secrets.choice(string.punctuation))
    
    # Fill remaining length
    for _ in range(length - len(password)):
        password.append(secrets.choice(characters))
    
    # Shuffle
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def check_password_strength(password: str) -> dict:
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    charset_size = 0
    if has_upper:
        charset_size += 26
    if has_lower:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32
    
    import math
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
  
    if entropy < 50:
        strength = "Weak"
    elif entropy < 70:
        strength = "Moderate"
    elif entropy < 90:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    return {
        "length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digits": has_digit,
        "has_special": has_special,
        "entropy": round(entropy, 1),
        "strength": strength
    }

# CLI Command Handlers
def cmd_init(args):
    manager = VaultManager()
    master_password = getpass.getpass("Create Master Password: ")
    confirm_password = getpass.getpass("Confirm Master Password: ")
    
    if master_password != confirm_password:
        print_error("Passwords don't match!")
        return
    
    if len(master_password) < 8:
        print_error("Master password must be at least 8 characters!")
        return
    
    if manager.initialize_vault(master_password):
        print_success("Vault created successfully! You can now add passwords.")

def cmd_add(args):
    manager = VaultManager()
    
    master_password = getpass.getpass("Master Password: ")
    if not manager.unlock_vault(master_password):
        return
    
    website = input("Website/Service: ").strip()
    username = input("Username/Email: ").strip()
    
    if args.generate:
        password = generate_password(
            length=args.length,
            use_special=not args.no_special
        )
        print_info(f"Generated password: {password}")
    else:
        password = getpass.getpass("Password (Enter to generate): ")
        if not password:
            password = generate_password(length=args.length)
            print_info(f"Generated password: {password}")
    
    manager.add_entry(website, username, password)

def cmd_get(args):
    manager = VaultManager()
    master_password = getpass.getpass("Master Password: ")

    if not manager.unlock_vault(master_password):
        return
    
    entry = manager.get_entry(args.website)
    if entry:
        print(f"\n{Colors.BOLD}Website:{Colors.END} {args.website}")
        print(f"{Colors.BOLD}Username:{Colors.END} {entry['username']}")
        
        if args.show:
            print(f"{Colors.BOLD}Password:{Colors.END} {entry['password']}")
        else:
            print(f"{Colors.BOLD}Password:{Colors.END} {'*' * len(entry['password'])}")
        
        if args.copy:
            try:
                import pyperclip
                pyperclip.copy(entry['password'])
                print_success("Password copied to clipboard!")
            except ImportError:
                print_warning("Install 'pyperclip' for clipboard support")

def cmd_list(args):
    manager = VaultManager()
    
    master_password = getpass.getpass("Master Password: ")
    if not manager.unlock_vault(master_password):
        return
    
    entries = manager.list_entries()
    
    if not entries:
        print_info("No entries stored yet.")
        return
    
    print(f"\n{Colors.BOLD}Stored Credentials ({len(entries)} entries):{Colors.END}")
    
    for i, website in enumerate(entries, 1):
        if args.detailed:
            entry = manager.get_entry(website)
            if entry:
                print(f"{i}. {website} ({entry['username']})")
        else:
            print(f"{i}. {website}")

def cmd_delete(args):
    manager = VaultManager()
    
    master_password = getpass.getpass("Master Password: ")
    if not manager.unlock_vault(master_password):
        return
    
    if not args.force:
        confirm = input(f"Delete '{args.website}'? (yes/no): ").lower()
        if confirm != 'yes':
            print_info("Operation cancelled.")
            return
    
    manager.delete_entry(args.website)

def cmd_update(args):
    manager = VaultManager()
    
    master_password = getpass.getpass("Master Password: ")
    if not manager.unlock_vault(master_password):
        return
    
    username = args.username if args.username else None
    
    if args.generate:
        password = generate_password()
        print_info(f"Generated password: {password}")
    elif args.password:
        password = args.password
    else:
        password = None
    
    manager.update_entry(args.website, username, password)

def cmd_change_master(args):
    manager = VaultManager()
    
    current_password = getpass.getpass("Current Master Password: ")
    if not manager.unlock_vault(current_password):
        return
    
    new_password = getpass.getpass("New Master Password: ")
    confirm_password = getpass.getpass("Confirm New Master Password: ")
    
    if new_password != confirm_password:
        print_error("Passwords don't match!")
        return
    
    if len(new_password) < 8:
        print_error("Master password must be at least 8 characters!")
        return
    
    manager.change_master_password(new_password)

def cmd_generate(args):
    password = generate_password(
        length=args.length,
        use_uppercase=not args.no_uppercase,
        use_lowercase=not args.no_lowercase,
        use_digits=not args.no_digits,
        use_special=not args.no_special
    )
    
    print(f"\n{Colors.BOLD}Generated Password:{Colors.END} {password}")
    
    strength = check_password_strength(password)
    print(f"{Colors.BOLD}Strength:{Colors.END} {strength['strength']} (Entropy: {strength['entropy']} bits)")
    
    if args.copy:
        try:
            import pyperclip
            pyperclip.copy(password)
            print_success("Copied to clipboard!")
        except ImportError:
            print_warning("Install 'pyperclip' for clipboard support")

def cmd_check(args):
    password = getpass.getpass("Enter password to check: ")
    
    analysis = check_password_strength(password)
    
    print(f"\n{Colors.BOLD}performing Password Strength Analysis:{Colors.END}")
    print(f"Length: {analysis['length']} characters")
    print(f"Uppercase: {'✓' if analysis['has_uppercase'] else '✗'}")
    print(f"Lowercase: {'✓' if analysis['has_lowercase'] else '✗'}")
    print(f"Digits: {'✓' if analysis['has_digits'] else '✗'}")
    print(f"Special: {'✓' if analysis['has_special'] else '✗'}")
    print(f"Entropy: {analysis['entropy']} bits")
    print(f"Strength: {analysis['strength']}")

def main():
    parser = argparse.ArgumentParser(
        description="SecureVault - Military-Grade CLI Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    parser_init = subparsers.add_parser('init', help='Initialize new vault')
    parser_init.set_defaults(func=cmd_init)
    
    # Add command
    parser_add = subparsers.add_parser('add', help='Add new credential')
    parser_add.add_argument('--generate', action='store_true', help='Generate password')
    parser_add.add_argument('--length', type=int, default=16, help='Password length')
    parser_add.add_argument('--no-special', action='store_true', help='No special chars')
    parser_add.set_defaults(func=cmd_add)

    # Get command
    parser_get = subparsers.add_parser('get', help='Retrieve credential')
    parser_get.add_argument('website', help='Website/service name')
    parser_get.add_argument('--copy', action='store_true', help='Copy to clipboard')
    parser_get.add_argument('--show', action='store_true', help='Show password')
    parser_get.set_defaults(func=cmd_get)

    # List command
    parser_list = subparsers.add_parser('list', help='List all entries')
    parser_list.add_argument('--detailed', action='store_true', help='Show usernames')
    parser_list.set_defaults(func=cmd_list)
    
    # Delete command
    parser_delete = subparsers.add_parser('delete', help='Delete entry')
    parser_delete.add_argument('website', help='Website/service name')
    parser_delete.add_argument('--force', action='store_true', help='Skip confirmation')
    parser_delete.set_defaults(func=cmd_delete)
    
    # Update command
    parser_update = subparsers.add_parser('update', help='Update entry')
    parser_update.add_argument('website', help='Website/service name')
    parser_update.add_argument('--username', help='New username')
    parser_update.add_argument('--password', help='New password')
    parser_update.add_argument('--generate', action='store_true', help='Generate new password')
    parser_update.set_defaults(func=cmd_update)
    
    # Change-master command
    parser_change_master = subparsers.add_parser('change-master', help='Change master password')
    parser_change_master.set_defaults(func=cmd_change_master)
    
    # Generate command
    parser_generate = subparsers.add_parser('generate', help='Generate password')
    parser_generate.add_argument('--length', type=int, default=16, help='Password length')
    parser_generate.add_argument('--no-uppercase', action='store_true', help='No uppercase letters')
    parser_generate.add_argument('--no-lowercase', action='store_true', help='No lowercase letters')
    parser_generate.add_argument('--no-digits', action='store_true', help='No digits')
    parser_generate.add_argument('--no-special', action='store_true', help='No special characters')
    parser_generate.add_argument('--copy', action='store_true', help='Copy to clipboard')
    parser_generate.set_defaults(func=cmd_generate)
    
    # Check command
    parser_check = subparsers.add_parser('check', help='Check password strength')
    parser_check.set_defaults(func=cmd_check)

    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        try:
            args.func(args)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()