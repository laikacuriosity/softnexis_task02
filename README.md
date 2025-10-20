**Softnexis Internshipt Task 02 - Secured CLI Password Manager<br>**

A secure and open-source command-line password manager built with Python that uses efficient encryption to protect your credentials. This solution can store passwords, generate strong random passwords, and manage all credentials from a secure encrypted vault.<br>

Features:<br>
Strong Encryption - AES-256-GCM encryption with PBKDF2 key derivation<br>
Cross-Platform - Works on Windows, macOS and Linux<br>
A simple CLI Interface - Employs easy to use commands for all operations<br>
Secure Password Generation - Cryptographically secure random passwords<br>
Password Strength Analysis - Checks entropy and strength of passwords<br>
Clipboard Support - Copy passwords directly to clipboard<br>
Brute-Force Protection - Vault locks after 5 failed attempts<br>
Local Storage - Data privacy is ensured by storing all the passwords and encryptions on the local machine.<br>

Required Prerequisites:<br>

- Python 3.6 or higher<br>
- `cryptography` library<br>

Installation process:<br>

1. Install the cryptography library:<br>
   pip install cryptography<br>

2. Optional: Install clipboard support:<br>
   pip install pyperclip<br>

3. Download the script:<br>
   git clone <repository-url><br>
   cd securevault<br>


Usage:<br>
For the first Time Setup:<br>

Initialize your password vault:<br>
python vault.py init<br>

The user is prompted to create a strong master password (minimum 8 characters).<br>

Managing Passwords:<br>

Add a new password:<br>
python vault.py add<br>

Add with auto-generated password:<br>
python vault.py add --generate<br>

Add with specific requirements:<br>
python vault.py add --generate --length 20 --no-special<br>

List all stored entries:<br>
python vault.py list<br>

List with details:<br>
python vault.py list --detailed<br>

Retrieve a password:<br>
python vault.py get example.com<br>

Show password in clear text:<br>
python vault.py get example.com --show<br>

Copy password to clipboard:<br>
python vault.py get example.com --copy<br>

Update an existing entry:<br>
python vault.py update example.com --username newuser --generate<br>

Delete an entry:<br>
python vault.py delete example.com<br>

Password Tools<br>
Generate a strong password:<br>
python vault.py generate --length 20 --copy<br>

Check password strength:<br>
python vault.py check<br>

Change master password:<br><br>
python vault.py change-master<br>

Command Reference<br>

`init` : Initialize new vault
`add` : Add new credential (options: `--generate`, `--length`, `--no-special`)<br>
`get <website>` : Retrieve credential (options: `--show`, `--copy`)<br>
`list`: List all entries (options: `--detailed`)<br>
`delete <website>` : Delete entry (options: `--force`)<br>
`update <website>` : Update entry (options: `--username`, `--password`, `--generate`)<br>
`change-master` : Change master password <br>
`generate` : Generate password (options: `--length`, `--no-uppercase`, `--no-lowercase`, `--no-digits`, `--no-special`, `--copy`)<br>
`check` : Check password strength <br>

Example Workflow<br>

Initialize vault<br>
python vault.py init<br>

Add important accounts:<br>

python vault.py add --generate<br>
Enter: gmail.com, your.email@gmail.com<br>

python vault.py add<br>
Enter: banking.com, your.username, your_password<br>

python vault.py add --generate --length 24<br>
Enter: social-media.com, your.username<br>

List all entries<br>
python vault.py list --detailed<br>

When you need a password<br>
python vault.py get gmail.com --copy<br>
Password copied to clipboard!<br>

Update a password<br>
python vault.py update banking.com --generate<br>

Password Generation Options<br>

1. 12-character password with only letters and numbers<br>
python vault.py generate --length 12 --no-special<br>

2. 20-character password with all character types<br>
python vault.py generate --length 20<br>

3. Copy generated password to clipboard<br>
python vault.py generate --copy<br>

Encryption Details:<br>
Algorithm: AES-256-GCM (Authenticated Encryption)<br>
Key Derivation: PBKDF2-HMAC-SHA256 with 480,000 iterations<br>
Salt: 16-byte cryptographically secure random salt<br>
Nonce: 12-byte random nonce for each encryption<br>

Security Measures<br>
Master Password Required for all operations<br>
Vault Lockout after 5 failed unlock attempts<br>
No Plaintext Storage - all data encrypted at rest<br>
Secure Memory Handling - keys cleared from memory after use<br>
Tamper Protection - GCM authentication prevents data modification<br>


Troubleshooting:<br>

1. "Module not found" error:<br>
pip install cryptography pyperclip<br>

2. Vault locked due to failed attempts:<br>
Delete `vault.json` and run `init` again (you'll lose all data)<br>

3. File permission errors on Windows:<br>
Run as Administrator or check file/folder permissions<br>

4. Clipboard not working:<br>
Install pyperclip: `pip install pyperclip`<br>

Use the built-in help system:<br>
python vault.py --help<br>
python vault.py add --help<br>

Password Strength Scale:<br>
< 50 bits: Weak<br>
50-70 bits: Moderate<br>  
70-90 bits: Strong<br>
> 90 bits: Very Strong<br>

Disclaimer<br>
This solution is provided for educational and personal use. The author is not responsible for any data loss or security breaches. Always maintain backups of your important data and use strong master passwords.<br>

