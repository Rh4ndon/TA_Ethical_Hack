import subprocess
import hashlib
import os
import re
import itertools
import string

input_file = 'stage2.enc'
real_iv = '44db17e0441beba1a6cfa4d1c2f0d912'

# Base flag content
base_flag = '~q*/:|qs~;qs|'

# Generate password variations
def generate_password_variations():
    passwords = []
    
    # Direct variations
    passwords.extend([
        base_flag,
        f'flag{{{base_flag}}}',
        f'flag{base_flag}',
        f'{{{base_flag}}}',
        f'FLAG{{{base_flag}}}',
        f'flag{{{base_flag.upper()}}}',
        f'flag{{{base_flag.lower()}}}',
    ])
    
    # Common CTF flag formats
    prefixes = ['flag{', 'FLAG{', 'ctf{', 'CTF{', '{', '']
    suffixes = ['}', '', '\n', '\r\n']
    
    for prefix in prefixes:
        for suffix in suffixes:
            passwords.append(f'{prefix}{base_flag}{suffix}')
            passwords.append(f'{prefix}{base_flag.upper()}{suffix}')
            passwords.append(f'{prefix}{base_flag.lower()}{suffix}')
    
    # Character substitutions (common in CTF)
    substitutions = {
        '~': ['!', '@', '#', '$', '%', '^', '&', '*', '`'],
        'q': ['Q', '9', '0'],
        '*': ['@', '#', '$', '%', '^', '&', '+'],
        '/': ['\\', '|', '1', 'l', 'I'],
        ':': [';', '!', '1', 'l', 'I'],
        '|': ['1', 'l', 'I', '/', '\\'],
        ';': [':', '!', '1'],
        's': ['S', '$', '5']
    }
    
    # Try single character substitutions
    for i, char in enumerate(base_flag):
        if char in substitutions:
            for sub in substitutions[char]:
                new_flag = base_flag[:i] + sub + base_flag[i+1:]
                passwords.extend([
                    new_flag,
                    f'flag{{{new_flag}}}',
                    f'FLAG{{{new_flag}}}',
                ])
    
    # Try common transformations
    transformations = [
        base_flag.replace('~', '!'),
        base_flag.replace('*', '@'),
        base_flag.replace('/', '\\'),
        base_flag.replace('|', '1'),
        base_flag.replace(';', ':'),
        base_flag.replace(':', ';'),
        base_flag.replace('q', 'Q'),
        base_flag.replace('s', 'S'),
        base_flag.replace('s', '$'),
        base_flag.replace('q', '9'),
        base_flag.replace('|', 'l'),
        base_flag.replace('/', '1'),
    ]
    
    for trans in transformations:
        passwords.extend([
            trans,
            f'flag{{{trans}}}',
            f'FLAG{{{trans}}}',
        ])
    
    # Try reversing
    reversed_flag = base_flag[::-1]
    passwords.extend([
        reversed_flag,
        f'flag{{{reversed_flag}}}',
        f'FLAG{{{reversed_flag}}}',
    ])
    
    # Try with different encodings hints
    encoded_variations = []
    for pwd in [base_flag, f'flag{{{base_flag}}}']:
        try:
            # Try different encodings
            encoded_variations.append(pwd.encode('utf-8').decode('latin-1'))
            encoded_variations.append(pwd.encode('latin-1').decode('utf-8', errors='ignore'))
        except:
            pass
    
    passwords.extend(encoded_variations)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_passwords = []
    for pwd in passwords:
        if pwd not in seen:
            seen.add(pwd)
            unique_passwords.append(pwd)
    
    return unique_passwords

# Generate all password variations
password_list = generate_password_variations()
print(f"Generated {len(password_list)} password variations")

# Get available ciphers
res = subprocess.run(['openssl', 'enc', '-ciphers'], capture_output=True, text=True)
ciphers = set()
for line in res.stdout.splitlines():
    ciphers.update(re.findall(r'\b[a-z0-9-]+\b', line))

# Focus on most common ciphers first, then expand
priority_ciphers = [
    'aes-256-cbc', 'aes-192-cbc', 'aes-128-cbc',
    'aes-256-ecb', 'aes-192-ecb', 'aes-128-ecb',
    'aes-256-ctr', 'aes-192-ctr', 'aes-128-ctr',
    'aes-256-ofb', 'aes-192-ofb', 'aes-128-ofb',
    'aes-256-cfb', 'aes-192-cfb', 'aes-128-cfb',
]

# Add other available AES ciphers
other_aes = [c for c in ciphers if 'aes' in c and c not in priority_ciphers]
target_ciphers = priority_ciphers + other_aes

print(f"Testing {len(target_ciphers)} ciphers with {len(password_list)} passwords each")
print(f"Total combinations to test: {len(target_ciphers) * len(password_list)}")

successful_decryptions = []
attempt_count = 0

for cipher_idx, cipher in enumerate(target_ciphers):
    if cipher not in ciphers:
        continue
        
    print(f"\n[{cipher_idx+1}/{len(target_ciphers)}] Testing cipher: {cipher}")
    
    for pwd_idx, password in enumerate(password_list):
        attempt_count += 1
        out_file = f'stage2_attempt_{attempt_count}.txt'
        
        if attempt_count % 100 == 0:
            print(f"  Progress: {attempt_count}/{len(target_ciphers) * len(password_list)} attempts")
        
        # Generate key for this password
        key_hex = hashlib.sha256(password.encode()).hexdigest()
        
        # Try different approaches
        approaches = []
        
        if cipher.endswith('ecb'):
            approaches.extend([
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-nosalt', '-in', input_file, '-out', out_file, '-k', password],
                ['openssl', 'enc', '-d', f'-{cipher}', '-nosalt', '-in', input_file, '-out', out_file, '-K', key_hex],
            ])
        else:
            approaches.extend([
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-nosalt', '-in', input_file, '-out', out_file, '-k', password],
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-nosalt', '-in', input_file, '-out', out_file, '-k', password, '-iv', real_iv],
                ['openssl', 'enc', '-d', f'-{cipher}', '-nosalt', '-in', input_file, '-out', out_file, '-K', key_hex, '-iv', real_iv],
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-pbkdf2', '-in', input_file, '-out', out_file, '-k', password],
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha1', '-nosalt', '-in', input_file, '-out', out_file, '-k', password],
            ])
        
        success = False
        for approach_idx, cmd in enumerate(approaches):
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                # Check if the output looks valid
                try:
                    with open(out_file, 'rb') as f:
                        content = f.read()
                    
                    # Look for flag patterns or readable text
                    is_likely_valid = False
                    
                    # Check for common flag patterns
                    if b'flag{' in content.lower() or b'ctf{' in content.lower():
                        is_likely_valid = True
                    
                    # Check for readable ASCII content
                    try:
                        text_content = content.decode('utf-8', errors='ignore')
                        readable_chars = sum(1 for c in text_content if c.isprintable())
                        if readable_chars / len(text_content) > 0.7:  # 70% printable characters
                            is_likely_valid = True
                    except:
                        pass
                    
                    # Check for common file headers
                    if content.startswith(b'PK'):  # ZIP file
                        is_likely_valid = True
                    elif content.startswith(b'\x89PNG'):  # PNG file
                        is_likely_valid = True
                    elif content.startswith(b'GIF'):  # GIF file
                        is_likely_valid = True
                    elif content.startswith(b'\xff\xd8'):  # JPEG file
                        is_likely_valid = True
                    
                    if is_likely_valid:
                        print(f"\n*** POTENTIAL SUCCESS ***")
                        print(f"Cipher: {cipher}")
                        print(f"Password: {repr(password)}")
                        print(f"Approach: {approach_idx + 1}")
                        print(f"Output file: {out_file}")
                        
                        # Show file info
                        try:
                            filetype = subprocess.run(['file', out_file], capture_output=True, text=True).stdout
                            print(f"File type: {filetype.strip()}")
                        except:
                            pass
                        
                        # Show content preview
                        print(f"First 100 bytes (hex): {content[:100].hex()}")
                        try:
                            text_preview = content.decode('utf-8', errors='ignore')[:200]
                            print(f"Text preview: {repr(text_preview)}")
                        except:
                            pass
                        
                        successful_decryptions.append((cipher, password, approach_idx + 1, out_file))
                        success = True
                        break
                    
                except Exception as e:
                    print(f"Error analyzing output: {e}")
                
                # Clean up if not successful
                if not success:
                    os.remove(out_file)
            else:
                # Clean up failed attempts
                if os.path.exists(out_file):
                    os.remove(out_file)
        
        if success:
            break  # Move to next cipher after finding success
    
    if successful_decryptions:
        print(f"Found {len(successful_decryptions)} successful decryptions so far")

print(f"\n=== FINAL RESULTS ===")
print(f"Total attempts made: {attempt_count}")
print(f"Successful decryptions: {len(successful_decryptions)}")

for i, (cipher, password, approach, filename) in enumerate(successful_decryptions):
    print(f"\n[{i+1}] SUCCESS:")
    print(f"  Cipher: {cipher}")
    print(f"  Password: {repr(password)}")
    print(f"  Approach: {approach}")
    print(f"  Output file: {filename}")
    
    # Show detailed content
    try:
        with open(filename, 'rb') as f:
            content = f.read()
        
        print(f"  File size: {len(content)} bytes")
        
        # Try to display as text
        try:
            text_content = content.decode('utf-8', errors='ignore')
            if len(text_content) < 500:
                print(f"  Full content: {repr(text_content)}")
            else:
                print(f"  Content preview: {repr(text_content[:500])}...")
        except:
            print(f"  Binary content (first 200 bytes): {content[:200].hex()}")
            
    except Exception as e:
        print(f"  Error reading final content: {e}")

if not successful_decryptions:
    print("\nNo successful decryptions found. Consider:")
    print("1. Verify the input file 'stage2.enc' exists and is correct")
    print("2. Double-check the IV extraction")
    print("3. Try manual variations of the flag format")
    print("4. The encryption might use a different algorithm entirely")

# Additional debugging info
print(f"\nDebugging info:")
print(f"Input file: {input_file}")
print(f"IV used: {real_iv}")
try:
    with open(input_file, 'rb') as f:
        first_32 = f.read(32)
        print(f"Input file first 32 bytes: {first_32.hex()}")
except Exception as e:
    print(f"Error reading input file: {e}")