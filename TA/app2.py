import subprocess
import hashlib
import os
import re
import itertools
import string
import binascii
from datetime import datetime

# Logging setup
LOG_FILE = 'decryption_analysis.log'
input_file = 'stage2.enc'
real_iv = '44db17e0441beba1a6cfa4d1c2f0d912'
base_flag = '~q*/:|qs~;qs|'

def log_message(message, print_to_console=True):
    """Log messages to file and optionally print to console"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(LOG_FILE, 'a', encoding='utf-8') as log_file:
        log_file.write(log_entry)
    
    if print_to_console:
        print(message)

def generate_keys_from_password(password):
    """Generate different key derivations from password"""
    keys = []
    
    # Method 1: Direct SHA256 hash
    keys.append(('SHA256', hashlib.sha256(password.encode()).hexdigest()))
    
    # Method 2: MD5 hash (less secure but sometimes used)
    keys.append(('MD5', hashlib.md5(password.encode()).hexdigest()))
    
    # Method 3: SHA1 hash
    keys.append(('SHA1', hashlib.sha1(password.encode()).hexdigest()))
    
    # Method 4: Direct password as hex (if possible)
    try:
        if len(password) == 32:  # Might be hex already
            keys.append(('Direct_Hex', password))
    except:
        pass
    
    # Method 5: Password padded/truncated to 32 bytes, then hex
    padded = password.ljust(32, '\x00')[:32]
    keys.append(('Padded', padded.encode().hex()))
    
    # Method 6: Double hash
    keys.append(('Double_SHA256', hashlib.sha256(hashlib.sha256(password.encode()).digest()).hexdigest()))
    
    # Method 7: Hash with salt (common variations)
    for salt in ['', 'salt', 'ctf', 'flag', password]:
        if salt:
            salted = password + salt
            keys.append((f'SHA256_salt_{salt}', hashlib.sha256(salted.encode()).hexdigest()))
    
    # Method 8: PBKDF2 with different iterations
    try:
        for iterations in [1000, 4096, 10000]:
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'', iterations)
            keys.append((f'PBKDF2_{iterations}', key.hex()))
    except:
        pass
    
    return keys

def try_manual_decryption(password, cipher, key_method, key_hex):
    """Try manual decryption with explicit parameters"""
    results = []
    
    # Read the encrypted file
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    
    # Extract IV from first 16 bytes
    file_iv = encrypted_data[:16].hex()
    ciphertext = encrypted_data[16:]  # Rest is ciphertext
    
    log_message(f"  File IV: {file_iv}", False)
    log_message(f"  Expected IV: {real_iv}", False)
    log_message(f"  Ciphertext length: {len(ciphertext)} bytes", False)
    
    # Try different IV approaches
    ivs_to_try = [
        ('extracted_iv', real_iv),
        ('file_first_16', file_iv),
        ('zero_iv', '0' * 32),
        ('no_iv', None)
    ]
    
    for iv_name, iv_val in ivs_to_try:
        approaches = []
        
        # Different OpenSSL command variations
        if cipher.endswith('ecb'):
            # ECB doesn't use IV
            approaches.extend([
                ['openssl', 'enc', '-d', f'-{cipher}', '-nosalt', '-K', key_hex],
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-nosalt', '-k', password],
                ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'md5', '-nosalt', '-k', password],
            ])
        else:
            if iv_val:
                approaches.extend([
                    ['openssl', 'enc', '-d', f'-{cipher}', '-nosalt', '-K', key_hex, '-iv', iv_val],
                    ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-nosalt', '-k', password, '-iv', iv_val],
                    ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'md5', '-nosalt', '-k', password, '-iv', iv_val],
                    ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha1', '-nosalt', '-k', password, '-iv', iv_val],
                ])
            else:
                approaches.extend([
                    ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'sha256', '-nosalt', '-k', password],
                    ['openssl', 'enc', '-d', f'-{cipher}', '-md', 'md5', '-nosalt', '-k', password],
                    ['openssl', 'enc', '-d', f'-{cipher}', '-pbkdf2', '-k', password],
                ])
        
        for approach_idx, cmd in enumerate(approaches):
            temp_file = f'temp_decrypt_{cipher}_{key_method}_{iv_name}_{approach_idx}.txt'
            
            try:
                # Try with full file first
                full_cmd = cmd + ['-in', input_file, '-out', temp_file]
                result = subprocess.run(full_cmd, capture_output=True, text=True)
                
                if result.returncode == 0 and os.path.exists(temp_file) and os.path.getsize(temp_file) > 0:
                    with open(temp_file, 'rb') as f:
                        content = f.read()
                    
                    results.append({
                        'method': f"{key_method}_{iv_name}_{approach_idx}",
                        'content': content,
                        'command': ' '.join(full_cmd),
                        'file': temp_file
                    })
                    
                    log_message(f"    SUCCESS: {key_method} + {iv_name} + approach {approach_idx}", False)
                    log_message(f"    Content length: {len(content)} bytes", False)
                    log_message(f"    First 50 bytes: {content[:50].hex()}", False)
                    
                    # Check if it looks like readable text
                    try:
                        text = content.decode('utf-8', errors='ignore')
                        readable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
                        log_message(f"    Readable ratio: {readable_ratio:.2f}", False)
                        if readable_ratio > 0.5:
                            log_message(f"    TEXT CONTENT: {repr(text[:200])}", False)
                    except Exception as e:
                        log_message(f"    Error decoding text: {e}", False)
                    
                    # Try interpreting as different formats
                    if content.startswith(b'PK'):
                        log_message("    -> Looks like ZIP file!", False)
                    elif content.startswith(b'\x89PNG'):
                        log_message("    -> Looks like PNG file!", False)
                    elif b'flag{' in content.lower():
                        log_message("    -> Contains flag pattern!", False)
                    elif b'ctf{' in content.lower():
                        log_message("    -> Contains CTF flag pattern!", False)
                else:
                    # Clean up failed attempts
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                
            except Exception as e:
                log_message(f"    ERROR: {e}", False)
                if os.path.exists(temp_file):
                    os.remove(temp_file)
    
    return results

def main():
    # Initialize log file
    with open(LOG_FILE, 'w', encoding='utf-8') as log_file:
        log_file.write(f"Decryption Analysis Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # Test with the most promising results from your log
    promising_combinations = [
        ('aes-256-ctr', base_flag),
        ('aes-192-ctr', base_flag),
        ('aes-128-ctr', base_flag),
        ('aes-256-ofb', base_flag),
        ('aes-192-ofb', base_flag),
        ('aes-128-ofb', base_flag),
        ('aes-256-cfb', base_flag),
        ('aes-192-cfb', base_flag),
        ('aes-128-cfb', base_flag),
        ('aes-192-cfb8', f'flag{{{base_flag}}}'),  # This one used different password
    ]

    log_message(f"Testing {len(promising_combinations)} promising combinations with detailed key analysis...")
    log_message(f"Input file: {input_file}")

    # Check input file
    try:
        with open(input_file, 'rb') as f:
            file_content = f.read()
            log_message(f"Input file size: {len(file_content)} bytes")
            log_message(f"First 32 bytes: {file_content[:32].hex()}")
    except Exception as e:
        log_message(f"Error reading input file: {e}")
        exit(1)

    all_results = []

    for cipher, password in promising_combinations:
        log_message(f"\n=== Testing {cipher} with password: {repr(password)} ===")
        
        # Generate different key derivations
        key_variations = generate_keys_from_password(password)
        
        for key_method, key_hex in key_variations:
            log_message(f"\n  Key method: {key_method}")
            log_message(f"  Key: {key_hex}")
            
            results = try_manual_decryption(password, cipher, key_method, key_hex)
            all_results.extend(results)

    log_message(f"\n=== FINAL ANALYSIS ===")
    log_message(f"Total successful decryptions: {len(all_results)}")

    # Group by content to find unique results
    unique_contents = {}
    for result in all_results:
        content_hash = hashlib.sha256(result['content']).hexdigest()
        if content_hash not in unique_contents:
            unique_contents[content_hash] = []
        unique_contents[content_hash].append(result)

    log_message(f"Unique content hashes: {len(unique_contents)}")

    for i, (content_hash, results) in enumerate(unique_contents.items()):
        log_message(f"\n--- Unique Content #{i+1} ---")
        log_message(f"Found in {len(results)} different combinations")
        log_message(f"Content hash: {content_hash}")
        
        content = results[0]['content']
        log_message(f"Size: {len(content)} bytes")
        log_message(f"Hex: {content.hex()}")
        
        # Try different interpretations
        interpretations = []
        
        # Try as text
        try:
            text = content.decode('utf-8', errors='ignore')
            readable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
            if readable_ratio > 0.3:
                interpretations.append(f"UTF-8 text ({readable_ratio:.2f} readable): {repr(text)}")
        except:
            pass
        
        # Try as hex-encoded data
        try:
            if len(content) % 2 == 0:
                hex_decoded = bytes.fromhex(content.decode('ascii'))
                interpretations.append(f"Hex-decoded ({len(hex_decoded)} bytes): {hex_decoded[:50].hex()}")
                
                # Check if hex-decoded looks like text
                try:
                    hex_text = hex_decoded.decode('utf-8', errors='ignore')
                    hex_readable = sum(1 for c in hex_text if c.isprintable()) / len(hex_text) if hex_text else 0
                    if hex_readable > 0.5:
                        interpretations.append(f"Hex-decoded text: {repr(hex_text)}")
                except:
                    pass
        except:
            pass
        
        # Try as base64
        try:
            import base64
            b64_decoded = base64.b64decode(content, validate=True)
            interpretations.append(f"Base64-decoded ({len(b64_decoded)} bytes): {b64_decoded[:50].hex()}")
            
            # Check if base64-decoded looks like text
            try:
                b64_text = b64_decoded.decode('utf-8', errors='ignore')
                b64_readable = sum(1 for c in b64_text if c.isprintable()) / len(b64_text) if b64_text else 0
                if b64_readable > 0.5:
                    interpretations.append(f"Base64-decoded text: {repr(b64_text)}")
            except:
                pass
        except:
            pass
        
        # Try XOR with common keys
        for xor_key in [0x42, 0x13, 0x37, 0x5A, 0xFF]:
            try:
                xor_result = bytes(b ^ xor_key for b in content)
                xor_text = xor_result.decode('utf-8', errors='ignore')
                xor_readable = sum(1 for c in xor_text if c.isprintable()) / len(xor_text) if xor_text else 0
                if xor_readable > 0.7:
                    interpretations.append(f"XOR with {xor_key:02x}: {repr(xor_text[:100])}")
            except:
                pass
        
        # Show all interpretations
        for interp in interpretations:
            log_message(f"  {interp}")
        
        if not interpretations:
            log_message("  No readable interpretations found")
        
        # Show some example commands that produced this result
        log_message(f"  Example command: {results[0]['command']}")
        log_message(f"  Method: {results[0]['method']}")

    log_message(f"\n=== RECOMMENDATIONS ===")
    log_message("1. Check if any of the unique contents above contain readable text or flags")
    log_message("2. Try saving the binary content as files and analyzing with `file` command")
    log_message("3. The 54-byte length suggests we might be getting a partial decrypt")
    log_message("4. Consider that the content might be encrypted again (nested encryption)")
    log_message("5. Try different character encodings (latin1, cp1252, etc.)")

    log_message("\nAnalysis complete. All results logged to " + LOG_FILE)

if __name__ == "__main__":
    main()