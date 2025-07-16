import subprocess
import hashlib
import os
import re

flag1 = '~q*/:|qs~;qs|'  # <-- first flag
input_file = 'stage2.enc'

# IV, extracted from the first 16 bytes of stage2.enc
real_iv = '44db17e0441beba1a6cfa4d1c2f0d912'

# Hash the flag to get a 256-bit key (hex)
key_hex = hashlib.sha256(flag1.encode()).hexdigest()

# Get all available enc ciphers
res = subprocess.run(['openssl', 'enc', '-ciphers'], capture_output=True, text=True)
ciphers = set()
for line in res.stdout.splitlines():
    ciphers.update(re.findall(r'\b[a-z0-9-]+\b', line))

# Filter ciphers for those containing '256'
target_ciphers = sorted([c for c in ciphers if 'aes-256-cbc' in c])

#target_ciphers = sorted([c for c in ciphers])

print(f"Trying these ciphers with a 256-bit key: {', '.join(target_ciphers)}")

for cipher in target_ciphers:
    out_file = f'stage2_{cipher}.txt'
    print(f'Trying {cipher}...')
    if cipher.endswith('ecb'):
        # ECB mode does not use IV
        cmd = [
            'openssl', 'enc', '-d', f'-{cipher}',
            '-md', 'sha256',
            '-nosalt',
            '-in', input_file,
            '-out', out_file,
            '-k', flag1
            #'-pass', 'pass:"' + flag1 + '"',
        ]
    else:
        cmd = [
            'openssl', 'enc', '-d', f'-{cipher}',
            '-md', 'sha256',
            '-nosalt',
            '-in', input_file,
            '-out', out_file,
            '-k', flag1
            #'-pass', 'pass:"' + flag1 + '"',
            #'-iv', real_iv,
        ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"Decryption SUCCESS with {cipher}. Output file: {out_file}")
        # Show file type
        try:
            filetype = subprocess.run(['file', out_file], capture_output=True, text=True).stdout
            print(filetype.strip())
        except Exception:
            pass
    else:
        print(f"Decryption failed with {cipher}: {result.stderr.strip()}")
        if os.path.exists(out_file):
            os.remove(out_file)
