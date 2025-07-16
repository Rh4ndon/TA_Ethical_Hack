import subprocess
import itertools
from concurrent.futures import ThreadPoolExecutor

PASSWORD_FILE = "passwords.txt"
RAR_FILE = "flag3.rar"
MAX_WORKERS = 8

def try_password(password):
    try:
        # Try with 7z first
        cmd = f'7z x -p"{password}" {RAR_FILE} -aoa -otemp_dir'
        res = subprocess.run(cmd, shell=True, 
                           stderr=subprocess.PIPE, 
                           stdout=subprocess.PIPE)
        
        if "Everything is Ok" in res.stdout.decode():
            return password
            
        # Fallback to unrar
        cmd = f'unrar x -p{password} {RAR_FILE}'
        res = subprocess.run(cmd, shell=True,
                           stderr=subprocess.PIPE,
                           stdout=subprocess.PIPE)
        
        if "All OK" in res.stdout.decode():
            return password
            
    except:
        pass
    return None

def generate_mutations(base):
    mutations = set()
    mutations.add(base)
    mutations.add(base.upper())
    mutations.add(base.lower())
    mutations.add(base.replace('e','3'))
    mutations.add(base.replace('a','4'))
    mutations.add(base.replace('o','0'))
    mutations.add(base + '!')
    mutations.add(base + '123')
    return mutations

def main():
    # Load base passwords
    with open(PASSWORD_FILE) as f:
        passwords = set(line.strip() for line in f if line.strip())
    
    # Generate mutations
    enhanced = set()
    for p in passwords:
        enhanced.update(generate_mutations(p))
    
    print(f"Testing {len(enhanced)} password variations...")
    
    # Parallel processing
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = executor.map(try_password, enhanced)
        
        for password, result in zip(enhanced, results):
            if result:
                print(f"\nSUCCESS! Password found: {password}")
                return
    
    print("\nNo password found in dictionary")

if __name__ == "__main__":
    main()