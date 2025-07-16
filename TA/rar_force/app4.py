import subprocess
import os
import sys
from datetime import datetime
import itertools
import string
from tqdm import tqdm
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp

# Configuration
RAR_LOG = 'rar_passwords.log'
FLAG3_RAR = 'flag3.rar'
BASE_FLAG = '~q*/:|qs~;qs|'

# Performance settings
MAX_THREADS = min(32, mp.cpu_count() * 4)  # Aggressive threading
BATCH_SIZE = 1000
TIMEOUT = 5  # seconds per password test

class RarLogger:
    def __init__(self):
        self.rar_log = None
        self.lock = threading.Lock()
        self.initialize_logs()
        
    def initialize_logs(self):
        try:
            self.rar_log = open(RAR_LOG, 'a')
            self.write_log_header()
        except Exception as e:
            print(f"Failed to initialize logs: {e}", file=sys.stderr)
            sys.exit(1)
    
    def write_log_header(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.rar_log.write(f"\n\n=== New Optimized Bruteforce Session {timestamp} ===\n")
        self.rar_log.flush()
    
    def log(self, message, print_console=True):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with self.lock:
                self.rar_log.write(f"[{timestamp}] {message}\n")
                self.rar_log.flush()
                
            if print_console:
                print(message)
        except Exception as e:
            print(f"Logging failed: {e}", file=sys.stderr)
    
    def close(self):
        try:
            if self.rar_log:
                self.rar_log.close()
        except:
            pass

# Global variables for thread communication
found_password = None
stop_search = threading.Event()

def test_rar_password_batch(passwords):
    """Test multiple passwords efficiently"""
    global found_password, stop_search
    
    for password in passwords:
        if stop_search.is_set():
            return None
            
        try:
            # Use faster 7z if available, fallback to unrar
            cmd = ['7z', 't', f'-p{password}', FLAG3_RAR]
            result = subprocess.run(
                cmd,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                text=True,
                timeout=TIMEOUT
            )
            
            if result.returncode == 0:
                found_password = password
                stop_search.set()
                return password
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Try unrar if 7z fails or times out
            try:
                cmd = ['unrar', 't', f'-p{password}', FLAG3_RAR]
                result = subprocess.run(
                    cmd,
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    text=True,
                    timeout=TIMEOUT
                )
                
                if result.returncode == 0:
                    found_password = password
                    stop_search.set()
                    return password
                    
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                continue
        except Exception:
            continue
    
    return None

def generate_smart_passwords():
    """Generate passwords in order of likelihood"""
    
    # 1. PRIORITY: CTF Flag patterns based on previous flag
    # Previous: flag{mult1_st4g3_c0mpl3t3}
    ctf_patterns = [
        # Direct stage progression patterns
        'flag{second_stage_completed}',
        'flag{stage2_completed}',
        'flag{st4g32_c0mpl3t3d}',
        'flag{s3c0nd_st4g3_c0mpl3t3d}',
        'FLAG{second_stage_completed}',
        'FLAG{stage2_completed}',
        'FLAG{st4g32_c0mpl3t3d}',
        'FLAG{s3c0nd_st4g3_c0mpl3t3d}',
        'fl4g{second_stage_completed}',
        'fl4g{stage2_completed}',
        'fl4g{st4g32_c0mpl3t3d}',
        'fl4g{s3c0nd_st4g3_c0mpl3t3d}',
        'FL4G{second_stage_completed}',
        'FL4G{stage2_completed}',
        'FL4G{st4g32_c0mpl3t3d}',
        'FL4G{s3c0nd_st4g3_c0mpl3t3d}',
        'second_stage_completed',
        'stage2_completed',
        'st4g32_c0mpl3t3d',
        's3c0nd_st4g3_c0mpl3t3d',
        'second_stage',
        'stage2',
        'st4g32',
        's3c0nd_st4g3',
        'second_stage_flag',
        'stage2_flag',
        'st4g32_flag',
        's3c0nd_st4g3_flag',
        'second_stage_ctf',
        'stage2_ctf',
        'st4g32_ctf',
        's3c0nd_st4g3_ctf',
        'second_stage_flag3',
        'stage2_flag3',
        'st4g32_flag3',
        's3c0nd_st4g3_flag3',
        'second_stage_flag3_completed',
        'stage2_flag3_completed',
        'st4g32_flag3_completed',
        's3c0nd_st4g3_flag3_completed',
    ]
    
    # 2. Base flag variations
    variations = generate_variations(BASE_FLAG)
    for var in variations:
        if 4 <= len(var) <= 12:
            yield var
    
    # 3. Dictionary-based generation
    dict_words = [
        'admin', 'user', 'test', 'guest', 'root', 'flag', 'ctf', 'challenge',
        'crack', 'hack', 'pass', 'key', 'code', 'file', 'data', 'info',
        'temp', 'demo', 'sample', 'example', 'default', 'public', 'private'
    ]
    
    for word in dict_words:
        for suffix in ['', '1', '12', '123', '1234', '!', '@', '#', '2024', '2025']:
            for prefix in ['', '1', '12', '123', 'admin', 'test']:
                pwd = prefix + word + suffix
                if 4 <= len(pwd) <= 12:
                    yield pwd
    
    # 4. Pattern-based generation (most efficient brute force)
    # Start with shorter, more likely patterns
    patterns = [
        # Length 4-6: Numbers + letters
        (string.digits + string.ascii_lowercase, 4, 6),
        # Length 4-7: Alphanumeric
        (string.ascii_letters + string.digits, 4, 7),
        # Length 4-8: Common symbols
        (string.ascii_letters + string.digits + '!@#$%^&*', 4, 8),
    ]
    
    for charset, min_len, max_len in patterns:
        for length in range(min_len, min_len + 3):  # Limit to prevent explosion
            for pwd in itertools.product(charset, repeat=length):
                if stop_search.is_set():
                    return
                yield ''.join(pwd)

def generate_variations(base_flag):
    """Generate variations of the base flag"""
    variations = set()
    
    # Standard variations
    variations.add(base_flag)
    variations.add(f'flag{{{base_flag}}}')
    variations.add(f'FLAG{{{base_flag}}}')
    variations.add(f'ctf{{{base_flag}}}')
    variations.add(f'CTF{{{base_flag}}}')
    variations.add(base_flag[::-1])
    variations.add(base_flag.upper())
    variations.add(base_flag.lower())
    variations.add(base_flag.replace('~', '-'))
    variations.add(base_flag.replace('~', '_'))
    variations.add(base_flag.replace('~', ''))
    variations.add(base_flag.replace('|', 'I'))
    variations.add(base_flag.replace('|', 'l'))
    variations.add(base_flag.replace(':', '.'))
    variations.add(base_flag.replace('*', 'x'))
    
    # ROT13 and simple ciphers
    try:
        variations.add(base_flag.encode('rot13'))
    except:
        pass
    
    return list(variations)

def parallel_crack(logger):
    """Run password cracking with multiple threads"""
    global found_password, stop_search
    
    logger.log(f"Starting optimized crack with {MAX_THREADS} threads...")
    
    password_gen = generate_smart_passwords()
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = set()
        passwords_tested = 0
        
        try:
            # Submit initial batches
            for _ in range(MAX_THREADS * 2):
                batch = list(itertools.islice(password_gen, BATCH_SIZE))
                if not batch:
                    break
                future = executor.submit(test_rar_password_batch, batch)
                futures.add(future)
            
            # Process results and submit new batches
            while futures and not stop_search.is_set():
                # Check completed futures
                for future in as_completed(futures, timeout=1):
                    futures.remove(future)
                    passwords_tested += BATCH_SIZE
                    
                    try:
                        result = future.result()
                        if result:
                            logger.log(f"\nSUCCESS! Password found: {result}")
                            logger.log(f"Tested {passwords_tested} passwords")
                            return result
                    except Exception as e:
                        logger.log(f"Thread error: {e}", print_console=False)
                    
                    # Submit new batch if not stopping
                    if not stop_search.is_set():
                        batch = list(itertools.islice(password_gen, BATCH_SIZE))
                        if batch:
                            new_future = executor.submit(test_rar_password_batch, batch)
                            futures.add(new_future)
                        else:
                            break
                    
                    break  # Only process one completed future per iteration
                
                # Progress update
                if passwords_tested % 10000 == 0:
                    logger.log(f"Tested {passwords_tested} passwords... ({passwords_tested/60:.0f}/min)")
        
        except KeyboardInterrupt:
            logger.log("\nSearch interrupted by user")
            stop_search.set()
    
    return None

def main():
    logger = RarLogger()
    
    # Check if file exists
    if not os.path.exists(FLAG3_RAR):
        logger.log(f"ERROR: {FLAG3_RAR} not found!")
        return
    
    # Check if 7z is available (much faster than unrar)
    try:
        subprocess.run(['7z'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.log("Using 7z for fast extraction (recommended)")
    except FileNotFoundError:
        logger.log("7z not found, using unrar (slower). Install 7zip for better performance.")
    
    try:
        start_time = time.time()
        
        # Run optimized parallel crack
        result = parallel_crack(logger)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        if result:
            logger.log(f"\nCracking completed in {elapsed:.2f} seconds!")
            logger.log(f"Working password: {result}")
        else:
            logger.log(f"\nNo password found after {elapsed:.2f} seconds")
            logger.log("Try expanding the search patterns or using a dictionary attack")

    except KeyboardInterrupt:
        logger.log("\nCracking interrupted by user.")
    except Exception as e:
        logger.log(f"\nCritical error: {str(e)}")
    finally:
        logger.close()

if __name__ == "__main__":
    main()