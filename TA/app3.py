import subprocess
import hashlib
import os
import sys
from datetime import datetime

# Configuration
LOG_FILE = 'decryption.log'
RAR_LOG = 'rar_passwords.log'
STAGE2_ENC = 'stage2.enc'
FLAG3_RAR = 'flag3.rar'
BASE_FLAG = '~q*/:|qs~;qs|'

class Logger:
    def __init__(self):
        self.log_file = None
        self.rar_log = None
        self.initialize_logs()
        
    def initialize_logs(self):
        try:
            self.log_file = open(LOG_FILE, 'a')
            self.rar_log = open(RAR_LOG, 'a')
            self.write_log_header()
        except Exception as e:
            print(f"Failed to initialize logs: {e}", file=sys.stderr)
            sys.exit(1)
    
    def write_log_header(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_file.write(f"\n\n=== New Session {timestamp} ===\n")
        self.rar_log.write(f"\n\n=== New Session {timestamp} ===\n")
        self.log_file.flush()
        self.rar_log.flush()
    
    def log(self, message, log_type='main', print_console=True):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            if log_type == 'main':
                self.log_file.write(f"[{timestamp}] {message}\n")
                self.log_file.flush()
            elif log_type == 'rar':
                self.rar_log.write(f"[{timestamp}] {message}\n")
                self.rar_log.flush()
            
            if print_console:
                print(message)
        except Exception as e:
            print(f"Logging failed: {e}", file=sys.stderr)
    
    def close(self):
        try:
            if self.log_file:
                self.log_file.close()
            if self.rar_log:
                self.rar_log.close()
        except:
            pass

# Common flag format variations
FLAG_FORMATS = [
    BASE_FLAG,
    f'flag{{{BASE_FLAG}}}',
    f'FLAG{{{BASE_FLAG}}}',
    f'ctf{{{BASE_FLAG}}}',
    f'CTF{{{BASE_FLAG}}}',
    f'{BASE_FLAG}',
    BASE_FLAG[::-1],  # reversed
    BASE_FLAG.upper(),
    BASE_FLAG.lower(),
]

# Common OpenSSL ciphers to try
CIPHERS = [
    'aes-256-cbc', 'aes-192-cbc', 'aes-128-cbc',
    'aes-256-ctr', 'aes-192-ctr', 'aes-128-ctr',
    'aes-256-cfb', 'aes-192-cfb', 'aes-128-cfb',
    'des-ede3', 'des-ede3-cbc',
]

def try_decrypt(logger, password, cipher):
    """Try decrypting stage2.enc with given password and cipher"""
    temp_out = f'temp_dec_{cipher}_{hashlib.md5(password.encode()).hexdigest()[:6]}.bin'
    cmd = [
        'openssl', 'enc', '-d',
        f'-{cipher}',
        '-in', STAGE2_ENC,
        '-out', temp_out,
        '-k', password,
        '-md', 'md5'
    ]
    
    try:
        result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if result.returncode == 0 and os.path.exists(temp_out):
            with open(temp_out, 'rb') as f:
                content = f.read()
            
            if len(content) > 0:
                return content
    except Exception as e:
        logger.log(f"Error decrypting: {e}", print_console=False)
    finally:
        if os.path.exists(temp_out):
            try:
                os.remove(temp_out)
            except:
                pass
    return None

def test_rar_password(logger, password):
    """Test if password can extract flag3.rar"""
    try:
        result = subprocess.run(
            ['unrar', 't', f'-p{password}', FLAG3_RAR],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        return "All OK" in result.stdout
    except FileNotFoundError:
        logger.log("ERROR: 'unrar' command not found. Please install unrar.")
        sys.exit(1)
    except Exception as e:
        logger.log(f"Error testing RAR: {e}", print_console=False)
        return False

def main():
    logger = Logger()
    
    try:
        logger.log("Starting decryption process...")
        logger.log(f"Trying {len(FLAG_FORMATS)} password variations")
        logger.log(f"Testing {len(CIPHERS)} OpenSSL ciphers")

        success = False
        for password in FLAG_FORMATS:
            if success:
                break
                
            logger.log(f"\nTrying password: {password}")
            
            for cipher in CIPHERS:
                if success:
                    break
                    
                logger.log(f"  Testing cipher: {cipher}", print_console=False)
                
                decrypted = try_decrypt(logger, password, cipher)
                if decrypted:
                    logger.log(f"  Successfully decrypted with {cipher}!")
                    
                    # Try the decrypted content as RAR password
                    try:
                        rar_password = decrypted.decode('utf-8').strip()
                        logger.log(f"  Trying as RAR password: {rar_password}")
                        
                        if test_rar_password(logger, rar_password):
                            logger.log("\nSUCCESS! Found working RAR password!")
                            logger.log(f"Password: {rar_password}", 'rar')
                            logger.log(f"Used OpenSSL command: openssl enc -d -{cipher} -in {STAGE2_ENC} -k {password}", 'rar')
                            success = True
                            break
                        
                        # Also try the original password as RAR password
                        if test_rar_password(logger, password):
                            logger.log("\nSUCCESS! Original password works for RAR!")
                            logger.log(f"Password: {password}", 'rar')
                            logger.log(f"Used OpenSSL command: openssl enc -d -{cipher} -in {STAGE2_ENC} -k {password}", 'rar')
                            success = True
                            break
                    
                    except UnicodeDecodeError:
                        # Try raw bytes as password if text decode fails
                        logger.log("  Decrypted content not text, trying raw bytes...", print_console=False)
                        if test_rar_password(logger, decrypted):
                            logger.log("\nSUCCESS! Raw bytes work as RAR password!")
                            logger.log(f"Password: [binary data]", 'rar')
                            logger.log(f"Hex: {decrypted.hex()}", 'rar')
                            logger.log(f"Used OpenSSL command: openssl enc -d -{cipher} -in {STAGE2_ENC} -k {password}", 'rar')
                            success = True
                            break

        if not success:
            logger.log("\nFinished all combinations without success.")
            logger.log("Check decryption.log for details.")

    except Exception as e:
        logger.log(f"\nCritical error: {str(e)}")
        sys.exit(1)
    finally:
        logger.close()

if __name__ == "__main__":
    main()