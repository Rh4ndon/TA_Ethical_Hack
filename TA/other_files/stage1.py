# stage1.py
def confuse(input_str):
    return ''.join(chr(ord(c) ^ 13) for c in input_str[::-1])

def main():
    # This is an obfuscated version of flag1
    data = "q~|6s~|q7\"'|rs"
    print("Welcome to Stage 1.")
    print("Find the correct function and decode the string.")
    
    print("Encoded data:", data)
    print("Decoded data:", confuse(data)) # ~q*/:|qs~;qs|
    print("Original data:", confuse(confuse(data))) # Just for checking

if __name__ == "__main__":
    main()
