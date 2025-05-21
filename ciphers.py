"""
Enhanced Cipher Library
A comprehensive collection of classical cipher decryption methods with robust input validation.
"""

import string
import re
from typing import Union, Optional


class CipherError(Exception):
    """Custom exception for cipher-related errors."""
    pass


# ==================== SHIFT-BASED CIPHERS ====================

def caesar_cipher(text: str, shift: int) -> str:
    """
    Applies Caesar cipher decryption with the given shift value.
    
    Args:
        text: The ciphertext to decrypt
        shift: Number of positions to shift back (positive or negative)
    
    Returns:
        Decrypted plaintext
    """
    if not isinstance(shift, int):
        raise CipherError(f"Caesar cipher requires an integer shift, got {type(shift).__name__}")
    
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
        else:
            result.append(char)
    
    return ''.join(result)


def rot13_cipher(text: str) -> str:
    """
    Applies ROT13 cipher decryption (Caesar cipher with shift 13).
    
    Args:
        text: The ciphertext to decrypt
    
    Returns:
        Decrypted plaintext
    """
    return caesar_cipher(text, 13)


def atbash_cipher(text: str) -> str:
    """
    Applies Atbash cipher decryption (A=Z, B=Y, C=X, etc.).
    
    Args:
        text: The ciphertext to decrypt
    
    Returns:
        Decrypted plaintext
    """
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr(ord('z') - (ord(char) - ord('a'))))
        elif 'A' <= char <= 'Z':
            result.append(chr(ord('Z') - (ord(char) - ord('A'))))
        else:
            result.append(char)
    
    return ''.join(result)


# ==================== KEYWORD-BASED CIPHERS ====================

def vigenere_cipher(text: str, keyword: str) -> str:
    """
    Applies Vigenère cipher decryption using the provided keyword.
    
    Args:
        text: The ciphertext to decrypt
        keyword: Alphabetic keyword for decryption
    
    Returns:
        Decrypted plaintext
    """
    if not keyword or not keyword.replace(' ', '').isalpha():
        raise CipherError(f"Vigenère cipher requires an alphabetic keyword, got '{keyword}'")
    
    # Clean keyword (remove spaces, convert to lowercase)
    clean_keyword = ''.join(keyword.split()).lower()
    keyword_len = len(clean_keyword)
    keyword_as_int = [ord(k) - ord('a') for k in clean_keyword]
    
    result = []
    keyword_index = 0
    
    for char in text:
        if 'a' <= char <= 'z':
            shift = keyword_as_int[keyword_index % keyword_len]
            result.append(chr(((ord(char) - ord('a') - shift) % 26) + ord('a')))
            keyword_index += 1
        elif 'A' <= char <= 'Z':
            shift = keyword_as_int[keyword_index % keyword_len]
            result.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
            keyword_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def beaufort_cipher(text: str, keyword: str) -> str:
    """
    Applies Beaufort cipher decryption (variant of Vigenère).
    
    Args:
        text: The ciphertext to decrypt
        keyword: Alphabetic keyword for decryption
    
    Returns:
        Decrypted plaintext
    """
    if not keyword or not keyword.replace(' ', '').isalpha():
        raise CipherError(f"Beaufort cipher requires an alphabetic keyword, got '{keyword}'")
    
    clean_keyword = ''.join(keyword.split()).lower()
    keyword_len = len(clean_keyword)
    keyword_as_int = [ord(k) - ord('a') for k in clean_keyword]
    
    result = []
    keyword_index = 0
    
    for char in text:
        if 'a' <= char <= 'z':
            shift = keyword_as_int[keyword_index % keyword_len]
            result.append(chr(((shift - (ord(char) - ord('a'))) % 26) + ord('a')))
            keyword_index += 1
        elif 'A' <= char <= 'Z':
            shift = keyword_as_int[keyword_index % keyword_len]
            result.append(chr(((shift - (ord(char) - ord('A'))) % 26) + ord('A')))
            keyword_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


# ==================== SUBSTITUTION CIPHERS ====================

def simple_substitution_cipher(text: str, alphabet: str) -> str:
    """
    Applies simple substitution cipher decryption using a custom alphabet.
    
    Args:
        text: The ciphertext to decrypt
        alphabet: 26-letter substitution alphabet
    
    Returns:
        Decrypted plaintext
    """
    if not alphabet or len(alphabet) != 26 or not alphabet.isalpha():
        raise CipherError(f"Simple substitution requires a 26-letter alphabetic keyword, got '{alphabet}'")
    
    original_lower = string.ascii_lowercase
    original_upper = string.ascii_uppercase
    substitution_lower = alphabet.lower()
    substitution_upper = alphabet.upper()
    
    # Create translation tables
    lower_mapping = str.maketrans(substitution_lower, original_lower)
    upper_mapping = str.maketrans(substitution_upper, original_upper)
    
    return text.translate(lower_mapping).translate(upper_mapping)


def affine_cipher(text: str, keyword: str) -> str:
    """
    Applies affine cipher decryption using the format "a,b" where ax + b ≡ y (mod 26).
    
    Args:
        text: The ciphertext to decrypt
        keyword: Format "a,b" where a and b are integers, a must be coprime to 26
    
    Returns:
        Decrypted plaintext
    """
    try:
        if ',' not in keyword:
            raise ValueError("Keyword must contain comma separator")
        
        a_str, b_str = keyword.split(',', 1)
        a, b = int(a_str.strip()), int(b_str.strip())
        
        # Check if 'a' is coprime to 26
        if gcd(a, 26) != 1:
            raise CipherError(f"'a' value ({a}) must be coprime to 26")
        
        # Find modular multiplicative inverse of 'a'
        a_inv = mod_inverse(a, 26)
        
    except (ValueError, IndexError):
        raise CipherError(f"Affine cipher requires format 'a,b' with integers, got '{keyword}'")
    
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            y = ord(char) - ord('a')
            x = (a_inv * (y - b)) % 26
            result.append(chr(x + ord('a')))
        elif 'A' <= char <= 'Z':
            y = ord(char) - ord('A')
            x = (a_inv * (y - b)) % 26
            result.append(chr(x + ord('A')))
        else:
            result.append(char)
    
    return ''.join(result)


# ==================== TRANSPOSITION CIPHERS ====================

def reverse_cipher(text: str) -> str:
    """
    Applies reverse cipher decryption (reverses the entire text).
    
    Args:
        text: The ciphertext to decrypt
    
    Returns:
        Decrypted plaintext
    """
    return text[::-1]


def columnar_transposition_cipher(text: str, keyword: str) -> str:
    """
    Applies columnar transposition cipher decryption.
    
    Args:
        text: The ciphertext to decrypt
        keyword: Alphabetic keyword for column ordering
    
    Returns:
        Decrypted plaintext
    """
    if not keyword or not keyword.replace(' ', '').isalpha():
        raise CipherError(f"Columnar transposition requires an alphabetic keyword, got '{keyword}'")
    
    clean_keyword = ''.join(keyword.split()).upper()
    key_length = len(clean_keyword)
    
    # Create column order based on alphabetical sorting of keyword
    sorted_chars = sorted(enumerate(clean_keyword), key=lambda x: x[1])
    column_order = [i for i, _ in sorted_chars]
    
    # Calculate number of rows
    num_rows = len(text) // key_length
    if len(text) % key_length != 0:
        num_rows += 1
    
    # Create grid
    grid = [['' for _ in range(key_length)] for _ in range(num_rows)]
    
    # Fill grid column by column according to sorted order
    text_index = 0
    for col_priority in range(key_length):
        col_index = column_order.index(col_priority)
        for row in range(num_rows):
            if text_index < len(text):
                grid[row][col_index] = text[text_index]
                text_index += 1
    
    # Read grid row by row
    result = []
    for row in grid:
        result.extend(row)
    
    return ''.join(result).rstrip()


def rail_fence_cipher(text: str, keyword: str) -> str:
    """
    Applies rail fence cipher decryption.
    
    Args:
        text: The ciphertext to decrypt
        keyword: Number of rails (integer as string)
    
    Returns:
        Decrypted plaintext
    """
    try:
        num_rails = int(keyword)
        if num_rails < 2:
            raise ValueError("Number of rails must be >= 2")
    except ValueError:
        raise CipherError(f"Rail fence cipher requires a positive integer >= 2, got '{keyword}'")
    
    if len(text) <= num_rails:
        return text
    
    # Create rail pattern
    rails = [[] for _ in range(num_rails)]
    
    # Calculate rail lengths
    cycle_length = 2 * (num_rails - 1)
    full_cycles = len(text) // cycle_length
    remainder = len(text) % cycle_length
    
    # Fill rails
    text_index = 0
    for rail in range(num_rails):
        # Count characters in this rail
        chars_in_rail = full_cycles
        if rail == 0 or rail == num_rails - 1:
            # Top and bottom rails
            if remainder > rail:
                chars_in_rail += 1
        else:
            # Middle rails
            chars_in_rail *= 2
            if remainder > rail:
                chars_in_rail += 1
            if remainder > cycle_length - rail:
                chars_in_rail += 1
        
        # Extract characters for this rail
        for _ in range(chars_in_rail):
            if text_index < len(text):
                rails[rail].append(text[text_index])
                text_index += 1
    
    # Reconstruct original text
    result = [''] * len(text)
    rail_indices = [0] * num_rails
    
    for i in range(len(text)):
        cycle_pos = i % cycle_length
        if cycle_pos < num_rails:
            rail = cycle_pos
        else:
            rail = cycle_length - cycle_pos
        
        if rail_indices[rail] < len(rails[rail]):
            result[i] = rails[rail][rail_indices[rail]]
            rail_indices[rail] += 1
    
    return ''.join(result)


# ==================== HISTORICAL CIPHERS ====================

def playfair_cipher(text: str, keyword: str) -> str:
    """
    Applies Playfair cipher decryption.
    
    Args:
        text: The ciphertext to decrypt (should have even length)
        keyword: Alphabetic keyword for generating the 5x5 grid
    
    Returns:
        Decrypted plaintext
    """
    if not keyword or not keyword.replace(' ', '').isalpha():
        raise CipherError(f"Playfair cipher requires an alphabetic keyword, got '{keyword}'")
    
    # Clean and prepare keyword
    clean_keyword = ''.join(keyword.split()).upper().replace('J', 'I')
    
    # Create 5x5 grid
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
    seen = set()
    grid_chars = []
    
    # Add keyword characters
    for char in clean_keyword:
        if char not in seen and char in alphabet:
            grid_chars.append(char)
            seen.add(char)
    
    # Add remaining alphabet
    for char in alphabet:
        if char not in seen:
            grid_chars.append(char)
    
    # Create position mapping
    char_to_pos = {}
    for i, char in enumerate(grid_chars):
        char_to_pos[char] = (i // 5, i % 5)
    
    # Clean text and prepare for decryption
    clean_text = ''.join(c.upper() for c in text if c.isalpha()).replace('J', 'I')
    
    if len(clean_text) % 2 != 0:
        raise CipherError("Playfair cipher requires even-length text")
    
    # Decrypt pairs
    result = []
    for i in range(0, len(clean_text), 2):
        char1, char2 = clean_text[i], clean_text[i + 1]
        
        if char1 not in char_to_pos or char2 not in char_to_pos:
            result.extend([char1, char2])
            continue
        
        row1, col1 = char_to_pos[char1]
        row2, col2 = char_to_pos[char2]
        
        if row1 == row2:  # Same row
            new_col1 = (col1 - 1) % 5
            new_col2 = (col2 - 1) % 5
            result.append(grid_chars[row1 * 5 + new_col1])
            result.append(grid_chars[row2 * 5 + new_col2])
        elif col1 == col2:  # Same column
            new_row1 = (row1 - 1) % 5
            new_row2 = (row2 - 1) % 5
            result.append(grid_chars[new_row1 * 5 + col1])
            result.append(grid_chars[new_row2 * 5 + col2])
        else:  # Rectangle
            result.append(grid_chars[row1 * 5 + col2])
            result.append(grid_chars[row2 * 5 + col1])
    
    return ''.join(result)


# ==================== UTILITY FUNCTIONS ====================

def gcd(a: int, b: int) -> int:
    """Calculate greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a: int, m: int) -> int:
    """Calculate modular multiplicative inverse."""
    def extended_gcd(a: int, b: int) -> tuple:
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        raise CipherError(f"Modular inverse does not exist for {a} and {m}")
    return (x % m + m) % m


# ==================== MAIN CIPHER APPLICATION FUNCTION ====================

def apply_cipher(ciphertext: str, keyword: str = "", cipher_method: str = "") -> str:
    """
    Applies a specific decryption cipher method using a keyword.
    
    Args:
        ciphertext: The text to decrypt
        keyword: The keyword, number, or parameter for decryption
        cipher_method: The name of the cipher method
    
    Returns:
        The decrypted text or error message
    """
    if not ciphertext:
        return "Error: No ciphertext provided."
    
    cipher_method = cipher_method.lower().replace('_', '').replace('-', '').replace(' ', '')
    
    print(f"Applying '{cipher_method}' cipher with keyword '{keyword}' to text: '{ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}'")
    
    try:
        # Ciphers that don't require keywords
        if cipher_method == 'reverse':
            return reverse_cipher(ciphertext)
        elif cipher_method == 'rot13':
            return rot13_cipher(ciphertext)
        elif cipher_method == 'atbash':
            return atbash_cipher(ciphertext)
        
        # Validate keyword for ciphers that require it
        if not keyword:
            return f"Error: {cipher_method.title()} cipher requires a keyword."
        
        # Apply specific cipher based on method
        if cipher_method == 'caesar':
            try:
                shift = int(keyword)
                return caesar_cipher(ciphertext, shift)
            except ValueError:
                return f"Error: Caesar cipher requires a numeric keyword, got '{keyword}'."
        
        elif cipher_method == 'vigenere':
            return vigenere_cipher(ciphertext, keyword)
        
        elif cipher_method == 'beaufort':
            return beaufort_cipher(ciphertext, keyword)
        
        elif cipher_method in ['simplesubstitution', 'substitution', 'monoalphabetic']:
            return simple_substitution_cipher(ciphertext, keyword)
        
        elif cipher_method == 'affine':
            return affine_cipher(ciphertext, keyword)
        
        elif cipher_method in ['columnartransposition', 'columnar']:
            return columnar_transposition_cipher(ciphertext, keyword)
        
        elif cipher_method in ['railfence', 'zigzag']:
            return rail_fence_cipher(ciphertext, keyword)
        
        elif cipher_method == 'playfair':
            return playfair_cipher(ciphertext, keyword)
        
        else:
            available_ciphers = [
                'caesar', 'rot13', 'atbash', 'vigenere', 'beaufort', 
                'simple_substitution', 'affine', 'reverse', 
                'columnar_transposition', 'rail_fence', 'playfair'
            ]
            return f"Error: Unknown cipher method '{cipher_method}'. Available ciphers: {', '.join(available_ciphers)}"
    
    except CipherError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


# ==================== AUTOMATIC TESTING FUNCTIONS ====================

def parse_keywords(keyword_string: str) -> list:
    """
    Parse comma or newline separated keywords from input string.
    
    Args:
        keyword_string: String containing keywords separated by commas or newlines
    
    Returns:
        List of cleaned keywords
    """
    if not keyword_string:
        return []
    
    # Split by comma or newline and clean up
    keywords = []
    for item in re.split(r'[,\n]', keyword_string):
        cleaned = item.strip()
        if cleaned:
            keywords.append(cleaned)
    
    return keywords


def is_valid_keyword_for_cipher(keyword: str, cipher_method: str) -> bool:
    """
    Check if a keyword is valid for a specific cipher method.
    
    Args:
        keyword: The keyword to validate
        cipher_method: The cipher method name
    
    Returns:
        True if the keyword is valid for the cipher, False otherwise
    """
    cipher_method = cipher_method.lower().replace('_', '').replace('-', '').replace(' ', '')
    
    # Ciphers that don't need keywords
    if cipher_method in ['reverse', 'rot13', 'atbash']:
        return keyword == ""
    
    # Caesar cipher - needs integer
    if cipher_method == 'caesar':
        try:
            int(keyword)
            return True
        except ValueError:
            return False
    
    # Rail fence - needs positive integer >= 2
    if cipher_method in ['railfence', 'zigzag']:
        try:
            num = int(keyword)
            return num >= 2
        except ValueError:
            return False
    
    # Affine cipher - needs "a,b" format where a is coprime to 26
    if cipher_method == 'affine':
        try:
            if ',' not in keyword:
                return False
            a_str, b_str = keyword.split(',', 1)
            a, b = int(a_str.strip()), int(b_str.strip())
            return gcd(a, 26) == 1
        except (ValueError, IndexError):
            return False
    
    # Alphabetic-only ciphers
    if cipher_method in ['vigenere', 'beaufort', 'columnartransposition', 'columnar', 'playfair']:
        return keyword.replace(' ', '').isalpha() and len(keyword.replace(' ', '')) > 0
    
    # Simple substitution - needs exactly 26 unique letters
    if cipher_method in ['simplesubstitution', 'substitution', 'monoalphabetic']:
        clean_keyword = keyword.replace(' ', '')
        return (len(clean_keyword) == 26 and 
                clean_keyword.isalpha() and 
                len(set(clean_keyword.lower())) == 26)
    
    return False


def generate_affine_combinations(keywords: list) -> list:
    """
    Generate valid affine cipher combinations from available keywords.
    
    Args:
        keywords: List of all keywords
    
    Returns:
        List of valid "a,b" combinations for affine cipher
    """
    numbers = []
    for keyword in keywords:
        try:
            num = int(keyword)
            numbers.append(num)
        except ValueError:
            continue
    
    affine_combinations = []
    for a in numbers:
        if gcd(abs(a), 26) == 1:  # a must be coprime to 26
            for b in numbers:
                affine_combinations.append(f"{a},{b}")
    
    return affine_combinations


def generate_substitution_alphabet(keywords: list) -> list:
    """
    Try to generate a 26-letter substitution alphabet from keywords.
    
    Args:
        keywords: List of all keywords
    
    Returns:
        List of valid 26-letter alphabets (likely empty unless specifically provided)
    """
    alphabets = []
    for keyword in keywords:
        clean_keyword = keyword.replace(' ', '')
        if (len(clean_keyword) == 26 and 
            clean_keyword.isalpha() and 
            len(set(clean_keyword.lower())) == 26):
            alphabets.append(keyword)
    
    return alphabets


def test_all_cipher_combinations(ciphertext: str, keyword_string: str) -> list:
    """
    Test all valid cipher and keyword combinations for the given ciphertext.
    
    Args:
        ciphertext: The encrypted text to decrypt
        keyword_string: String containing keywords (comma or newline separated)
    
    Returns:
        List of dictionaries containing test results
    """
    if not ciphertext:
        return [{"error": "No ciphertext provided"}]
    
    keywords = parse_keywords(keyword_string)
    results = []
    
    # Define all available cipher methods
    cipher_methods = [
        'caesar', 'rot13', 'atbash', 'vigenere', 'beaufort',
        'simple_substitution', 'affine', 'reverse', 
        'columnar_transposition', 'rail_fence', 'playfair'
    ]
    
    for cipher_method in cipher_methods:
        print(f"\nTesting {cipher_method.upper()} cipher...")
        
        # Handle ciphers that don't need keywords
        if cipher_method in ['reverse', 'rot13', 'atbash']:
            result = apply_cipher(ciphertext, "", cipher_method)
            results.append({
                'keyword': '',
                'cipher': cipher_method,
                'status': 'Success' if not result.startswith('Error') else 'Error',
                'result': result
            })
            continue
        
        # Generate special combinations for affine cipher
        if cipher_method == 'affine':
            affine_combos = generate_affine_combinations(keywords)
            for combo in affine_combos:
                result = apply_cipher(ciphertext, combo, cipher_method)
                results.append({
                    'keyword': combo,
                    'cipher': cipher_method,
                    'status': 'Success' if not result.startswith('Error') else 'Error',
                    'result': result
                })
            continue
        
        # Generate substitution alphabets
        if cipher_method == 'simple_substitution':
            alphabets = generate_substitution_alphabet(keywords)
            for alphabet in alphabets:
                result = apply_cipher(ciphertext, alphabet, cipher_method)
                results.append({
                    'keyword': alphabet,
                    'cipher': cipher_method,
                    'status': 'Success' if not result.startswith('Error') else 'Error',
                    'result': result
                })
            continue
        
        # Test regular keywords
        for keyword in keywords:
            if is_valid_keyword_for_cipher(keyword, cipher_method):
                result = apply_cipher(ciphertext, keyword, cipher_method)
                results.append({
                    'keyword': keyword,
                    'cipher': cipher_method,
                    'status': 'Success' if not result.startswith('Error') else 'Error',
                    'result': result
                })
    
    return results


def format_results_summary(results: list) -> str:
    """
    Format test results into a readable summary.
    
    Args:
        results: List of test result dictionaries
    
    Returns:
        Formatted string summary
    """
    if not results:
        return "No results to display."
    
    summary = f"CIPHER ANALYSIS SUMMARY\n{'=' * 50}\n"
    summary += f"Total tests run: {len(results)}\n"
    
    success_count = sum(1 for r in results if r.get('status') == 'Success')
    summary += f"Successful decryptions: {success_count}\n"
    summary += f"Failed attempts: {len(results) - success_count}\n\n"
    
    # Group by cipher method
    cipher_groups = {}
    for result in results:
        cipher = result.get('cipher', 'unknown')
        if cipher not in cipher_groups:
            cipher_groups[cipher] = []
        cipher_groups[cipher].append(result)
    
    for cipher, cipher_results in cipher_groups.items():
        summary += f"\n{cipher.upper()} CIPHER ({len(cipher_results)} tests):\n"
        summary += "-" * 40 + "\n"
        
        for result in cipher_results:
            keyword = result.get('keyword', '')
            status = result.get('status', 'Unknown')
            decrypted = result.get('result', '')
            
            keyword_display = f"'{keyword}'" if keyword else "no keyword"
            summary += f"  Keyword: {keyword_display:15} | Status: {status:7} | Result: {decrypted[:50]}\n"
    
    return summary


def run_comprehensive_analysis(ciphertext: str, keyword_string: str, print_summary: bool = True) -> list:
    """
    Run comprehensive cipher analysis and optionally print summary.
    
    Args:
        ciphertext: The encrypted text to analyze
        keyword_string: Keywords to test (comma or newline separated)
        print_summary: Whether to print formatted summary
    
    Returns:
        List of all test results
    """
    print(f"Starting comprehensive cipher analysis...")
    print(f"Ciphertext: {ciphertext[:100]}{'...' if len(ciphertext) > 100 else ''}")
    print(f"Testing with keywords: {keyword_string[:100]}{'...' if len(keyword_string) > 100 else ''}")
    print("\n" + "=" * 60)
    
    results = test_all_cipher_combinations(ciphertext, keyword_string)
    
    if print_summary:
        print("\n" + format_results_summary(results))
    
    return results


# ==================== EXAMPLE USAGE ====================

if __name__ == "__main__":
    # Example from the Deciphenator tool
    sample_ciphertext = """E N E A A M G C J L D B T T S Z J B T G L
S U R S F U Z O J U W O Y X S B O R L S S
T Y I J C N U K R F E M E U F N A C J D
T D F E T L A N D D E R C C V F R F K Y
H N X A S H R A J J N N B J X T Y B D T
L X V T N P B W Z C O Y S D Z W S S H O
A O S S K S G Y H D T Y X A R G G O M D
O L T C C U Z D M O W I I I D Y B K F
D Q F C X S G C S F R Z X S F W G B D R
U A X A F P E C K E Y B I P N F U C B M"""
    
    sample_keywords = "Pyrexia, -10, 10, Urabrask, Infect, Poison"
    
    # Run comprehensive analysis
    results = run_comprehensive_analysis(sample_ciphertext, sample_keywords)
    
    print(f"\n\nDetailed Results ({len(results)} total tests):")
    print("=" * 60)
    for i, result in enumerate(results, 1):
        print(f"{i:2d}. {result['cipher'].upper():20} | {result['keyword']:15} | {result['status']:7} | {result['result'][:60]}")