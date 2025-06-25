import base64
import codecs
import binascii
import urllib.parse
import re
from functools import wraps
from .utils import is_printable_ratio
import base91

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '-..-.': '/', '-....-': '-', '-.--.': '(', '-.--.-': ')', '.----.': "'",
    '-...-': '=', '.-.-.': '+', '---...': ':', '-.-.-.': ';', '..--.-': '_',
    '.-..-.': '"', '...-..-': '$', '.--.-.': '@', '...---...': 'SOS'
}

def safe_decode(func):
    @wraps(func)
    def wrapper(data):
        try:
            return func(data) or []
        except Exception:
            return []
    return wrapper

def _bytes_to_str(decoded_bytes):
    for encoding in ('utf-8', 'latin1'):
        try:
            return decoded_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return repr(decoded_bytes)

def _add_padding(data_bytes):
    missing_padding = (-len(data_bytes)) % 4
    if missing_padding:
        data_bytes += b'=' * missing_padding
    return data_bytes

@safe_decode
def decode_base64(data):
    results = []
    data_bytes = data.encode() if isinstance(data, str) else data
    try:
        decoded = base64.b64decode(data_bytes, validate=True)
        results.append(('Base64 standard', _bytes_to_str(decoded)))
    except (binascii.Error, ValueError):
        pass
    try:
        padded_data = _add_padding(data_bytes.replace(b'-', b'+').replace(b'_', b'/'))
        decoded = base64.b64decode(padded_data, validate=True)
        results.append(('Base64 URL-safe', _bytes_to_str(decoded)))
    except (binascii.Error, ValueError):
        pass
    return results

@safe_decode
def decode_base32(data):
    clean_data = re.sub(r'\s+', '', data).upper()
    padded_data = clean_data + '=' * ((8 - len(clean_data) % 8) % 8)
    decoded = base64.b32decode(padded_data, casefold=True)
    return [('Base32', _bytes_to_str(decoded))]

@safe_decode
def decode_base85(data):
    results = []
    decoded = base64.a85decode(data, adobe=False, ignorechars=b'\n\r\t ')
    results.append(('Base85', _bytes_to_str(decoded)))
    decoded = base64.b85decode(data, ignorechars=b'\n\r\t ')
    results.append(('Base85 (b85)', _bytes_to_str(decoded)))
    return results

@safe_decode
def decode_base91(data):
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    )
    try:
        import base91
        decoded = base91.decode(data)
        return [('Base91', _bytes_to_str(decoded))]
    except Exception:
        return []

@safe_decode
def decode_base58(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    def b58decode(s):
        num = 0
        for char in s:
            num *= 58
            if char not in alphabet:
                raise ValueError('Invalid character for base58')
            num += alphabet.index(char)
        combined = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
        n_pad = len(s) - len(s.lstrip('1'))
        return b'\x00' * n_pad + combined
    decoded = b58decode(data)
    return [('Base58', _bytes_to_str(decoded))]

@safe_decode
def decode_hex(data):
    clean_data = re.sub(r'0x|\\x|\s+', '', data)
    decoded = bytes.fromhex(clean_data)
    return [('Hex', _bytes_to_str(decoded))]

@safe_decode
def decode_rot13(data):
    decoded = codecs.decode(data, 'rot_13')
    return [('ROT13', decoded)]

@safe_decode
def decode_url(data):
    decoded = urllib.parse.unquote(data)
    return [('URL Decode', decoded)]

@safe_decode
def decode_url_unicode(data):
    def replace_unicode(match):
        codepoint = int(match.group(1), 16)
        return chr(codepoint)
    decoded = re.sub(r'%u([0-9A-Fa-f]{4})', replace_unicode, data)
    decoded = urllib.parse.unquote(decoded)
    return [('URL Unicode Decode', decoded)]

@safe_decode
def decode_xor(data):
    results = []
    raw_bytes = None
    try:
        clean_data = re.sub(r'\s+', '', data)
        raw_bytes = bytes.fromhex(clean_data)
    except Exception:
        try:
            raw_bytes = base64.b64decode(data)
        except Exception:
            raw_bytes = data.encode('latin1', errors='ignore')
    for key in range(256):
        xord = bytes(b ^ key for b in raw_bytes)
        try:
            decoded_str = xord.decode('utf-8')
            if is_printable_ratio(decoded_str) > 0.85:
                results.append((f'XOR with key 0x{key:02X}', decoded_str))
        except UnicodeDecodeError:
            continue
        if len(results) >= 5:
            break
    return results

@safe_decode
def decode_binary(data):
    bits = ''.join(re.findall(r'[01]{8}', data))
    if not bits:
        return []
    decoded_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    decoded_str = _bytes_to_str(decoded_bytes)
    return [('Binary', decoded_str)]

@safe_decode
def decode_octal(data):
    octs = ''.join(re.findall(r'[0-7]{3}', data))
    if not octs:
        return []
    decoded_bytes = bytes(int(octs[i:i+3], 8) for i in range(0, len(octs), 3))
    decoded_str = _bytes_to_str(decoded_bytes)
    return [('Octal', decoded_str)]

@safe_decode
def decode_ascii_codes(data):
    parts = re.findall(r'\d{1,3}', data)
    if not parts:
        return []
    decoded_chars = [chr(int(c)) for c in parts if 0 <= int(c) <= 255]
    decoded_str = ''.join(decoded_chars)
    return [('ASCII codes', decoded_str)]

@safe_decode
def decode_caesar(data):
    results = []
    for shift in range(1, 26):
        decoded = []
        for c in data:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded_c = chr((ord(c) - base - shift) % 26 + base)
                decoded.append(decoded_c)
            else:
                decoded.append(c)
        decoded_str = ''.join(decoded)
        if is_printable_ratio(decoded_str) > 0.85:
            results.append((f'Caesar shift -{shift}', decoded_str))
            if len(results) >= 5:
                break
    return results

@safe_decode
def decode_utf16(data):
    results = []
    decoded_le = data.encode('latin1', errors='ignore').decode('utf-16le', errors='ignore')
    if is_printable_ratio(decoded_le) > 0.85:
        results.append(('UTF-16 LE', decoded_le))
    decoded_be = data.encode('latin1', errors='ignore').decode('utf-16be', errors='ignore')
    if is_printable_ratio(decoded_be) > 0.85:
        results.append(('UTF-16 BE', decoded_be))
    return results

@safe_decode
def decode_morse(data):
    words = data.strip().split('   ')
    decoded_words = []
    for word in words:
        chars = word.split()
        decoded_chars = []
        for c in chars:
            decoded_char = MORSE_CODE_DICT.get(c)
            if decoded_char is None:
                return []
            decoded_chars.append(decoded_char)
        decoded_words.append(''.join(decoded_chars))
    decoded_str = ' '.join(decoded_words)
    if is_printable_ratio(decoded_str) > 0.85:
        return [('Morse', decoded_str)]
    return []

@safe_decode
def decode_morse_inverted(data):
    inverted = data.replace('.', 'x').replace('-', '.').replace('x', '-')
    return decode_morse(inverted)

@safe_decode
def decode_atbash(data):
    def atbash_char(c):
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            return chr(base + (25 - (ord(c) - base)))
        return c
    decoded = ''.join(atbash_char(c) for c in data)
    if is_printable_ratio(decoded) > 0.85:
        return [('Atbash', decoded)]
    return []

@safe_decode
def decode_atbash_rot13(data):
    intermediate = decode_atbash(data)
    if intermediate:
        return decode_rot13(intermediate[0][1])
    return []

@safe_decode
def decode_bacon(data):
    data = data.strip().upper()
    trans_table = str.maketrans({'A': '0', 'B': '1', '0': '0', '1': '1'})
    binary = data.translate(trans_table)
    binary = ''.join(c for c in binary if c in '01')
    if len(binary) < 5:
        return []
    decoded_chars = []
    for i in range(0, len(binary) - 4, 5):
        chunk = binary[i:i+5]
        val = int(chunk, 2)
        if 0 <= val <= 25:
            decoded_chars.append(chr(val + ord('A')))
        else:
            return []
    decoded_str = ''.join(decoded_chars)
    if is_printable_ratio(decoded_str) > 0.85:
        return [('Bacon cipher', decoded_str)]
    return []

@safe_decode
def decode_rex(data):
    decoded_chars = []
    for c in data:
        if c.isdigit():
            decoded_c = chr((ord(c) - ord('0') - 5) % 10 + ord('0'))
            decoded_chars.append(decoded_c)
        else:
            decoded_chars.append(c)
    decoded_str = ''.join(decoded_chars)
    if is_printable_ratio(decoded_str) > 0.85:
        return [('REX ROT5 digits', decoded_str)]
    return []

@safe_decode
def decode_rot5(data):
    decoded_chars = []
    for c in data:
        if c.isdigit():
            decoded_c = chr((ord(c) - ord('0') + 5) % 10 + ord('0'))
            decoded_chars.append(decoded_c)
        else:
            decoded_chars.append(c)
    decoded_str = ''.join(decoded_chars)
    if is_printable_ratio(decoded_str) > 0.85:
        return [('ROT5 digits', decoded_str)]
    return []

@safe_decode
def decode_polybius(data):
    data = re.sub(r'[^1-5]', '', data)
    if len(data) % 2 != 0:
        return []
    polybius_square = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'K'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]
    decoded_chars = []
    for i in range(0, len(data), 2):
        row = int(data[i]) - 1
        col = int(data[i+1]) - 1
        if 0 <= row < 5 and 0 <= col < 5:
            decoded_chars.append(polybius_square[row][col])
        else:
            return []
    decoded_str = ''.join(decoded_chars)
    if is_printable_ratio(decoded_str) > 0.85:
        return [('Polybius square', decoded_str)]
    return []

@safe_decode
def decode_rail_fence(data, max_rails=5):
    results = []
    for rails in range(2, max_rails + 1):
        rail = [''] * rails
        idx, step = 0, 1
        for c in data:
            rail[idx] += c
            if idx == 0:
                step = 1
            elif idx == rails - 1:
                step = -1
            idx += step
        decoded_str = ''.join(rail)
        if is_printable_ratio(decoded_str) > 0.85:
            results.append((f'Rail Fence {rails} rails', decoded_str))
            if len(results) >= 5:
                break
    return results

@safe_decode
def decode_vigenere(data, key='KEY'):
    results = []
    key = key.upper()
    data = data.upper()
    decoded_chars = []
    for i, c in enumerate(data):
        if c.isalpha():
            k = ord(key[i % len(key)]) - ord('A')
            decoded_c = chr((ord(c) - ord('A') - k) % 26 + ord('A'))
            decoded_chars.append(decoded_c)
        else:
            decoded_chars.append(c)
    decoded_str = ''.join(decoded_chars)
    if is_printable_ratio(decoded_str) > 0.85:
        results.append((f'Vigenère cipher with key "{key}"', decoded_str))
    return results

DECODERS = [
    decode_base64,
    decode_base32,
    decode_base85,
    decode_base91,
    decode_base58,
    decode_hex,
    decode_rot13,
    decode_url,
    decode_url_unicode,
    decode_xor,
    decode_binary,
    decode_octal,
    decode_ascii_codes,
    decode_caesar,
    decode_utf16,
    decode_morse,
    decode_morse_inverted,
    decode_atbash,
    decode_atbash_rot13,
    decode_bacon,
    decode_rex,
    decode_rot5,
    decode_polybius,
    decode_rail_fence,
    decode_vigenere,
]

def try_all_methods(data):
    results = []
    seen = set()
    for decoder in DECODERS:
        for method, decoded in decoder(data):
            if decoded not in seen:
                seen.add(decoded)
                results.append((method, decoded))
    return results[:20]

def detect_most_probable(data):
    results = try_all_methods(data)
    if not results:
        return None
    results.sort(key=lambda res: (is_printable_ratio(res[1]), len(res[1])), reverse=True)
    return results[0]
