import base64
import codecs
import binascii
import urllib.parse
import re
from .utils import is_printable_ratio

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

def decode_base32(data):
    results = []
    try:
        clean_data = re.sub(r'\s+', '', data).upper()
        padded_data = clean_data + '=' * ((8 - len(clean_data) % 8) % 8)
        decoded = base64.b32decode(padded_data, casefold=True)
        results.append(('Base32', _bytes_to_str(decoded)))
    except (binascii.Error, ValueError):
        pass
    return results

def decode_base85(data):
    results = []
    try:
        decoded = base64.a85decode(data, adobe=False, ignorechars=b'\n\r\t ')
        results.append(('Base85', _bytes_to_str(decoded)))
    except Exception:
        pass
    try:
        decoded = base64.b85decode(data, ignorechars=b'\n\r\t ')
        results.append(('Base85 (b85)', _bytes_to_str(decoded)))
    except Exception:
        pass
    return results

def decode_hex(data):
    try:
        clean_data = re.sub(r'\s+', '', data)
        decoded = bytes.fromhex(clean_data)
        return [('Hex', _bytes_to_str(decoded))]
    except Exception:
        return []

def decode_rot13(data):
    try:
        decoded = codecs.decode(data, 'rot_13')
        return [('ROT13', decoded)]
    except Exception:
        return []

def decode_url(data):
    try:
        decoded = urllib.parse.unquote(data)
        return [('URL Decode', decoded)]
    except Exception:
        return []

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

def decode_binary(data):
    try:
        bits = ''.join(re.findall(r'[01]{8}', data))
        if not bits:
            return []
        decoded_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        decoded_str = _bytes_to_str(decoded_bytes)
        return [('Binary', decoded_str)]
    except Exception:
        return []

def decode_octal(data):
    try:
        octs = ''.join(re.findall(r'[0-7]{3}', data))
        if not octs:
            return []
        decoded_bytes = bytes(int(octs[i:i+3], 8) for i in range(0, len(octs), 3))
        decoded_str = _bytes_to_str(decoded_bytes)
        return [('Octal', decoded_str)]
    except Exception:
        return []

def decode_ascii_codes(data):
    try:
        parts = re.findall(r'\d{1,3}', data)
        if not parts:
            return []
        decoded_chars = [chr(int(c)) for c in parts if 0 <= int(c) <= 255]
        decoded_str = ''.join(decoded_chars)
        return [('ASCII codes', decoded_str)]
    except Exception:
        return []

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

def decode_utf16(data):
    results = []
    try:
        decoded_le = data.encode('latin1').decode('utf-16le')
        if is_printable_ratio(decoded_le) > 0.85:
            results.append(('UTF-16 LE', decoded_le))
    except Exception:
        pass
    try:
        decoded_be = data.encode('latin1').decode('utf-16be')
        if is_printable_ratio(decoded_be) > 0.85:
            results.append(('UTF-16 BE', decoded_be))
    except Exception:
        pass
    return results

def decode_morse(data):
    words = data.strip().split('   ')
    decoded_words = []
    try:
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
    except Exception:
        return []

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

def decode_polybius(data):
    try:
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
    except Exception:
        return []

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

def try_all_methods(data):
    all_results = []
    all_results.extend(decode_base64(data))
    all_results.extend(decode_base32(data))
    all_results.extend(decode_base85(data))
    all_results.extend(decode_hex(data))
    all_results.extend(decode_rot13(data))
    all_results.extend(decode_url(data))
    all_results.extend(decode_xor(data))
    all_results.extend(decode_binary(data))
    all_results.extend(decode_octal(data))
    all_results.extend(decode_ascii_codes(data))
    all_results.extend(decode_caesar(data))
    all_results.extend(decode_utf16(data))
    all_results.extend(decode_morse(data))
    all_results.extend(decode_atbash(data))
    all_results.extend(decode_bacon(data))
    all_results.extend(decode_rex(data))
    all_results.extend(decode_polybius(data))
    all_results.extend(decode_rail_fence(data))

    seen = set()
    unique_results = []
    for method, decoded in all_results:
        if decoded not in seen:
            seen.add(decoded)
            unique_results.append((method, decoded))
    return unique_results[:20]

def detect_most_probable(data):
    results = try_all_methods(data)
    if not results:
        return None
    def score(res):
        _, decoded = res
        ratio = is_printable_ratio(decoded)
        length = len(decoded)
        return (ratio, length)
    results.sort(key=score, reverse=True)
    return results[0]
