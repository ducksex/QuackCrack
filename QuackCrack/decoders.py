import base64
import codecs
import binascii
import urllib.parse
from .utils import is_printable_ratio

def decode_base64(data):
    results = []
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(data, validate=True)
            try:
                decoded_str = decoded.decode('utf-8')
            except UnicodeDecodeError:
                decoded_str = repr(decoded)
            results.append(('Base64', decoded_str))
        except (binascii.Error, ValueError):
            continue
    return results

def decode_hex(data):
    try:
        clean_data = data.replace(' ', '')
        decoded = bytes.fromhex(clean_data)
        try:
            decoded_str = decoded.decode('utf-8')
        except UnicodeDecodeError:
            decoded_str = repr(decoded)
        return [('Hex', decoded_str)]
    except ValueError:
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
        clean_data = data.replace(' ', '')
        raw_bytes = bytes.fromhex(clean_data)
    except ValueError:
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

def try_all_methods(data):
    all_results = []
    all_results.extend(decode_base64(data))
    all_results.extend(decode_hex(data))
    all_results.extend(decode_rot13(data))
    all_results.extend(decode_url(data))
    all_results.extend(decode_xor(data))
    return all_results
