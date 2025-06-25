import base64
import codecs
import binascii
import urllib.parse
from .utils import is_printable_ratio

def _bytes_to_str(decoded_bytes):
    try:
        return decoded_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return repr(decoded_bytes)

def _add_padding(data_bytes):
    missing_padding = (-len(data_bytes)) % 4
    if missing_padding:
        data_bytes += b'=' * missing_padding
    return data_bytes

def decode_base64(data):
    results = []
    if isinstance(data, str):
        data_bytes = data.encode()
    else:
        data_bytes = data

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

def decode_hex(data):
    try:
        clean_data = data.replace(' ', '')
        decoded = bytes.fromhex(clean_data)
        return [('Hex', _bytes_to_str(decoded))]
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
