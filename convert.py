import base64
import argparse
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import csv

def export_bitwarden_csv(processed_data, output_csv_path):
    """
    Export processed data to Bitwarden-compatible CSV.
    """
    header = [
        "folder", "favorite", "type", "name", "notes", "fields",
        "reprompt", "login_uri", "login_username", "login_password", "login_totp"
    ]
    rows = []

    text = processed_data.decode('utf-8', errors='ignore')
    lines = text.splitlines()
    in_table = False
    table_headers = []
    row_dict = {}
    for line in lines:
        if line.strip().startswith("TABLE HEADERS:"):
            in_table = True
            continue
        if in_table and line.strip() == "":
            continue
        if in_table and line.strip() == "-" * 40:
            if row_dict:
                name = row_dict.get("title", "")
                notes = row_dict.get("credential_memo", "")
                login_uri = row_dict.get("origin_url", "")
                login_username = row_dict.get("username_value", "")
                login_password = row_dict.get("password_value", "")
                login_totp = row_dict.get("otp", "")
                if login_totp == "&&&NULL&&&":
                    login_totp = ""
                    
                rows.append([
                    "",  # folder
                    "0", # favorite
                    "1", # type (login)
                    name,
                    notes,
                    "",  # fields
                    "0", # reprompt
                    login_uri,
                    login_username,
                    login_password,
                    login_totp
                ])
            row_dict = {}
            continue
        if in_table and ": " in line:
            k, v = line.split(": ", 1)
            row_dict[k.strip()] = v.strip()

    with open(output_csv_path, "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)
        writer.writerows(rows)
    
    print(f"Exported {len(rows)} items to Bitwarden CSV.")


def decrypt_samsung_pass_file(encrypted_data, password):
    """
    Decrypt Samsung Pass encrypted data.
    
    Args:
        encrypted_data (bytes): Base64 encoded encrypted data
        password (str): Password used for encryption
        
    Returns:
        bytes: Decrypted data
    """
    print(f"Length of input encrypted data: {len(encrypted_data)}")
    
    decoded_data = base64.b64decode(encrypted_data)
    print(f"Length of decoded data: {len(decoded_data)}")
    
    salt_bytes = decoded_data[:20]
    print(f"Salt bytes length: {len(salt_bytes)}")
    
    block_size = 16 
    iv_bytes = decoded_data[20:20+block_size]
    print(f"IV bytes length: {len(iv_bytes)}")
    
    encrypted_bytes = decoded_data[20+block_size:]
    print(f"Encrypted bytes length: {len(encrypted_bytes)}")
    
    iteration_count = 70000
    key_length = 32
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt_bytes,
        iterations=iteration_count,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv_bytes),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    padding_length = decrypted_data[-1]
    if padding_length > 16:
        print("Warning: Invalid padding detected, returning raw decrypted data")
        return decrypted_data
    
    for i in range(1, padding_length + 1):
        if decrypted_data[-i] != padding_length:
            print("Warning: Invalid padding detected, returning raw decrypted data")
            return decrypted_data
    
    return decrypted_data[:-padding_length]


def decrypt_file(file_path, password):
    """
    Decrypt a Samsung Pass export file.
    
    Args:
        file_path (str): Path to the Samsung Pass export file
        password (str): Password used for encryption
        
    Returns:
        bytes: Decrypted data
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # If the password is empty and the file doesn't look like base64, 
        # it might be an already decrypted file
        if not password and not is_likely_base64(content):
            return content
            
        return decrypt_samsung_pass_file(content, password)
    
    except Exception as e:
        print(f"Error decrypting file: {e}")
        import traceback
        traceback.print_exc()
        return None


def is_likely_base64(data):
    """Check if data looks like it's base64 encoded."""
    try:
        if isinstance(data, bytes):
            sample = data[:100].decode('ascii', errors='ignore')
        else:
            sample = data[:100]
            
        base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        base64_ratio = sum(1 for c in sample if c in base64_chars) / len(sample)
        return base64_ratio > 0.9
    except:
        return False


def decode_base64_field(field):
    """Try to decode a base64 encoded field."""
    try:
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in field):
            decoded = base64.b64decode(field)
            try:
                return decoded.decode('utf-8')
            except UnicodeDecodeError:
                return field
        return field
    except Exception:
        return field


def process_decrypted_data(data):
    """Process decrypted data to make it more readable."""
    try:
        text_data = data.decode('utf-8')
        
        lines = text_data.splitlines()
        
        processed_lines = []
        in_table = False
        table_headers = None
        
        for line in lines:
            if line == "next_table":
                in_table = True
                table_headers = None
                processed_lines.append("\n--- NEW TABLE ---\n")
                continue
                
            if in_table and not table_headers:
                table_headers = line.split(';')
                processed_lines.append("TABLE HEADERS: " + ", ".join(table_headers))
                continue
                
            if in_table and table_headers:
                fields = line.split(';')
                
                if len(fields) == 1 and not fields[0]:
                    in_table = False
                    continue
                
                decoded_fields = [decode_base64_field(field) for field in fields]
                
                if table_headers and len(table_headers) == len(decoded_fields):
                    row_dict = dict(zip(table_headers, decoded_fields))
                    
                    formatted_row = []
                    for key, value in row_dict.items():
                        formatted_row.append(f"{key}: {value}")
                    
                    processed_lines.append("\n".join(formatted_row))
                    processed_lines.append("-" * 40)
                else:
                    processed_lines.append(", ".join(decoded_fields))
            else:
                processed_lines.append(line)
        
        return "\n".join(processed_lines).encode('utf-8')
    except Exception as e:
        print(f"Error processing decrypted data: {e}")
        return data
    
def spass_file_type(path):
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"File does not exist: {path}")
    if not path.lower().endswith('.spass'):
        raise argparse.ArgumentTypeError("File must have a .spass extension")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Decrypt Samsung Pass export and convert to Bitwarden CSV."
    )
    parser.add_argument("export_file_path", type=spass_file_type, help="Path to Samsung Pass export file")
    parser.add_argument("password", help="Password for decryption")
    parser.add_argument("--all", action="store_true", help="Export all decrypted data")
    args = parser.parse_args()

    file_path = args.export_file_path
    password = args.password
    
    print(f"Decrypting file: {file_path}")
    decrypted_data = decrypt_file(file_path, password)
    
    if decrypted_data:
        processed_data = process_decrypted_data(decrypted_data)
        
        is_text = True
        try:
            processed_data.decode('utf-8')
        except UnicodeDecodeError:
            is_text = False
        
        ext = ".txt" if is_text else ".bin"
        output_file = os.path.splitext(file_path)[0] + ".decrypted" + ext
        
        if args.all:
          with open(output_file, 'wb') as f:
              f.write(processed_data)
          print(f"Processed data saved to: {output_file}")

        bitwarden_csv_file = os.path.splitext(file_path)[0] + ".bitwarden.csv"
        export_bitwarden_csv(processed_data, bitwarden_csv_file)
        print(f"Bitwarden CSV exported to: {bitwarden_csv_file}")