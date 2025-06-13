import os
import base64
import json
from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class MusicEncryption:
    def __init__(self):
        # Tạo cặp khóa RSA
        self.key = RSA.generate(1024)
        self.public_key = self.key.publickey()
        self.private_key = self.key

    def create_session_key(self):
        return get_random_bytes(24)  # 192 bits cho Triple DES

    def encrypt_metadata(self, metadata, key):
        cipher = DES.new(key[:8], DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(json.dumps(metadata).encode(), DES.block_size))
        return base64.b64encode(cipher.iv + ct_bytes).decode()

    def encrypt_file(self, file_path, session_key):
        # Đọc file
        with open(file_path, 'rb') as f:
            data = f.read()

        # Tạo IV
        iv = get_random_bytes(8)
        
        # Mã hóa file bằng Triple DES
        cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data, DES3.block_size))
        
        return iv, ct_bytes

    def sign_data(self, data):
        hash_obj = SHA512.new(data)
        signature = pkcs1_15.new(self.private_key).sign(hash_obj)
        return base64.b64encode(signature).decode()

    def encrypt_session_key(self, session_key, recipient_public_key):
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        return base64.b64encode(cipher_rsa.encrypt(session_key)).decode()

    def prepare_package(self, file_path, metadata, recipient_public_key):
        # Tạo session key
        session_key = self.create_session_key()
        
        # Mã hóa metadata
        encrypted_metadata = self.encrypt_metadata(metadata, session_key)
        
        # Mã hóa file
        iv, encrypted_file = self.encrypt_file(file_path, session_key)
        
        # Tính hash
        hash_obj = SHA512.new(iv + encrypted_file)
        file_hash = hash_obj.hexdigest()
        
        # Ký số
        signature = self.sign_data(hash_obj.digest())
        
        # Mã hóa session key
        encrypted_session_key = self.encrypt_session_key(session_key, recipient_public_key)
        
        # Tạo package
        package = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(encrypted_file).decode(),
            "meta": encrypted_metadata,
            "hash": file_hash,
            "sig": signature,
            "session_key": encrypted_session_key
        }
        
        return package

    def verify_and_decrypt(self, package, sender_public_key):
        try:
            # Giải mã session key
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            session_key = cipher_rsa.decrypt(base64.b64decode(package["session_key"]))
            
            # Kiểm tra hash
            iv = base64.b64decode(package["iv"])
            ciphertext = base64.b64decode(package["cipher"])
            hash_obj = SHA512.new(iv + ciphertext)
            
            if hash_obj.hexdigest() != package["hash"]:
                return False, "Hash không hợp lệ"
            
            # Kiểm tra chữ ký
            try:
                pkcs1_15.new(sender_public_key).verify(
                    hash_obj,
                    base64.b64decode(package["sig"])
                )
            except (ValueError, TypeError):
                return False, "Chữ ký không hợp lệ"
            
            # Giải mã file
            cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
            
            # Giải mã metadata
            meta_cipher = DES.new(session_key[:8], DES.MODE_CBC)
            meta_iv = base64.b64decode(package["meta"])[:8]
            meta_ct = base64.b64decode(package["meta"])[8:]
            meta_cipher = DES.new(session_key[:8], DES.MODE_CBC, meta_iv)
            decrypted_metadata = json.loads(unpad(meta_cipher.decrypt(meta_ct), DES.block_size))
            
            return True, {
                "data": decrypted_data,
                "metadata": decrypted_metadata
            }
            
        except Exception as e:
            return False, str(e) 