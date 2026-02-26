import base64
import hashlib

def generate_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message, password):
    key = generate_key(password)
    message_bytes = message.encode()
    
    encrypted_bytes = bytearray()
    for i in range(len(message_bytes)):
        encrypted_bytes.append(message_bytes[i] ^ key[i % len(key)])
    
    return base64.b64encode(encrypted_bytes).decode()

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    encrypted_bytes = base64.b64decode(encrypted_message.encode())
    
    decrypted_bytes = bytearray()
    for i in range(len(encrypted_bytes)):
        decrypted_bytes.append(encrypted_bytes[i] ^ key[i % len(key)])
    
    return decrypted_bytes.decode()