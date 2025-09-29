#from cryptography.fernet import Fernet, InvalidToken
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#import base64
#import os
#import json
#from datetime import datetime, timedelta

class AdvancedTextEncryptor:
    def __init__(self, passphrase: str, salt: bytes = None, iterations: int = 100000):
       # """
       # Initialize with a passphrase. Salt is auto-generated if None.
        #Iterations: Higher = more secure but slower (default is strong).
        #"""
        if salt is None:
            salt = os.urandom(16)  # 128-bit salt for security
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for Fernet
            salt=salt,
            iterations=iterations,)
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        self.cipher = Fernet(key)
        self.salt = salt  # Store salt to share with recipient (not secret)

    def encrypt(self, message: str, ttl_minutes: int = 60) -> dict:
        #"""
        #Encrypt a text message. Adds a timestamp for TTL (time-to-live).
        #Returns a dict with ciphertext, salt, and timestamp for transmission.
        #"""
        timestamp = datetime.utcnow().isoformat()
        payload = {"message": message,"timestamp": timestamp}
        json_payload = json.dumps(payload).encode()
        
        # Encrypt the payload
        ciphertext = self.cipher.encrypt(json_payload)
        
        return 
        {"ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),  # URL-safe for messaging
            "salt": base64.b64encode(self.salt).decode(),  # Share this with key
            "ttl_minutes": ttl_minutes}

    def decrypt(self, encrypted_data: dict) -> str:
        #"""
        #Decrypt the message. Checks TTL and verifies integrity.
        #Returns plaintext if valid, else raises error.
        #"""
        try:
            # Reconstruct ciphertext
            ciphertext = base64.urlsafe_b64decode(encrypted_data["ciphertext"].encode())
            decrypted_json = self.cipher.decrypt(ciphertext).decode()
            
            payload = json.loads(decrypted_json)
            message = payload["message"]
            timestamp = datetime.fromisoformat(payload["timestamp"])
            
            # Check TTL (advanced freshness check)
            ttl_minutes = encrypted_data.get("ttl_minutes", 60)
            if datetime.utcnow() > timestamp + timedelta(minutes=ttl_minutes):
                raise ValueError("Message expired (TTL exceeded)")
            
            return message
        except (InvalidToken, ValueError, KeyError) as e:
            raise ValueError(f"Decryption failed: {str(e)}")

# Example Usage
#if __name__ == "__main__":
    # Step 1: Create encryptor (share passphrase and salt securely)
   # passphrase = "my_super_secret_passphrase_2023"  # In practice, use a strong, unique one
    #encryptor = AdvancedTextEncryptor(passphrase)
    
    # Step 2: Encrypt a message
   # original_message = "Hello, this is a secret text message! 🚀"
    #encrypted = encryptor.encrypt(original_message, ttl_minutes=30)
    #print("Encrypted Data (transmit this):")
    #print(json.dumps(encrypted, indent=2))
    
    # Step 3: Simulate decryption (recipient uses same passphrase + received salt)
    #recipient_encryptor = AdvancedTextEncryptor(
     #   passphrase, 
      #  salt=base64.b64decode(encrypted["salt"].encode())

   # decrypted_message = recipient_encryptor.decrypt(encrypted)
    #print(f"\nDecrypted Message: {decrypted_message}")
