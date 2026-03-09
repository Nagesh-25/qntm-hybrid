"""
AES Encryption/Decryption Module
Supports encryption of text, images, audio, and video files
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json
from typing import Union, Tuple


class AESEncryptor:
    """Handle AES encryption and decryption for various file types"""
    
    def __init__(self, key: bytes, iv: bytes = None):
        """
        Initialize AES encryptor
        
        Args:
            key: 32-byte encryption key
            iv: 16-byte initialization vector (generated if not provided)
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        
        self.key = key
        self.iv = iv if iv else os.urandom(16)
        self.backend = default_backend()
    
    def encrypt_text(self, plaintext: str) -> Tuple[bytes, bytes]:
        """
        Encrypt plain text
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            tuple: (ciphertext, iv)
        """
        # Convert text to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(self.iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padded_plaintext = self._add_padding(plaintext_bytes)
        
        # Encrypt
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return ciphertext, self.iv
    
    def encrypt_bytes(self, plaintext_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt raw bytes
        
        Args:
            plaintext_bytes: Bytes to encrypt
            
        Returns:
            tuple: (ciphertext, iv)
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(self.iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padded_plaintext = self._add_padding(plaintext_bytes)
        
        # Encrypt
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return ciphertext, self.iv
    
    def decrypt_text(self, ciphertext: bytes, iv: bytes) -> str:
        """
        Decrypt encrypted text
        
        Args:
            ciphertext: Encrypted data
            iv: Initialization vector used for encryption
            
        Returns:
            str: Decrypted text
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext_bytes = self._remove_padding(padded_plaintext)
        
        return plaintext_bytes.decode('utf-8')
    
    def decrypt_bytes(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt encrypted bytes
        
        Args:
            ciphertext: Encrypted data
            iv: Initialization vector used for encryption
            
        Returns:
            bytes: Decrypted bytes
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext_bytes = self._remove_padding(padded_plaintext)
        
        return plaintext_bytes
    
    def encrypt_file(self, file_path: str) -> Tuple[bytes, bytes, dict]:
        """
        Encrypt a file (binary data)
        
        Args:
            file_path: Path to file to encrypt
            
        Returns:
            tuple: (ciphertext, iv, metadata)
        """
        # Read file
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(self.iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        padded_plaintext = self._add_padding(plaintext)
        
        # Encrypt
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Prepare metadata
        metadata = {
            'filename': os.path.basename(file_path),
            'original_size': len(plaintext),
            'encrypted_size': len(ciphertext),
            'file_type': os.path.splitext(file_path)[1]
        }
        
        return ciphertext, self.iv, metadata
    
    def decrypt_file(self, ciphertext: bytes, iv: bytes, output_path: str = None) -> bytes:
        """
        Decrypt encrypted file
        
        Args:
            ciphertext: Encrypted data
            iv: Initialization vector used for encryption
            output_path: Optional path to save decrypted file
            
        Returns:
            bytes: Decrypted file data
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        plaintext = self._remove_padding(padded_plaintext)
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(plaintext)
        
        return plaintext
    
    def encrypt_large_file(self, file_path: str, chunk_size: int = 1024 * 1024) -> Tuple[str, dict]:
        """
        Encrypt large file using chunked approach
        
        Args:
            file_path: Path to file to encrypt
            chunk_size: Size of chunks to process (default 1MB)
            
        Returns:
            tuple: (encrypted_file_path, metadata)
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(self.iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Output path
        output_path = file_path + '.enc'
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Encrypt in chunks
        with open(file_path, 'rb') as infile:
            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    outfile.write(encryptor.update(chunk))
                
                # Finalize with padding
                outfile.write(encryptor.finalize())
        
        # Prepare metadata
        encrypted_size = os.path.getsize(output_path)
        metadata = {
            'filename': os.path.basename(file_path),
            'original_size': file_size,
            'encrypted_size': encrypted_size,
            'file_type': os.path.splitext(file_path)[1],
            'iv': self.iv.hex()
        }
        
        return output_path, metadata
    
    def decrypt_large_file(self, encrypted_file_path: str, iv: bytes, 
                          output_path: str = None, chunk_size: int = 1024 * 1024) -> str:
        """
        Decrypt large file using chunked approach
        
        Args:
            encrypted_file_path: Path to encrypted file
            iv: Initialization vector used for encryption
            output_path: Optional path to save decrypted file
            chunk_size: Size of chunks to process (default 1MB)
            
        Returns:
            str: Path to decrypted file
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Output path
        if output_path is None:
            output_path = encrypted_file_path.replace('.enc', '_decrypted')
        
        # Decrypt in chunks
        with open(encrypted_file_path, 'rb') as infile:
            with open(output_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    outfile.write(decryptor.update(chunk))
                
                # Finalize and remove padding
                final_data = decryptor.finalize()
                outfile.write(final_data)
        
        # Remove padding from the last write
        self._remove_padding_from_file(output_path)
        
        return output_path
    
    @staticmethod
    def _add_padding(data: bytes) -> bytes:
        """Add PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def _remove_padding_from_file(file_path: str) -> None:
        """Remove PKCS7 padding from end of file"""
        with open(file_path, 'r+b') as f:
            f.seek(-1, 2)
            padding_length = ord(f.read(1))
            
            if 0 < padding_length <= 16:
                # Verify padding
                f.seek(-padding_length, 2)
                padding_bytes = f.read(padding_length)
                
                if all(b == padding_length for b in padding_bytes):
                    f.seek(-padding_length, 2)
                    f.truncate()


if __name__ == "__main__":
    # Test AES encryption
    print("Testing AES Encryption/Decryption...")
    
    # Generate test key
    key = os.urandom(32)
    iv = os.urandom(16)
    
    # Create encryptor
    aes = AESEncryptor(key, iv)
    
    # Test text encryption
    plaintext = "Hello, this is a secret message!"
    ciphertext, used_iv = aes.encrypt_text(plaintext)
    print(f"Encrypted text: {ciphertext.hex()[:32]}...")
    
    # Test decryption
    decrypted = aes.decrypt_text(ciphertext, used_iv)
    print(f"Decrypted text: {decrypted}")
    print(f"Encryption successful: {plaintext == decrypted}")
