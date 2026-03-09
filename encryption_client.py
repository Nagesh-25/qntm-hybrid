"""
Hybrid Encryption Client
Interactive client for encryption/decryption operations
Supports text, images, audio, and video files
"""

import socket
import json
import os
import base64
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HybridEncryptionClient:
    """Client for hybrid quantum-classical encryption"""
    
    def __init__(self, host='localhost', port=5555):
        """
        Initialize encryption client
        
        Args:
            host: Server host address
            port: Server port
        """
        self.host = host
        self.port = port
        self.socket = None
        self.session_id = None
        self.key = None
        self.iv = None
    
    def connect(self) -> bool:
        """
        Connect to encryption server
        
        Returns:
            bool: True if connected successfully
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            self.socket.close()
            logger.info("Disconnected from server")
    
    def _send_request(self, request: dict) -> Optional[dict]:
        """
        Send request to server and receive response
        
        Args:
            request: Request dictionary
            
        Returns:
            dict: Response from server or None if error
        """
        try:
            # Create new socket for each request
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            
            request_json = json.dumps(request, default=str)
            sock.sendall(request_json.encode('utf-8'))
            
            response_data = b''
            while True:
                chunk = sock.recv(1024 * 1024)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) > 100 * 1024 * 1024:
                    raise ValueError("Response too large")
                try:
                    response = json.loads(response_data.decode('utf-8'))
                    break
                except json.JSONDecodeError:
                    pass
            
            sock.close()
            return response
        except Exception as e:
            logger.error(f"Request error: {str(e)}")
            return None
    
    def generate_quantum_key(self) -> bool:
        """
        Generate quantum encryption key from server
        
        Returns:
            bool: True if key generated successfully
        """
        try:
            request = {'action': 'generate_key'}
            response = self._send_request(request)
            
            if response and response.get('status') == 'ok':
                self.session_id = response['session_id']
                self.key = response['key']
                self.iv = response['iv']
                logger.info(f"Quantum key generated - Session ID: {self.session_id}")
                print(f"✓ Quantum key generated successfully")
                print(f"  Session ID: {self.session_id[:16]}...")
                return True
            else:
                error = response.get('message', 'Unknown error') if response else 'No response'
                logger.error(f"Key generation failed: {error}")
                print(f"✗ Key generation failed: {error}")
                return False
        
        except Exception as e:
            logger.error(f"Error generating key: {str(e)}")
            return False
    
    def encrypt_text(self, plaintext: str) -> bool:
        """
        Encrypt text
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            bool: True if encryption successful
        """
        try:
            if not self.session_id:
                print("✗ No active session. Generate a key first.")
                return False
            
            request = {
                'action': 'encrypt_text',
                'plaintext': plaintext,
                'session_id': self.session_id
            }
            response = self._send_request(request)
            
            if response and response.get('status') == 'ok':
                ciphertext = response['ciphertext']
                iv = response['iv']
                
                # Save to file
                output_file = 'encrypted_text.enc'
                with open(output_file, 'w') as f:
                    json.dump({
                        'ciphertext': ciphertext,
                        'iv': iv,
                        'type': 'text'
                    }, f, indent=2)
                
                logger.info(f"Text encrypted and saved to {output_file}")
                print(f"✓ Text encrypted successfully")
                print(f"  Original length: {response['length']} characters")
                print(f"  Encrypted file: {output_file}")
                return True
            else:
                error = response.get('message', 'Unknown error') if response else 'No response'
                print(f"✗ Encryption failed: {error}")
                return False
        
        except Exception as e:
            logger.error(f"Error encrypting text: {str(e)}")
            print(f"✗ Error: {str(e)}")
            return False
    
    def decrypt_text(self, encrypted_file: str) -> bool:
        """
        Decrypt encrypted text
        
        Args:
            encrypted_file: Path to encrypted file
            
        Returns:
            bool: True if decryption successful
        """
        try:
            if not self.session_id:
                print("✗ No active session. Generate a key first.")
                return False
            
            # Load encrypted data
            with open(encrypted_file, 'r') as f:
                data = json.load(f)
            
            request = {
                'action': 'decrypt_text',
                'ciphertext': data['ciphertext'],
                'iv': data['iv'],
                'session_id': self.session_id
            }
            response = self._send_request(request)
            
            if response and response.get('status') == 'ok':
                plaintext = response['plaintext']
                
                # Save to file
                output_file = 'decrypted_text.txt'
                with open(output_file, 'w') as f:
                    f.write(plaintext)
                
                logger.info(f"Text decrypted and saved to {output_file}")
                print(f"✓ Text decrypted successfully")
                print(f"  Decrypted content: {plaintext[:100]}...")
                print(f"  Decrypted file: {output_file}")
                return True
            else:
                error = response.get('message', 'Unknown error') if response else 'No response'
                print(f"✗ Decryption failed: {error}")
                return False
        
        except Exception as e:
            logger.error(f"Error decrypting text: {str(e)}")
            print(f"✗ Error: {str(e)}")
            return False
    
    def encrypt_file(self, file_path: str) -> bool:
        """
        Encrypt a file (image, audio, video, or any binary file)
        
        Args:
            file_path: Path to file to encrypt
            
        Returns:
            bool: True if encryption successful
        """
        try:
            if not self.session_id:
                print("✗ No active session. Generate a key first.")
                return False
            
            if not os.path.exists(file_path):
                print(f"✗ File not found: {file_path}")
                return False
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            file_type = os.path.splitext(file_path)[1]
            
            # Check file size (max 10MB)
            if file_size > 10 * 1024 * 1024:
                print(f"✗ File too large. Maximum size: 10MB")
                return False
            
            # Encode file data
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            
            request = {
                'action': 'encrypt_file',
                'data': encoded_data,
                'file_type': file_type,
                'filename': os.path.basename(file_path),
                'session_id': self.session_id
            }
            response = self._send_request(request)
            
            if response and response.get('status') == 'ok':
                ciphertext = response['ciphertext']
                iv = response['iv']
                metadata = response['metadata']
                
                # Save to file
                output_file = f"{os.path.splitext(file_path)[0]}_encrypted.enc"
                with open(output_file, 'w') as f:
                    json.dump({
                        'ciphertext': ciphertext,
                        'iv': iv,
                        'metadata': metadata,
                        'type': 'file'
                    }, f, indent=2)
                
                logger.info(f"File encrypted and saved to {output_file}")
                print(f"✓ File encrypted successfully")
                print(f"  File type: {file_type}")
                print(f"  Original size: {file_size / (1024*1024):.2f} MB")
                print(f"  Encrypted file: {output_file}")
                return True
            else:
                error = response.get('message', 'Unknown error') if response else 'No response'
                print(f"✗ Encryption failed: {error}")
                return False
        
        except Exception as e:
            logger.error(f"Error encrypting file: {str(e)}")
            print(f"✗ Error: {str(e)}")
            return False
    
    def decrypt_file(self, encrypted_file: str, output_file: str = None) -> bool:
        """
        Decrypt an encrypted file
        
        Args:
            encrypted_file: Path to encrypted file
            output_file: Optional output file path
            
        Returns:
            bool: True if decryption successful
        """
        try:
            if not self.session_id:
                print("✗ No active session. Generate a key first.")
                return False
            
            if not os.path.exists(encrypted_file):
                print(f"✗ File not found: {encrypted_file}")
                return False
            
            # Load encrypted data
            with open(encrypted_file, 'r') as f:
                data = json.load(f)
            
            request = {
                'action': 'decrypt_file',
                'data': data['ciphertext'],
                'iv': data['iv'],
                'session_id': self.session_id
            }
            response = self._send_request(request)
            
            if response and response.get('status') == 'ok':
                file_data = base64.b64decode(response['data'])
                metadata = data.get('metadata', {})
                
                # Determine output file path
                if output_file is None:
                    if 'filename' in metadata:
                        output_file = f"decrypted_{metadata['filename']}"
                    else:
                        output_file = 'decrypted_file'
                
                # Save file
                with open(output_file, 'wb') as f:
                    f.write(file_data)
                
                logger.info(f"File decrypted and saved to {output_file}")
                print(f"✓ File decrypted successfully")
                print(f"  File size: {len(file_data) / (1024*1024):.2f} MB")
                print(f"  Decrypted file: {output_file}")
                return True
            else:
                error = response.get('message', 'Unknown error') if response else 'No response'
                print(f"✗ Decryption failed: {error}")
                return False
        
        except Exception as e:
            logger.error(f"Error decrypting file: {str(e)}")
            print(f"✗ Error: {str(e)}")
            return False
    
    def interactive_menu(self):
        """Run interactive menu for user operations"""
        print("\n" + "="*60)
        print("   HYBRID QUANTUM-CLASSICAL ENCRYPTION SYSTEM")
        print("="*60)
        
        while True:
            print("\n" + "-"*60)
            print("MAIN MENU")
            print("-"*60)
            print("1. Generate Quantum Encryption Key")
            print("2. Encrypt Text")
            print("3. Decrypt Text")
            print("4. Encrypt File (Image/Audio/Video/Any)")
            print("5. Decrypt File")
            print("6. Exit")
            print("-"*60)
            
            choice = input("Enter your choice (1-6): ").strip()
            
            if choice == '1':
                self.generate_quantum_key()
            
            elif choice == '2':
                print("\n--- Encrypt Text ---")
                text = input("Enter text to encrypt: ").strip()
                if text:
                    self.encrypt_text(text)
            
            elif choice == '3':
                print("\n--- Decrypt Text ---")
                file = input("Enter encrypted file path (default: encrypted_text.enc): ").strip()
                if not file:
                    file = 'encrypted_text.enc'
                self.decrypt_text(file)
            
            elif choice == '4':
                print("\n--- Encrypt File ---")
                print("Supported formats: JPG, PNG, GIF (images)")
                print("                  MP3, WAV, AAC (audio)")
                print("                  MP4, AVI, MOV (video)")
                print("                  Or any other file type")
                file = input("Enter file path: ").strip()
                if file:
                    self.encrypt_file(file)
            
            elif choice == '5':
                print("\n--- Decrypt File ---")
                file = input("Enter encrypted file path: ").strip()
                if file:
                    output = input("Enter output file path (optional, press Enter to auto-generate): ").strip()
                    self.decrypt_file(file, output if output else None)
            
            elif choice == '6':
                print("\nGoodbye!")
                break
            
            else:
                print("✗ Invalid choice. Please try again.")


def main():
    """Main entry point"""
    client = HybridEncryptionClient(host='localhost', port=5555)
    
    print("\nConnecting to encryption server...")
    if not client.connect():
        print("Failed to connect to server. Make sure the server is running.")
        return
    
    try:
        client.interactive_menu()
    except KeyboardInterrupt:
        print("\n\nClosing client...")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
