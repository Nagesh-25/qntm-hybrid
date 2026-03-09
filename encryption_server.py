"""
Hybrid Encryption Server
Receives encryption/decryption requests from clients
Manages quantum key generation and AES operations
"""

import socket
import threading
import json
import uuid
import base64
import logging
import os
from typing import Dict, Tuple

from quantum_key_gen import QuantumKeyGenerator
from aes_encryption import AESEncryptor      # assume this takes/returns bytes

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HybridEncryptionServer:
    def __init__(self, host='localhost', port=5555, num_qubits=256):
        self.host = host
        self.port = port
        self.socket = None
        self.quantum_key_gen = QuantumKeyGenerator(num_qubits=num_qubits)
        self.active_sessions: Dict[str, Dict] = {}

        logger.info(f"Initializing Hybrid Encryption Server on {host}:{port}")

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            logger.info(f"Server listening on {self.host}:{self.port}")

            while True:
                client_sock, addr = self.socket.accept()
                logger.info(f"Connection from {addr}")
                t = threading.Thread(
                    target=self._handle_client, args=(client_sock, addr)
                )
                t.daemon = True
                t.start()
        except KeyboardInterrupt:
            logger.info("Server shutdown initiated")
        finally:
            if self.socket:
                self.socket.close()

    def _handle_client(self, client_socket: socket.socket, client_address: Tuple):
        session_id = None
        try:
            raw = b''
            while True:
                chunk = client_socket.recv(1024 * 1024)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 100 * 1024 * 1024:
                    raise ValueError("Request too large")
                try:
                    request = json.loads(raw.decode('utf-8'))
                    break
                except json.JSONDecodeError:
                    pass
            request = json.loads(raw)
            action = request.get('action')
            session_id = request.get('session_id')

            if action == 'generate_key':
                response = self._handle_generate_key(request)
                session_id = response.get('session_id')
            elif action == 'encrypt_text':
                response = self._handle_encrypt_text(request, session_id)
            elif action == 'decrypt_text':
                response = self._handle_decrypt_text(request, session_id)
            elif action == 'encrypt_file':
                response = self._handle_encrypt_file(request, session_id)
            elif action == 'decrypt_file':
                response = self._handle_decrypt_file(request, session_id)
            else:
                response = {'status': 'error', 'message': 'unknown action'}

            client_socket.sendall(json.dumps(response).encode('utf-8'))

        except Exception as exc:
            logger.exception("Error handling client")
            try:
                client_socket.sendall(
                    json.dumps({'status': 'error', 'message': str(exc)}).encode()
                )
            except Exception:        # give up if send fails
                pass
        finally:
            client_socket.close()
            logger.info(f"Client connection closed: {client_address}")

    def _handle_generate_key(self, request: Dict) -> Dict:
        try:
            key = self.quantum_key_gen.generate_quantum_key()
            iv = self.quantum_key_gen.generate_iv()
            session_id = str(uuid.uuid4())
            self.active_sessions[session_id] = {'key': key, 'iv': iv}
            logger.info(f"Quantum key generated - Session ID: {session_id}")
            return {
                'status': 'ok',
                'session_id': session_id,
                'key': key.hex(),        # send hex string
                'iv': iv.hex(),
            }
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            return {'status': 'error', 'message': str(e)}

    def _get_session_material(self, session_id: str):
        if not session_id or session_id not in self.active_sessions:
            raise ValueError('no active session')
        sess = self.active_sessions[session_id]
        return bytes.fromhex(sess['key']) if isinstance(sess['key'], str) else sess['key'], \
               bytes.fromhex(sess['iv'])  if isinstance(sess['iv'], str)  else sess['iv']

    def _handle_encrypt_text(self, request: Dict, session_id: str) -> Dict:
        try:
            plaintext = request.get('plaintext', '')
            key, iv = self._get_session_material(session_id)
            aes = AESEncryptor(key, iv)
            ciphertext, used_iv = aes.encrypt_text(plaintext)
            return {'status': 'ok', 'ciphertext': ciphertext.hex(), 'iv': used_iv.hex(), 'length': len(plaintext)}
        except Exception as e:
            logger.error(f"text encryption error: {e}")
            return {'status': 'error', 'message': str(e)}

    def _handle_decrypt_text(self, request: Dict, session_id: str) -> Dict:
        try:
            hex_ct = request.get('ciphertext', '')
            iv_hex = request.get('iv', '')
            key, _ = self._get_session_material(session_id)
            iv = bytes.fromhex(iv_hex) if iv_hex else _
            aes = AESEncryptor(key, iv)
            # client must send hex string
            plaintext = aes.decrypt_text(bytes.fromhex(hex_ct), iv)
            return {'status': 'ok', 'plaintext': plaintext}
        except Exception as e:
            logger.error(f"text decryption error: {e}")
            return {'status': 'error', 'message': str(e)}

    def _handle_encrypt_file(self, request: Dict, session_id: str) -> Dict:
        try:
            b64data = request.get('data', '')
            file_type = request.get('file_type', '')
            filename = request.get('filename', '')
            key, iv = self._get_session_material(session_id)
            aes = AESEncryptor(key, iv)
            raw = base64.b64decode(b64data)
            cipher, used_iv = aes.encrypt_bytes(raw)
            metadata = {
                'filename': filename,
                'original_size': len(raw),
                'encrypted_size': len(cipher),
                'file_type': file_type
            }
            return {'status': 'ok', 'ciphertext': base64.b64encode(cipher).decode('ascii'), 'iv': used_iv.hex(), 'metadata': metadata}
        except Exception as e:
            logger.error(f"file encryption error: {e}")
            return {'status': 'error', 'message': str(e)}

    def _handle_decrypt_file(self, request: Dict, session_id: str) -> Dict:
        try:
            b64ct = request.get('data', '')
            iv_hex = request.get('iv', '')
            key, _ = self._get_session_material(session_id)
            iv = bytes.fromhex(iv_hex) if iv_hex else _
            aes = AESEncryptor(key, iv)
            plaintext = aes.decrypt_bytes(base64.b64decode(b64ct), iv)
            return {'status': 'ok', 'data': base64.b64encode(plaintext).decode('ascii')}
        except Exception as e:
            logger.error(f"file decryption error: {e}")
            return {'status': 'error', 'message': str(e)}

if __name__ == "__main__":
    server = HybridEncryptionServer(host='0.0.0.0', port=5555, num_qubits=256)
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
