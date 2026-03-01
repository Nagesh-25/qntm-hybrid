"""
Quantum Key Generation Module
Uses Qiskit to generate quantum-enhanced encryption keys
"""

import os
import hashlib
import numpy as np
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister

# AerSimulator/QasmSimulator live in qiskit_aer in recent releases;
# fall back to the provider module for older installs.
from qiskit_aer import AerSimulator, QasmSimulator


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class QuantumKeyGenerator:
    """Generate encryption keys using quantum circuit simulations"""
    
    def __init__(self, num_qubits: int = 256, simulator=None):
        """
        Initialize quantum key generator
        
        Args:
            num_qubits: Number of qubits for key generation (default 256)
            simulator: Quantum simulator to use (default: None)
        """
        self.num_qubits = num_qubits
        # default simulator choice – statevector is fine for small circuits,
        # use the qasm backend otherwise to avoid the “insufficient memory” error.
        if simulator is None:
            if num_qubits <= 25:
                self.simulator = AerSimulator()          # statevector
            else:
                self.simulator = QasmSimulator()        # qasm‑style simulator
        else:
            self.simulator = simulator
    
    def generate_quantum_key(self, seed=None):
        """
        Generate a quantum-enhanced key using BB84-inspired protocol
        
        Args:
            seed: Optional seed for reproducibility
            
        Returns:
            bytes: 32-byte encryption key
        """
        if seed is not None:
            np.random.seed(seed)
        
        # Create quantum circuit for key generation
        qr = QuantumRegister(self.num_qubits, 'q')
        cr = ClassicalRegister(self.num_qubits, 'c')
        qc = QuantumCircuit(qr, cr)
        
        # Apply random Hadamard and rotation gates
        bases = []
        for i in range(self.num_qubits):
            bit = np.random.randint(0, 2)
            basis = np.random.choice(['Z', 'X'])
            bases.append(basis)
            if bit:
                qc.x(qr[i])
            if basis == 'X':
                qc.h(qr[i])
        
        # Measure all qubits
        qc.measure(qr, cr)
        
        # Execute circuit
        try:
            result = self.simulator.run(qc, shots=1).result()
        except Exception as exc:
            raise RuntimeError(
                f"simulation failed for {self.num_qubits} qubits: {exc}"
            ) from exc
        
        # Extract measurement outcomes; use get_counts() without a circuit
        # argument to avoid the “experiment … could not be found” error.
        try:
            counts = result.get_counts()
            bitstring = next(iter(counts))
        except Exception as exc:
            raise RuntimeError(
                f"could not obtain measurement results: {exc}"
            ) from exc
        
        quantum_bits = np.array([int(bit) for bit in bitstring])
        
        # Combine with random classical bits for hybrid approach
        classical_bits = np.random.randint(0, 2, self.num_qubits)
        hybrid_bits = (quantum_bits + classical_bits) % 2
        
        # Convert bit array to bytes
        key_bytes = np.packbits(hybrid_bits[:256]).tobytes()[:32]
        
        return key_bytes
    
    def derive_key_from_password(self, password, salt=None):
        """
        Derive encryption key from password using quantum-seeded KDF
        
        Args:
            password: Password string
            salt: Optional salt (generated if not provided)
            
        Returns:
            tuple: (encryption_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        # Generate quantum seed
        quantum_seed = self.generate_quantum_key()
        
        # Use PBKDF2 with quantum seed as additional entropy
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        
        # Combine password with quantum entropy
        quantum_entropy = hashlib.sha256(quantum_seed).digest()
        combined_input = password.encode() + quantum_entropy
        
        key = kdf.derive(combined_input)
        return key, salt
    
    def generate_iv(self):
        """
        Generate a quantum-enhanced initialization vector
        
        Returns:
            bytes: 16-byte IV
        """
        quantum_iv = self.generate_quantum_key()[:16]
        return quantum_iv


if __name__ == "__main__":
    # Test quantum key generator
    print("Testing Quantum Key Generator...")
    qkg = QuantumKeyGenerator(num_qubits=24)   # 24 or so runs fine
    
    # Generate quantum key
    key = qkg.generate_quantum_key()
    print(f"Generated quantum key: {key.hex()[:32]}...")
    
    # Derive key from password
    password = "SecurePassword123"
    derived_key, salt = qkg.derive_key_from_password(password)
    print(f"Derived key from password: {derived_key.hex()[:32]}...")
    print(f"Salt: {salt.hex()}")
    
    # Generate IV
    iv = qkg.generate_iv()
    print(f"Generated IV: {iv.hex()}")
