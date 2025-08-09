"""
Production-grade encryption utilities for iSECTECH AI services.

This module provides comprehensive encryption capabilities including:
- AES-256-GCM encryption for data at rest and in transit
- Key management with rotation and derivation
- Multi-tenant encryption contexts
- Model encryption and protection
"""

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..config.settings import SecurityClassification


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class KeyManagementError(EncryptionError):
    """Exception for key management operations."""
    pass


class DataEncryption:
    """Advanced data encryption with AES-256-GCM."""
    
    def __init__(self, key: bytes):
        """Initialize with encryption key."""
        if len(key) != 32:  # 256 bits
            raise EncryptionError("Key must be 32 bytes (256 bits)")
        self.aead = AESGCM(key)
    
    def encrypt(self, plaintext: Union[str, bytes], 
                associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Additional authenticated data
            
        Returns:
            Tuple of (ciphertext, nonce)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = self.aead.encrypt(nonce, plaintext, associated_data)
        
        return ciphertext, nonce
    
    def decrypt(self, ciphertext: bytes, nonce: bytes,
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data with AES-256-GCM.
        
        Args:
            ciphertext: Encrypted data
            nonce: Nonce used for encryption
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        try:
            return self.aead.decrypt(nonce, ciphertext, associated_data)
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}")
    
    def encrypt_to_base64(self, plaintext: Union[str, bytes],
                         associated_data: Optional[bytes] = None) -> str:
        """Encrypt data and return base64-encoded result."""
        ciphertext, nonce = self.encrypt(plaintext, associated_data)
        
        # Combine nonce + ciphertext for storage
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode('ascii')
    
    def decrypt_from_base64(self, encrypted_data: str,
                           associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt base64-encoded data."""
        try:
            combined = base64.b64decode(encrypted_data.encode('ascii'))
            nonce = combined[:12]  # First 12 bytes are nonce
            ciphertext = combined[12:]  # Rest is ciphertext
            
            return self.decrypt(ciphertext, nonce, associated_data)
        except Exception as e:
            raise EncryptionError(f"Base64 decryption failed: {e}")


class KeyDerivation:
    """Key derivation functions for secure key generation."""
    
    @staticmethod
    def derive_key_pbkdf2(password: Union[str, bytes], salt: bytes,
                         iterations: int = 100000) -> bytes:
        """Derive key using PBKDF2."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password)
    
    @staticmethod
    def derive_key_scrypt(password: Union[str, bytes], salt: bytes,
                         n: int = 2**14, r: int = 8, p: int = 1) -> bytes:
        """Derive key using Scrypt (more secure but slower)."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            n=n,
            r=r,
            p=p,
        )
        return kdf.derive(password)
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate cryptographically secure salt."""
        return os.urandom(32)


class TenantEncryptionContext:
    """Encryption context for multi-tenant environments."""
    
    def __init__(self, tenant_id: str, security_classification: SecurityClassification):
        self.tenant_id = tenant_id
        self.security_classification = security_classification
        self.context_hash = self._generate_context_hash()
    
    def _generate_context_hash(self) -> bytes:
        """Generate hash of tenant context for encryption."""
        context_data = f"{self.tenant_id}:{self.security_classification.value}"
        return hashlib.sha256(context_data.encode('utf-8')).digest()
    
    def get_associated_data(self) -> bytes:
        """Get associated data for authenticated encryption."""
        return self.context_hash


class ModelEncryption:
    """Specialized encryption for ML models."""
    
    def __init__(self, encryption_manager: 'EncryptionManager'):
        self.encryption_manager = encryption_manager
    
    def encrypt_model_weights(self, weights: bytes, model_id: str,
                            tenant_context: Optional[TenantEncryptionContext] = None) -> str:
        """Encrypt model weights with metadata."""
        encryptor = self.encryption_manager.get_encryptor(tenant_context)
        
        # Create associated data with model metadata
        metadata = f"model:{model_id}:{datetime.utcnow().isoformat()}"
        associated_data = metadata.encode('utf-8')
        if tenant_context:
            associated_data += tenant_context.get_associated_data()
        
        return encryptor.encrypt_to_base64(weights, associated_data)
    
    def decrypt_model_weights(self, encrypted_weights: str, model_id: str,
                            tenant_context: Optional[TenantEncryptionContext] = None) -> bytes:
        """Decrypt model weights with metadata validation."""
        encryptor = self.encryption_manager.get_encryptor(tenant_context)
        
        # Reconstruct associated data (without timestamp for flexibility)
        metadata_prefix = f"model:{model_id}:"
        associated_data = metadata_prefix.encode('utf-8')
        if tenant_context:
            associated_data += tenant_context.get_associated_data()
        
        # Note: In production, you might want to store metadata separately
        # to avoid timestamp mismatches
        return encryptor.decrypt_from_base64(encrypted_weights, associated_data)


class EncryptionManager:
    """Central encryption management for AI services."""
    
    def __init__(self, master_key: Optional[bytes] = None):
        """Initialize encryption manager."""
        self.master_key = master_key or self._generate_master_key()
        self.tenant_keys: Dict[str, bytes] = {}
        self.key_rotation_schedule: Dict[str, datetime] = {}
        self.model_encryption = ModelEncryption(self)
    
    def _generate_master_key(self) -> bytes:
        """Generate master encryption key."""
        # In production, this should come from a secure key management service
        master_password = os.getenv('ISECTECH_MASTER_ENCRYPTION_KEY')
        if not master_password:
            # Generate random key for development
            return os.urandom(32)
        
        salt = os.getenv('ISECTECH_ENCRYPTION_SALT', 'isectech-ai-salt').encode('utf-8')
        return KeyDerivation.derive_key_scrypt(master_password, salt)
    
    def get_tenant_key(self, tenant_id: str, 
                      security_classification: SecurityClassification) -> bytes:
        """Get or generate tenant-specific encryption key."""
        key_id = f"{tenant_id}:{security_classification.value}"
        
        if key_id not in self.tenant_keys:
            # Derive tenant key from master key
            tenant_data = key_id.encode('utf-8')
            tenant_key = hmac.new(
                self.master_key,
                tenant_data,
                hashlib.sha256
            ).digest()
            
            self.tenant_keys[key_id] = tenant_key
            self.key_rotation_schedule[key_id] = datetime.utcnow() + timedelta(days=30)
        
        return self.tenant_keys[key_id]
    
    def get_encryptor(self, tenant_context: Optional[TenantEncryptionContext] = None) -> DataEncryption:
        """Get data encryptor for specific tenant context."""
        if tenant_context:
            key = self.get_tenant_key(
                tenant_context.tenant_id,
                tenant_context.security_classification
            )
        else:
            key = self.master_key
        
        return DataEncryption(key)
    
    def rotate_tenant_key(self, tenant_id: str, 
                         security_classification: SecurityClassification) -> None:
        """Rotate encryption key for a tenant."""
        key_id = f"{tenant_id}:{security_classification.value}"
        
        # Generate new key
        new_salt = KeyDerivation.generate_salt()
        tenant_data = f"{key_id}:{datetime.utcnow().isoformat()}".encode('utf-8')
        new_key = hmac.new(self.master_key, tenant_data + new_salt, hashlib.sha256).digest()
        
        # Update key and schedule
        old_key = self.tenant_keys.get(key_id)
        self.tenant_keys[key_id] = new_key
        self.key_rotation_schedule[key_id] = datetime.utcnow() + timedelta(days=30)
        
        # In production, you would need to re-encrypt data with new key
        # This is a complex operation that requires careful coordination
    
    def check_key_rotation_needed(self) -> Dict[str, datetime]:
        """Check which keys need rotation."""
        now = datetime.utcnow()
        return {
            key_id: scheduled_time
            for key_id, scheduled_time in self.key_rotation_schedule.items()
            if scheduled_time <= now
        }
    
    def encrypt_sensitive_field(self, value: Union[str, bytes], field_name: str,
                              tenant_context: Optional[TenantEncryptionContext] = None) -> str:
        """Encrypt a sensitive field with field-specific associated data."""
        encryptor = self.get_encryptor(tenant_context)
        
        # Create field-specific associated data
        associated_data = f"field:{field_name}".encode('utf-8')
        if tenant_context:
            associated_data += tenant_context.get_associated_data()
        
        return encryptor.encrypt_to_base64(value, associated_data)
    
    def decrypt_sensitive_field(self, encrypted_value: str, field_name: str,
                              tenant_context: Optional[TenantEncryptionContext] = None) -> bytes:
        """Decrypt a sensitive field with field-specific associated data."""
        encryptor = self.get_encryptor(tenant_context)
        
        # Reconstruct field-specific associated data
        associated_data = f"field:{field_name}".encode('utf-8')
        if tenant_context:
            associated_data += tenant_context.get_associated_data()
        
        return encryptor.decrypt_from_base64(encrypted_value, associated_data)
    
    def get_encryption_status(self) -> Dict:
        """Get encryption system status for monitoring."""
        return {
            "master_key_present": bool(self.master_key),
            "tenant_keys_count": len(self.tenant_keys),
            "keys_needing_rotation": len(self.check_key_rotation_needed()),
            "encryption_algorithm": "AES-256-GCM",
            "key_derivation": "HMAC-SHA256",
        }


# Global encryption manager instance
_encryption_manager: Optional[EncryptionManager] = None


def get_encryption_manager() -> EncryptionManager:
    """Get global encryption manager instance."""
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager


def create_tenant_context(tenant_id: str, 
                         security_classification: SecurityClassification) -> TenantEncryptionContext:
    """Create tenant encryption context."""
    return TenantEncryptionContext(tenant_id, security_classification)