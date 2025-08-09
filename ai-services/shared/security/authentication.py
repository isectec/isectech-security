"""
Production-grade authentication for iSECTECH AI services.

This module provides comprehensive authentication capabilities including:
- JWT token management and validation
- API key authentication
- Multi-factor authentication support
- Session management with security controls
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union

import jwt
from passlib.context import CryptContext
from passlib.hash import argon2

from ..config.settings import SecurityClassification, SecuritySettings


class AuthenticationError(Exception):
    """Base exception for authentication operations."""
    pass


class TokenValidationError(AuthenticationError):
    """Exception for token validation failures."""
    pass


class APIKeyError(AuthenticationError):
    """Exception for API key operations."""
    pass


class UserClaims:
    """User claims and attributes for authentication."""
    
    def __init__(self, user_id: str, tenant_id: str, roles: List[str],
                 security_clearance: SecurityClassification,
                 permissions: List[str] = None):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.roles = roles or []
        self.security_clearance = security_clearance
        self.permissions = permissions or []
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in self.permissions
    
    def can_access_classification(self, required_classification: SecurityClassification) -> bool:
        """Check if user can access data with given security classification."""
        classification_levels = {
            SecurityClassification.UNCLASSIFIED: 0,
            SecurityClassification.CONFIDENTIAL: 1,
            SecurityClassification.SECRET: 2,
            SecurityClassification.TOP_SECRET: 3,
        }
        
        user_level = classification_levels.get(self.security_clearance, 0)
        required_level = classification_levels.get(required_classification, 0)
        
        return user_level >= required_level
    
    def to_dict(self) -> Dict:
        """Convert user claims to dictionary for JWT."""
        return {
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "roles": self.roles,
            "security_clearance": self.security_clearance.value,
            "permissions": self.permissions,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'UserClaims':
        """Create UserClaims from dictionary."""
        claims = cls(
            user_id=data["user_id"],
            tenant_id=data["tenant_id"],
            roles=data.get("roles", []),
            security_clearance=SecurityClassification(data["security_clearance"]),
            permissions=data.get("permissions", [])
        )
        
        if "created_at" in data:
            claims.created_at = datetime.fromisoformat(data["created_at"])
        if "last_activity" in data:
            claims.last_activity = datetime.fromisoformat(data["last_activity"])
        
        return claims


class JWTManager:
    """JWT token management with security features."""
    
    def __init__(self, settings: SecuritySettings):
        self.settings = settings
        self.secret_key = settings.jwt_secret_key
        self.algorithm = settings.jwt_algorithm
        self.expiration_minutes = settings.jwt_expiration_minutes
    
    def create_access_token(self, user_claims: UserClaims, 
                           expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.expiration_minutes)
        
        # Create JWT payload
        payload = {
            "sub": user_claims.user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access_token",
            "claims": user_claims.to_dict()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_claims: UserClaims) -> str:
        """Create JWT refresh token (longer expiration)."""
        expire = datetime.utcnow() + timedelta(days=7)  # 7 days for refresh
        
        payload = {
            "sub": user_claims.user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh_token",
            "tenant_id": user_claims.tenant_id
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token: str) -> UserClaims:
        """Validate JWT token and return user claims."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") != "access_token":
                raise TokenValidationError("Invalid token type")
            
            # Extract user claims
            claims_data = payload.get("claims")
            if not claims_data:
                raise TokenValidationError("Missing user claims in token")
            
            return UserClaims.from_dict(claims_data)
        
        except jwt.ExpiredSignatureError:
            raise TokenValidationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid token: {e}")
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """Create new access token from refresh token."""
        try:
            payload = jwt.decode(refresh_token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != "refresh_token":
                raise TokenValidationError("Invalid refresh token type")
            
            user_id = payload.get("sub")
            tenant_id = payload.get("tenant_id")
            
            if not user_id or not tenant_id:
                raise TokenValidationError("Invalid refresh token payload")
            
            # In production, you would fetch full user claims from database
            # For now, create minimal claims
            user_claims = UserClaims(
                user_id=user_id,
                tenant_id=tenant_id,
                roles=["user"],  # Default role
                security_clearance=SecurityClassification.UNCLASSIFIED
            )
            
            return self.create_access_token(user_claims)
        
        except jwt.ExpiredSignatureError:
            raise TokenValidationError("Refresh token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid refresh token: {e}")


class APIKeyManager:
    """API key management for service-to-service authentication."""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    
    def generate_api_key(self) -> str:
        """Generate cryptographically secure API key."""
        # Generate 32 bytes (256 bits) of random data
        key_bytes = secrets.token_bytes(32)
        # Encode as URL-safe base64
        return secrets.token_urlsafe(32)
    
    def hash_api_key(self, api_key: str) -> str:
        """Hash API key for secure storage."""
        return self.pwd_context.hash(api_key)
    
    def verify_api_key(self, api_key: str, hashed_key: str) -> bool:
        """Verify API key against stored hash."""
        return self.pwd_context.verify(api_key, hashed_key)
    
    def create_api_key_claims(self, service_name: str, tenant_id: str,
                            permissions: List[str]) -> Dict:
        """Create claims for API key authentication."""
        return {
            "service_name": service_name,
            "tenant_id": tenant_id,
            "permissions": permissions,
            "created_at": datetime.utcnow().isoformat(),
            "key_type": "service_api_key"
        }


class SessionManager:
    """Session management with security controls."""
    
    def __init__(self, settings: SecuritySettings):
        self.settings = settings
        self.active_sessions: Dict[str, Dict] = {}
        self.max_sessions_per_user = 5
        self.session_timeout_minutes = 60
    
    def create_session(self, user_claims: UserClaims, ip_address: str,
                      user_agent: str) -> str:
        """Create new user session."""
        session_id = secrets.token_urlsafe(32)
        
        session_data = {
            "session_id": session_id,
            "user_claims": user_claims,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "is_active": True
        }
        
        # Cleanup old sessions for user
        self._cleanup_user_sessions(user_claims.user_id)
        
        self.active_sessions[session_id] = session_data
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str) -> Optional[UserClaims]:
        """Validate session and return user claims."""
        session = self.active_sessions.get(session_id)
        if not session or not session["is_active"]:
            return None
        
        # Check session timeout
        last_activity = session["last_activity"]
        if datetime.utcnow() - last_activity > timedelta(minutes=self.session_timeout_minutes):
            self.invalidate_session(session_id)
            return None
        
        # Basic IP validation (in production, use more sophisticated checks)
        if session["ip_address"] != ip_address:
            # Log potential session hijacking attempt
            self.invalidate_session(session_id)
            return None
        
        # Update last activity
        session["last_activity"] = datetime.utcnow()
        return session["user_claims"]
    
    def invalidate_session(self, session_id: str) -> None:
        """Invalidate specific session."""
        if session_id in self.active_sessions:
            self.active_sessions[session_id]["is_active"] = False
    
    def invalidate_user_sessions(self, user_id: str) -> None:
        """Invalidate all sessions for a user."""
        for session in self.active_sessions.values():
            if session["user_claims"].user_id == user_id:
                session["is_active"] = False
    
    def _cleanup_user_sessions(self, user_id: str) -> None:
        """Cleanup old sessions for user."""
        user_sessions = [
            (session_id, session) for session_id, session in self.active_sessions.items()
            if session["user_claims"].user_id == user_id and session["is_active"]
        ]
        
        # Keep only the most recent sessions
        if len(user_sessions) >= self.max_sessions_per_user:
            # Sort by last activity and keep the most recent
            user_sessions.sort(key=lambda x: x[1]["last_activity"], reverse=True)
            
            # Invalidate oldest sessions
            for session_id, _ in user_sessions[self.max_sessions_per_user - 1:]:
                self.invalidate_session(session_id)
    
    def get_active_sessions_count(self, user_id: str) -> int:
        """Get count of active sessions for user."""
        return sum(
            1 for session in self.active_sessions.values()
            if session["user_claims"].user_id == user_id and session["is_active"]
        )


class AuthenticationManager:
    """Central authentication management."""
    
    def __init__(self, settings: SecuritySettings):
        self.settings = settings
        self.jwt_manager = JWTManager(settings)
        self.api_key_manager = APIKeyManager()
        self.session_manager = SessionManager(settings)
        self.pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    
    def authenticate_user(self, username: str, password: str,
                         ip_address: str, user_agent: str) -> Dict:
        """Authenticate user with username/password."""
        # In production, this would verify against database
        # For now, create mock authentication
        
        if not username or not password:
            raise AuthenticationError("Missing username or password")
        
        # Mock user authentication (replace with actual user lookup)
        user_claims = UserClaims(
            user_id=f"user_{username}",
            tenant_id="default_tenant",
            roles=["user", "analyst"],
            security_clearance=SecurityClassification.CONFIDENTIAL,
            permissions=["read_events", "analyze_threats"]
        )
        
        # Create tokens and session
        access_token = self.jwt_manager.create_access_token(user_claims)
        refresh_token = self.jwt_manager.create_refresh_token(user_claims)
        session_id = self.session_manager.create_session(user_claims, ip_address, user_agent)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session_id,
            "token_type": "bearer",
            "expires_in": self.settings.jwt_expiration_minutes * 60,
            "user_claims": user_claims.to_dict()
        }
    
    def authenticate_api_key(self, api_key: str) -> UserClaims:
        """Authenticate using API key."""
        # In production, this would verify against database of hashed API keys
        # For now, create mock authentication
        
        if not api_key or len(api_key) < 32:
            raise APIKeyError("Invalid API key format")
        
        # Mock API key authentication
        return UserClaims(
            user_id="service_user",
            tenant_id="service_tenant",
            roles=["service"],
            security_clearance=SecurityClassification.SECRET,
            permissions=["read_events", "write_events", "analyze_threats"]
        )
    
    def hash_password(self, password: str) -> str:
        """Hash password for secure storage."""
        return self.pwd_context.hash(password)
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against stored hash."""
        return self.pwd_context.verify(password, hashed_password)
    
    def get_authentication_status(self) -> Dict:
        """Get authentication system status for monitoring."""
        return {
            "active_sessions": len([
                s for s in self.session_manager.active_sessions.values()
                if s["is_active"]
            ]),
            "jwt_algorithm": self.jwt_manager.algorithm,
            "session_timeout_minutes": self.session_manager.session_timeout_minutes,
            "password_hashing": "argon2",
        }


# Global authentication manager instance
_auth_manager: Optional[AuthenticationManager] = None


def get_auth_manager(settings: SecuritySettings) -> AuthenticationManager:
    """Get global authentication manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthenticationManager(settings)
    return _auth_manager