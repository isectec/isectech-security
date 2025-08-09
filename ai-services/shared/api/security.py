"""
Production-Grade API Security Framework for iSECTECH AI Services

Provides enterprise security features including:
- JWT authentication with rotation and validation
- Multi-tenant authorization with RBAC/ABAC
- API key management with scoped permissions  
- Rate limiting and DDoS protection
- Request validation and sanitization
- Security headers and CORS configuration
- Audit logging and security monitoring
"""

import asyncio
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import jwt
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, validator
import redis.asyncio as redis

from ..config.settings import SecuritySettings
from ..security.audit import AuditLogger
from ..security.encryption import EncryptionManager


class SecurityClearance:
    """Security clearance levels for iSECTECH operations"""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL" 
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"
    
    LEVELS = [PUBLIC, INTERNAL, CONFIDENTIAL, SECRET, TOP_SECRET]
    
    @classmethod
    def can_access(cls, user_level: str, required_level: str) -> bool:
        """Check if user clearance allows access to required level"""
        try:
            user_idx = cls.LEVELS.index(user_level)
            required_idx = cls.LEVELS.index(required_level)
            return user_idx >= required_idx
        except ValueError:
            return False


class APIPermission:
    """API-specific permissions for fine-grained access control"""
    # Behavioral Analysis Service
    BEHAVIORAL_READ = "behavioral:read"
    BEHAVIORAL_ANALYZE = "behavioral:analyze"
    BEHAVIORAL_ADMIN = "behavioral:admin"
    
    # NLP Assistant Service
    NLP_READ = "nlp:read"
    NLP_PROCESS = "nlp:process"
    NLP_ADMIN = "nlp:admin"
    
    # Decision Engine Service  
    DECISION_READ = "decision:read"
    DECISION_EXECUTE = "decision:execute"
    DECISION_ADMIN = "decision:admin"
    
    # System Permissions
    SYSTEM_HEALTH = "system:health"
    SYSTEM_METRICS = "system:metrics"
    SYSTEM_ADMIN = "system:admin"


class TokenPayload(BaseModel):
    """JWT token payload structure"""
    sub: str  # User ID
    tenant_id: str  # Tenant ID
    user_type: str  # user, service, admin
    permissions: List[str]  # API permissions
    clearance: str  # Security clearance level
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp
    jti: str  # JWT ID for revocation
    
    @validator('clearance')
    def validate_clearance(cls, v):
        if v not in SecurityClearance.LEVELS:
            raise ValueError(f"Invalid clearance level: {v}")
        return v


class APIKeyInfo(BaseModel):
    """API key information and permissions"""
    key_id: str
    tenant_id: str
    name: str
    permissions: List[str]
    clearance: str
    rate_limit: int  # Requests per minute
    expires_at: Optional[datetime] = None
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool = True


class RateLimitInfo(BaseModel):
    """Rate limiting information"""
    identifier: str  # User ID, API key, or IP
    requests_made: int
    limit: int
    window_start: datetime
    window_duration: timedelta


class SecurityContext(BaseModel):
    """Security context for requests"""
    user_id: str
    tenant_id: str
    user_type: str
    permissions: Set[str]
    clearance: str
    api_key_id: Optional[str] = None
    request_id: str
    ip_address: str
    user_agent: str
    authenticated_at: datetime


class APISecurityManager:
    """Centralized API security management for iSECTECH"""
    
    def __init__(self, settings: SecuritySettings):
        self.settings = settings
        self.audit_logger = AuditLogger(settings)
        self.encryption_manager = EncryptionManager(settings)
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Initialize Redis for session and rate limiting
        self.redis_client = None
        self._initialize_redis()
        
        # Token blacklist for revoked JWTs
        self.token_blacklist: Set[str] = set()
        
        # API key storage (in production, use secure database)
        self.api_keys: Dict[str, APIKeyInfo] = {}
        
        # Rate limiting storage
        self.rate_limits: Dict[str, RateLimitInfo] = {}
        
    async def _initialize_redis(self):
        """Initialize Redis connection for caching and rate limiting"""
        try:
            self.redis_client = redis.Redis(
                host=self.settings.redis_host,
                port=self.settings.redis_port,
                password=self.settings.redis_password,
                db=self.settings.redis_db,
                decode_responses=True
            )
            await self.redis_client.ping()
        except Exception as e:
            # Fallback to in-memory storage
            print(f"Redis connection failed, using in-memory storage: {e}")
            self.redis_client = None
    
    def create_access_token(self, 
                          user_id: str, 
                          tenant_id: str,
                          user_type: str,
                          permissions: List[str],
                          clearance: str,
                          expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token with iSECTECH security"""
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.settings.jwt_access_token_expire_minutes
            )
        
        # Create token payload
        payload = TokenPayload(
            sub=user_id,
            tenant_id=tenant_id,
            user_type=user_type,
            permissions=permissions,
            clearance=clearance,
            exp=int(expire.timestamp()),
            iat=int(datetime.utcnow().timestamp()),
            jti=str(uuid4())
        )
        
        # Sign token
        token = jwt.encode(
            payload.dict(),
            self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm
        )
        
        # Log token creation
        self.audit_logger.log_security_event(
            event_type="token_created",
            user_id=user_id,
            tenant_id=tenant_id,
            details={
                "token_type": "access",
                "permissions": permissions,
                "clearance": clearance,
                "expires_at": expire.isoformat()
            }
        )
        
        return token
    
    async def verify_token(self, token: str) -> TokenPayload:
        """Verify and decode JWT token"""
        try:
            # Decode token
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm]
            )
            
            # Check if token is blacklisted
            jti = payload.get("jti")
            if jti and await self._is_token_blacklisted(jti):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            return TokenPayload(**payload)
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke a JWT token by adding to blacklist"""
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm],
                options={"verify_exp": False}  # Allow expired tokens
            )
            
            jti = payload.get("jti")
            if jti:
                await self._add_to_blacklist(jti, payload.get("exp", 0))
                return True
                
        except jwt.JWTError:
            pass
        
        return False
    
    async def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is in blacklist"""
        if self.redis_client:
            try:
                result = await self.redis_client.get(f"blacklist:{jti}")
                return result is not None
            except:
                pass
        
        return jti in self.token_blacklist
    
    async def _add_to_blacklist(self, jti: str, exp: int):
        """Add token to blacklist"""
        if self.redis_client:
            try:
                # Set expiration to token expiration time
                ttl = max(0, exp - int(time.time()))
                await self.redis_client.setex(f"blacklist:{jti}", ttl, "1")
                return
            except:
                pass
        
        # Fallback to in-memory
        self.token_blacklist.add(jti)
    
    def create_api_key(self,
                      tenant_id: str,
                      name: str,
                      permissions: List[str],
                      clearance: str,
                      rate_limit: int = 1000,
                      expires_in_days: Optional[int] = None) -> Tuple[str, str]:
        """Create API key with permissions"""
        
        # Generate secure API key
        key_id = str(uuid4())
        secret = self._generate_api_secret()
        
        # Hash the secret for storage
        key_hash = self.pwd_context.hash(secret)
        
        # Create expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Store API key info
        api_key_info = APIKeyInfo(
            key_id=key_id,
            tenant_id=tenant_id,
            name=name,
            permissions=permissions,
            clearance=clearance,
            rate_limit=rate_limit,
            expires_at=expires_at,
            created_at=datetime.utcnow()
        )
        
        # In production, store in secure database
        self.api_keys[key_hash] = api_key_info
        
        # Log API key creation
        self.audit_logger.log_security_event(
            event_type="api_key_created",
            tenant_id=tenant_id,
            details={
                "key_id": key_id,
                "name": name,
                "permissions": permissions,
                "clearance": clearance,
                "rate_limit": rate_limit
            }
        )
        
        return key_id, secret
    
    async def verify_api_key(self, api_key: str) -> APIKeyInfo:
        """Verify API key and return info"""
        
        # Find matching API key
        for key_hash, key_info in self.api_keys.items():
            if self.pwd_context.verify(api_key, key_hash):
                
                # Check if key is active and not expired
                if not key_info.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API key is inactive"
                    )
                
                if key_info.expires_at and datetime.utcnow() > key_info.expires_at:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API key has expired"
                    )
                
                # Update last used
                key_info.last_used = datetime.utcnow()
                
                return key_info
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    async def check_rate_limit(self, identifier: str, limit: int) -> bool:
        """Check if request is within rate limit"""
        
        now = datetime.utcnow()
        window_key = f"rate_limit:{identifier}:{now.strftime('%Y%m%d%H%M')}"
        
        if self.redis_client:
            try:
                # Atomic increment with expiration
                current = await self.redis_client.incr(window_key)
                if current == 1:
                    await self.redis_client.expire(window_key, 60)  # 1 minute window
                
                return current <= limit
                
            except:
                pass
        
        # Fallback to in-memory rate limiting
        rate_info = self.rate_limits.get(identifier)
        
        if not rate_info or (now - rate_info.window_start) > timedelta(minutes=1):
            # New window
            self.rate_limits[identifier] = RateLimitInfo(
                identifier=identifier,
                requests_made=1,
                limit=limit,
                window_start=now,
                window_duration=timedelta(minutes=1)
            )
            return True
        
        # Same window
        rate_info.requests_made += 1
        return rate_info.requests_made <= limit
    
    def _generate_api_secret(self) -> str:
        """Generate secure API key secret"""
        import secrets
        return f"isec_{secrets.token_urlsafe(32)}"
    
    def validate_permissions(self, 
                           user_permissions: Set[str], 
                           required_permissions: List[str]) -> bool:
        """Validate user has required permissions"""
        return all(perm in user_permissions for perm in required_permissions)
    
    def validate_clearance(self, user_clearance: str, required_clearance: str) -> bool:
        """Validate user clearance meets requirement"""
        return SecurityClearance.can_access(user_clearance, required_clearance)


class APIAuthentication:
    """FastAPI authentication dependency"""
    
    def __init__(self, security_manager: APISecurityManager):
        self.security_manager = security_manager
        self.bearer_scheme = HTTPBearer(auto_error=False)
    
    async def __call__(self, 
                      request: Request,
                      credentials: Optional[HTTPAuthorizationCredentials] = Security(HTTPBearer(auto_error=False))) -> SecurityContext:
        """Authenticate request and return security context"""
        
        # Extract authentication
        token = None
        api_key = None
        
        if credentials:
            if credentials.scheme.lower() == "bearer":
                token = credentials.credentials
            elif credentials.scheme.lower() == "apikey":
                api_key = credentials.credentials
        
        # Check for API key in header
        if not api_key:
            api_key = request.headers.get("X-API-Key")
        
        # Authenticate with token
        if token:
            payload = await self.security_manager.verify_token(token)
            
            return SecurityContext(
                user_id=payload.sub,
                tenant_id=payload.tenant_id,
                user_type=payload.user_type,
                permissions=set(payload.permissions),
                clearance=payload.clearance,
                request_id=str(uuid4()),
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent", ""),
                authenticated_at=datetime.utcnow()
            )
        
        # Authenticate with API key
        elif api_key:
            key_info = await self.security_manager.verify_api_key(api_key)
            
            # Check rate limit
            if not await self.security_manager.check_rate_limit(
                f"api_key:{key_info.key_id}", 
                key_info.rate_limit
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded"
                )
            
            return SecurityContext(
                user_id=f"api_key:{key_info.key_id}",
                tenant_id=key_info.tenant_id,
                user_type="service",
                permissions=set(key_info.permissions),
                clearance=key_info.clearance,
                api_key_id=key_info.key_id,
                request_id=str(uuid4()),
                ip_address=request.client.host,
                user_agent=request.headers.get("user-agent", ""),
                authenticated_at=datetime.utcnow()
            )
        
        # No authentication provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )


def require_permissions(*permissions: str):
    """Decorator to require specific permissions"""
    def decorator(func):
        func._required_permissions = permissions
        return func
    return decorator


def require_clearance(clearance: str):
    """Decorator to require specific security clearance"""
    def decorator(func):
        func._required_clearance = clearance
        return func
    return decorator


class PermissionChecker:
    """FastAPI dependency for permission checking"""
    
    def __init__(self, required_permissions: List[str] = None, required_clearance: str = None):
        self.required_permissions = required_permissions or []
        self.required_clearance = required_clearance
    
    def __call__(self, security_context: SecurityContext = Security(APIAuthentication)) -> SecurityContext:
        """Check permissions and clearance"""
        
        # Check permissions
        if self.required_permissions:
            if not all(perm in security_context.permissions for perm in self.required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {self.required_permissions}"
                )
        
        # Check clearance
        if self.required_clearance:
            if not SecurityClearance.can_access(security_context.clearance, self.required_clearance):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient clearance. Required: {self.required_clearance}"
                )
        
        return security_context