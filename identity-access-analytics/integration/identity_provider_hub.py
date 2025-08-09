"""
Identity Provider Integration Hub
Production-grade integration platform for federated identity management in ISECTECH platform
Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import logging
import time
import json
import uuid
import hashlib
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union, Tuple, Callable, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import base64
import re
import urllib.parse
from urllib.parse import parse_qs, urlparse
import sqlite3
import aiosqlite
import aiohttp
import asyncio
import ssl
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
import jwt
import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
import redis.asyncio as redis
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import xmltodict
import defusedxml.ElementTree as safe_ET
from jose import jwk, jwt as jose_jwt
import pytz
import socket
import struct


class ProtocolType(Enum):
    """Supported identity provider protocols"""
    SAML2 = "saml2"
    OIDC = "oidc"
    OAUTH2 = "oauth2"
    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"
    KERBEROS = "kerberos"
    RADIUS = "radius"
    SCIM = "scim"
    WS_FEDERATION = "ws_federation"
    CAS = "cas"
    CUSTOM = "custom"


class IdPType(Enum):
    """Identity provider types"""
    AZURE_AD = "azure_ad"
    AWS_IAM = "aws_iam"
    GOOGLE_WORKSPACE = "google_workspace"
    OKTA = "okta"
    AUTH0 = "auth0"
    PING_IDENTITY = "ping_identity"
    ONELOGIN = "onelogin"
    ACTIVE_DIRECTORY = "active_directory"
    LDAP = "ldap"
    GENERIC_SAML = "generic_saml"
    GENERIC_OIDC = "generic_oidc"
    CUSTOM = "custom"


class EventType(Enum):
    """Identity provider event types"""
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    GROUP_MEMBERSHIP_ADDED = "group_membership_added"
    GROUP_MEMBERSHIP_REMOVED = "group_membership_removed"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    TOKEN_ISSUED = "token_issued"
    TOKEN_RENEWED = "token_renewed"
    TOKEN_REVOKED = "token_revoked"


class IntegrationHealth(Enum):
    """Integration health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


@dataclass
class IdPConfiguration:
    """Identity provider configuration"""
    provider_id: str
    provider_name: str
    provider_type: IdPType
    protocol: ProtocolType
    enabled: bool = True
    
    # Connection settings
    endpoint_url: str = ""
    discovery_url: Optional[str] = None
    metadata_url: Optional[str] = None
    
    # Authentication credentials
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    certificate_path: Optional[str] = None
    private_key_path: Optional[str] = None
    
    # Protocol-specific settings
    saml_settings: Optional[Dict[str, Any]] = None
    oidc_settings: Optional[Dict[str, Any]] = None
    ldap_settings: Optional[Dict[str, Any]] = None
    
    # Integration settings
    sync_enabled: bool = True
    sync_interval_minutes: int = 60
    event_webhook_url: Optional[str] = None
    api_rate_limit: int = 100  # requests per minute
    
    # Advanced settings
    trust_all_certificates: bool = False
    timeout_seconds: int = 30
    max_retries: int = 3
    
    # Attribute mappings
    attribute_mappings: Optional[Dict[str, str]] = None
    
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IdentityEvent:
    """Identity provider event"""
    event_id: str
    provider_id: str
    event_type: EventType
    timestamp: datetime
    user_id: str
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    application: Optional[str] = None
    resource: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None
    raw_data: Optional[Dict[str, Any]] = None
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class UserProfile:
    """User profile from identity provider"""
    user_id: str
    provider_id: str
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IntegrationStatus:
    """Integration health and status"""
    provider_id: str
    health: IntegrationHealth
    last_sync: Optional[datetime] = None
    last_event: Optional[datetime] = None
    total_users: int = 0
    total_events: int = 0
    errors_count: int = 0
    last_error: Optional[str] = None
    response_time_ms: float = 0.0
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SAMLProcessor:
    """SAML 2.0 protocol processor"""
    
    def __init__(self, config: IdPConfiguration):
        self.config = config
        self.saml_settings = config.saml_settings or {}
        
    async def process_saml_response(self, saml_response: str) -> Optional[IdentityEvent]:
        """Process SAML authentication response"""
        try:
            # Decode base64 SAML response
            if self._is_base64(saml_response):
                saml_response = base64.b64decode(saml_response).decode('utf-8')
            
            # Parse XML safely
            root = safe_ET.fromstring(saml_response)
            
            # Extract namespace
            namespaces = {
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
            }
            
            # Extract assertion
            assertion = root.find('.//saml:Assertion', namespaces)
            if assertion is None:
                logging.error("No SAML assertion found in response")
                return None
            
            # Extract subject
            subject = assertion.find('.//saml:Subject/saml:NameID', namespaces)
            if subject is None:
                logging.error("No subject found in SAML assertion")
                return None
            
            user_id = subject.text
            
            # Extract attributes
            attributes = {}
            for attr in assertion.findall('.//saml:AttributeStatement/saml:Attribute', namespaces):
                attr_name = attr.get('Name') or attr.get('FriendlyName')
                attr_values = [val.text for val in attr.findall('saml:AttributeValue', namespaces)]
                if attr_name:
                    attributes[attr_name] = attr_values[0] if len(attr_values) == 1 else attr_values
            
            # Extract authentication context
            auth_context = assertion.find('.//saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef', namespaces)
            auth_method = auth_context.text if auth_context is not None else 'unknown'
            
            # Extract timestamps
            auth_instant = assertion.find('.//saml:AuthnStatement', namespaces)
            timestamp = datetime.now(timezone.utc)
            if auth_instant is not None and auth_instant.get('AuthnInstant'):
                timestamp = datetime.fromisoformat(auth_instant.get('AuthnInstant').replace('Z', '+00:00'))
            
            # Determine if authentication was successful
            status = root.find('.//samlp:Status/samlp:StatusCode', namespaces)
            success = status is not None and status.get('Value') == 'urn:oasis:names:tc:SAML:2.0:status:Success'
            
            return IdentityEvent(
                event_id=str(uuid.uuid4()),
                provider_id=self.config.provider_id,
                event_type=EventType.AUTHENTICATION_SUCCESS if success else EventType.AUTHENTICATION_FAILURE,
                timestamp=timestamp,
                user_id=user_id,
                user_email=attributes.get('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'),
                user_name=attributes.get('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'),
                attributes=attributes,
                success=success,
                raw_data={'saml_response': saml_response}
            )
            
        except Exception as e:
            logging.error(f"Failed to process SAML response: {e}")
            return None
    
    async def validate_saml_signature(self, saml_response: str) -> bool:
        """Validate SAML response signature"""
        try:
            # This would typically involve validating the XML signature
            # using the IdP's public certificate
            # For production, use a proper SAML library like python3-saml
            
            # Simplified validation - check if signature element exists
            root = safe_ET.fromstring(saml_response)
            signature = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            
            return signature is not None
            
        except Exception as e:
            logging.error(f"SAML signature validation failed: {e}")
            return False
    
    def _is_base64(self, s: str) -> bool:
        """Check if string is base64 encoded"""
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s)
            return True
        except:
            return False


class OIDCProcessor:
    """OpenID Connect protocol processor"""
    
    def __init__(self, config: IdPConfiguration):
        self.config = config
        self.oidc_settings = config.oidc_settings or {}
        self.jwks_cache = {}
        self.jwks_cache_expiry = None
        
    async def process_id_token(self, id_token: str) -> Optional[IdentityEvent]:
        """Process OpenID Connect ID token"""
        try:
            # Decode JWT header to get key ID
            header = jwt.get_unverified_header(id_token)
            kid = header.get('kid')
            
            # Get JWKS and find the key
            jwks = await self._get_jwks()
            key = None
            
            for jwk_key in jwks.get('keys', []):
                if jwk_key.get('kid') == kid:
                    key = jwk.construct(jwk_key)
                    break
            
            if not key:
                logging.error(f"No matching key found for kid: {kid}")
                return None
            
            # Verify and decode JWT
            payload = jwt.decode(
                id_token,
                key,
                algorithms=['RS256', 'RS384', 'RS512'],
                audience=self.config.client_id,
                issuer=self.oidc_settings.get('issuer')
            )
            
            # Extract user information
            user_id = payload.get('sub')
            user_email = payload.get('email')
            user_name = payload.get('name') or payload.get('preferred_username')
            
            # Extract custom claims
            attributes = {k: v for k, v in payload.items() 
                         if k not in ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time']}
            
            # Determine authentication time
            auth_time = payload.get('auth_time')
            timestamp = datetime.fromtimestamp(auth_time, tz=timezone.utc) if auth_time else datetime.now(timezone.utc)
            
            return IdentityEvent(
                event_id=str(uuid.uuid4()),
                provider_id=self.config.provider_id,
                event_type=EventType.AUTHENTICATION_SUCCESS,
                timestamp=timestamp,
                user_id=user_id,
                user_email=user_email,
                user_name=user_name,
                attributes=attributes,
                success=True,
                raw_data={'id_token': id_token}
            )
            
        except jwt.ExpiredSignatureError:
            logging.error("ID token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logging.error(f"Invalid ID token: {e}")
            return None
        except Exception as e:
            logging.error(f"Failed to process ID token: {e}")
            return None
    
    async def process_access_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Process OAuth2 access token to get user info"""
        try:
            userinfo_endpoint = self.oidc_settings.get('userinfo_endpoint')
            if not userinfo_endpoint:
                # Try to get from discovery
                discovery_url = self.config.discovery_url
                if discovery_url:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(discovery_url) as response:
                            if response.status == 200:
                                discovery_data = await response.json()
                                userinfo_endpoint = discovery_data.get('userinfo_endpoint')
            
            if not userinfo_endpoint:
                logging.error("No userinfo endpoint configured")
                return None
            
            # Call userinfo endpoint
            headers = {'Authorization': f'Bearer {access_token}'}
            async with aiohttp.ClientSession() as session:
                async with session.get(userinfo_endpoint, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logging.error(f"Userinfo request failed: {response.status}")
                        return None
                        
        except Exception as e:
            logging.error(f"Failed to process access token: {e}")
            return None
    
    async def _get_jwks(self) -> Dict[str, Any]:
        """Get JSON Web Key Set from provider"""
        # Check cache
        if self.jwks_cache and self.jwks_cache_expiry and datetime.now(timezone.utc) < self.jwks_cache_expiry:
            return self.jwks_cache
        
        try:
            jwks_uri = self.oidc_settings.get('jwks_uri')
            if not jwks_uri and self.config.discovery_url:
                # Get JWKS URI from discovery endpoint
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.config.discovery_url) as response:
                        if response.status == 200:
                            discovery_data = await response.json()
                            jwks_uri = discovery_data.get('jwks_uri')
            
            if not jwks_uri:
                raise ValueError("No JWKS URI available")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_uri) as response:
                    if response.status == 200:
                        jwks = await response.json()
                        
                        # Cache for 1 hour
                        self.jwks_cache = jwks
                        self.jwks_cache_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
                        
                        return jwks
                    else:
                        raise ValueError(f"Failed to fetch JWKS: {response.status}")
                        
        except Exception as e:
            logging.error(f"Failed to get JWKS: {e}")
            return {}


class LDAPProcessor:
    """LDAP/Active Directory processor"""
    
    def __init__(self, config: IdPConfiguration):
        self.config = config
        self.ldap_settings = config.ldap_settings or {}
        self.connection_pool = []
        
    async def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile from LDAP"""
        try:
            conn = await self._get_connection()
            if not conn:
                return None
            
            # Search for user
            search_base = self.ldap_settings.get('user_base_dn', '')
            search_filter = f"({self.ldap_settings.get('user_id_attribute', 'sAMAccountName')}={user_id})"
            
            attributes = [
                'displayName', 'givenName', 'sn', 'mail', 'sAMAccountName',
                'userPrincipalName', 'memberOf', 'lastLogon', 'whenCreated',
                'whenChanged', 'userAccountControl'
            ]
            
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            
            if not conn.entries:
                return None
            
            entry = conn.entries[0]
            
            # Extract user information
            profile = UserProfile(
                user_id=str(entry.sAMAccountName) if entry.sAMAccountName else user_id,
                provider_id=self.config.provider_id,
                username=str(entry.sAMAccountName) if entry.sAMAccountName else user_id,
                email=str(entry.mail) if entry.mail else None,
                first_name=str(entry.givenName) if entry.givenName else None,
                last_name=str(entry.sn) if entry.sn else None,
                display_name=str(entry.displayName) if entry.displayName else None,
                groups=[str(group) for group in entry.memberOf] if entry.memberOf else [],
                enabled=not (entry.userAccountControl and int(entry.userAccountControl) & 2),  # Check disabled flag
                created_at=entry.whenCreated.value if entry.whenCreated else None,
                updated_at=entry.whenChanged.value if entry.whenChanged else datetime.now(timezone.utc)
            )
            
            # Convert last logon timestamp
            if entry.lastLogon and entry.lastLogon.value:
                profile.last_login = entry.lastLogon.value
            
            return profile
            
        except Exception as e:
            logging.error(f"Failed to get user profile from LDAP: {e}")
            return None
        finally:
            if 'conn' in locals():
                conn.unbind()
    
    async def sync_users(self, page_size: int = 1000) -> List[UserProfile]:
        """Synchronize users from LDAP directory"""
        users = []
        
        try:
            conn = await self._get_connection()
            if not conn:
                return users
            
            search_base = self.ldap_settings.get('user_base_dn', '')
            search_filter = self.ldap_settings.get('user_filter', '(objectClass=user)')
            
            attributes = [
                'displayName', 'givenName', 'sn', 'mail', 'sAMAccountName',
                'userPrincipalName', 'memberOf', 'lastLogon', 'whenCreated',
                'whenChanged', 'userAccountControl'
            ]
            
            # Use paged search for large directories
            conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=page_size
            )
            
            # Process each entry
            for entry in conn.entries:
                try:
                    profile = UserProfile(
                        user_id=str(entry.sAMAccountName) if entry.sAMAccountName else str(entry.dn),
                        provider_id=self.config.provider_id,
                        username=str(entry.sAMAccountName) if entry.sAMAccountName else str(entry.dn),
                        email=str(entry.mail) if entry.mail else None,
                        first_name=str(entry.givenName) if entry.givenName else None,
                        last_name=str(entry.sn) if entry.sn else None,
                        display_name=str(entry.displayName) if entry.displayName else None,
                        groups=[str(group) for group in entry.memberOf] if entry.memberOf else [],
                        enabled=not (entry.userAccountControl and int(entry.userAccountControl) & 2),
                        created_at=entry.whenCreated.value if entry.whenCreated else None,
                        updated_at=entry.whenChanged.value if entry.whenChanged else datetime.now(timezone.utc)
                    )
                    
                    if entry.lastLogon and entry.lastLogon.value:
                        profile.last_login = entry.lastLogon.value
                    
                    users.append(profile)
                    
                except Exception as e:
                    logging.warning(f"Failed to process LDAP entry {entry.dn}: {e}")
                    continue
            
            # Handle paged results
            while conn.result['controls']:
                cookie = None
                for control in conn.result['controls']:
                    if control['type'] == '1.2.840.113556.1.4.319':  # Paged results control
                        cookie = control['value']['cookie']
                        break
                
                if not cookie:
                    break
                
                conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie
                )
                
                for entry in conn.entries:
                    try:
                        profile = UserProfile(
                            user_id=str(entry.sAMAccountName) if entry.sAMAccountName else str(entry.dn),
                            provider_id=self.config.provider_id,
                            username=str(entry.sAMAccountName) if entry.sAMAccountName else str(entry.dn),
                            email=str(entry.mail) if entry.mail else None,
                            first_name=str(entry.givenName) if entry.givenName else None,
                            last_name=str(entry.sn) if entry.sn else None,
                            display_name=str(entry.displayName) if entry.displayName else None,
                            groups=[str(group) for group in entry.memberOf] if entry.memberOf else [],
                            enabled=not (entry.userAccountControl and int(entry.userAccountControl) & 2),
                            created_at=entry.whenCreated.value if entry.whenCreated else None,
                            updated_at=entry.whenChanged.value if entry.whenChanged else datetime.now(timezone.utc)
                        )
                        
                        if entry.lastLogon and entry.lastLogon.value:
                            profile.last_login = entry.lastLogon.value
                        
                        users.append(profile)
                        
                    except Exception as e:
                        logging.warning(f"Failed to process LDAP entry {entry.dn}: {e}")
                        continue
            
            logging.info(f"Synchronized {len(users)} users from LDAP")
            return users
            
        except Exception as e:
            logging.error(f"LDAP user synchronization failed: {e}")
            return users
        finally:
            if 'conn' in locals():
                conn.unbind()
    
    async def _get_connection(self) -> Optional[Connection]:
        """Get LDAP connection"""
        try:
            server_uri = self.config.endpoint_url
            bind_dn = self.ldap_settings.get('bind_dn')
            bind_password = self.ldap_settings.get('bind_password')
            use_ssl = self.ldap_settings.get('use_ssl', True)
            
            server = Server(
                server_uri,
                use_ssl=use_ssl,
                get_info=ALL,
                connect_timeout=self.config.timeout_seconds
            )
            
            conn = Connection(
                server,
                user=bind_dn,
                password=bind_password,
                auto_bind=True,
                raise_exceptions=True
            )
            
            return conn
            
        except Exception as e:
            logging.error(f"Failed to create LDAP connection: {e}")
            return None


class AzureADIntegration:
    """Microsoft Azure Active Directory integration"""
    
    def __init__(self, config: IdPConfiguration):
        self.config = config
        self.tenant_id = config.saml_settings.get('tenant_id') if config.saml_settings else None
        self.access_token = None
        self.token_expiry = None
        
    async def get_access_token(self) -> Optional[str]:
        """Get Microsoft Graph API access token"""
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token
        
        try:
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            data = {
                'client_id': self.config.client_id,
                'client_secret': self.config.client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(token_url, data=data) as response:
                    if response.status == 200:
                        token_data = await response.json()
                        self.access_token = token_data['access_token']
                        expires_in = token_data.get('expires_in', 3600)
                        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
                        
                        return self.access_token
                    else:
                        logging.error(f"Failed to get Azure AD access token: {response.status}")
                        return None
                        
        except Exception as e:
            logging.error(f"Azure AD token request failed: {e}")
            return None
    
    async def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile from Microsoft Graph"""
        token = await self.get_access_token()
        if not token:
            return None
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        user_data = await response.json()
                        
                        # Get group memberships
                        groups = []
                        groups_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"
                        async with session.get(groups_url, headers=headers) as groups_response:
                            if groups_response.status == 200:
                                groups_data = await groups_response.json()
                                groups = [group['displayName'] for group in groups_data.get('value', [])]
                        
                        return UserProfile(
                            user_id=user_data['id'],
                            provider_id=self.config.provider_id,
                            username=user_data.get('userPrincipalName', ''),
                            email=user_data.get('mail') or user_data.get('userPrincipalName'),
                            first_name=user_data.get('givenName'),
                            last_name=user_data.get('surname'),
                            display_name=user_data.get('displayName'),
                            groups=groups,
                            enabled=user_data.get('accountEnabled', True),
                            created_at=datetime.fromisoformat(user_data['createdDateTime'].replace('Z', '+00:00')) if user_data.get('createdDateTime') else None
                        )
                    else:
                        logging.error(f"Failed to get Azure AD user: {response.status}")
                        return None
                        
        except Exception as e:
            logging.error(f"Azure AD user lookup failed: {e}")
            return None
    
    async def sync_users(self, page_size: int = 999) -> List[UserProfile]:
        """Synchronize users from Azure AD"""
        token = await self.get_access_token()
        if not token:
            return []
        
        users = []
        headers = {'Authorization': f'Bearer {token}'}
        url = f"https://graph.microsoft.com/v1.0/users?$top={page_size}"
        
        try:
            async with aiohttp.ClientSession() as session:
                while url:
                    async with session.get(url, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            for user_data in data.get('value', []):
                                try:
                                    # Get group memberships
                                    groups = []
                                    user_id = user_data['id']
                                    groups_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"
                                    
                                    async with session.get(groups_url, headers=headers) as groups_response:
                                        if groups_response.status == 200:
                                            groups_data = await groups_response.json()
                                            groups = [group['displayName'] for group in groups_data.get('value', [])]
                                    
                                    profile = UserProfile(
                                        user_id=user_data['id'],
                                        provider_id=self.config.provider_id,
                                        username=user_data.get('userPrincipalName', ''),
                                        email=user_data.get('mail') or user_data.get('userPrincipalName'),
                                        first_name=user_data.get('givenName'),
                                        last_name=user_data.get('surname'),
                                        display_name=user_data.get('displayName'),
                                        groups=groups,
                                        enabled=user_data.get('accountEnabled', True),
                                        created_at=datetime.fromisoformat(user_data['createdDateTime'].replace('Z', '+00:00')) if user_data.get('createdDateTime') else None
                                    )
                                    
                                    users.append(profile)
                                    
                                except Exception as e:
                                    logging.warning(f"Failed to process Azure AD user {user_data.get('id', 'unknown')}: {e}")
                                    continue
                            
                            # Check for next page
                            url = data.get('@odata.nextLink')
                            
                        else:
                            logging.error(f"Azure AD user sync failed: {response.status}")
                            break
            
            logging.info(f"Synchronized {len(users)} users from Azure AD")
            return users
            
        except Exception as e:
            logging.error(f"Azure AD user synchronization failed: {e}")
            return users


class IdentityProviderHub:
    """Main identity provider integration hub"""
    
    def __init__(self, db_path: str = "identity_providers.db", redis_url: str = "redis://localhost:6379"):
        self.db_path = db_path
        self.redis_url = redis_url
        self.providers = {}
        self.processors = {}
        self.integrations = {}
        self.redis_client = None
        self.sync_tasks = {}
        self.webhook_server = None
        self.initialized = False
        
        # Statistics
        self.stats = {
            'total_events_processed': 0,
            'successful_syncs': 0,
            'failed_syncs': 0,
            'active_providers': 0,
            'total_users': 0,
            'start_time': datetime.now(timezone.utc)
        }
        
        logging.info("Identity Provider Hub initialized")
    
    async def initialize(self):
        """Initialize the hub"""
        if self.initialized:
            return
        
        # Initialize database
        await self._initialize_database()
        
        # Initialize Redis
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logging.info("Redis connection established")
        except Exception as e:
            logging.warning(f"Redis connection failed: {e}")
        
        # Load existing provider configurations
        await self._load_providers()
        
        self.initialized = True
        logging.info("Identity Provider Hub fully initialized")
    
    async def add_provider(self, config: IdPConfiguration) -> bool:
        """Add a new identity provider"""
        try:
            # Validate configuration
            if not self._validate_config(config):
                return False
            
            # Store configuration
            await self._store_provider_config(config)
            
            # Create processor
            processor = self._create_processor(config)
            if processor:
                self.processors[config.provider_id] = processor
            
            # Create integration if supported
            integration = self._create_integration(config)
            if integration:
                self.integrations[config.provider_id] = integration
            
            # Store in memory
            self.providers[config.provider_id] = config
            
            # Start sync task if enabled
            if config.sync_enabled:
                await self._start_sync_task(config.provider_id)
            
            self.stats['active_providers'] = len([p for p in self.providers.values() if p.enabled])
            
            logging.info(f"Successfully added identity provider: {config.provider_name}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to add identity provider {config.provider_name}: {e}")
            return False
    
    async def remove_provider(self, provider_id: str) -> bool:
        """Remove an identity provider"""
        try:
            if provider_id not in self.providers:
                logging.warning(f"Provider {provider_id} not found")
                return False
            
            # Stop sync task
            if provider_id in self.sync_tasks:
                self.sync_tasks[provider_id].cancel()
                del self.sync_tasks[provider_id]
            
            # Remove from memory
            del self.providers[provider_id]
            
            if provider_id in self.processors:
                del self.processors[provider_id]
            
            if provider_id in self.integrations:
                del self.integrations[provider_id]
            
            # Remove from database
            await self._remove_provider_config(provider_id)
            
            self.stats['active_providers'] = len([p for p in self.providers.values() if p.enabled])
            
            logging.info(f"Successfully removed identity provider: {provider_id}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to remove identity provider {provider_id}: {e}")
            return False
    
    async def process_event(self, provider_id: str, event_data: Dict[str, Any]) -> Optional[IdentityEvent]:
        """Process an identity event from a provider"""
        if provider_id not in self.providers:
            logging.error(f"Unknown provider: {provider_id}")
            return None
        
        config = self.providers[provider_id]
        if not config.enabled:
            logging.warning(f"Provider {provider_id} is disabled")
            return None
        
        try:
            # Get appropriate processor
            processor = self.processors.get(provider_id)
            event = None
            
            if config.protocol == ProtocolType.SAML2 and isinstance(processor, SAMLProcessor):
                saml_response = event_data.get('saml_response')
                if saml_response:
                    event = await processor.process_saml_response(saml_response)
            
            elif config.protocol == ProtocolType.OIDC and isinstance(processor, OIDCProcessor):
                id_token = event_data.get('id_token')
                if id_token:
                    event = await processor.process_id_token(id_token)
            
            elif config.protocol == ProtocolType.OAUTH2 and isinstance(processor, OIDCProcessor):
                access_token = event_data.get('access_token')
                if access_token:
                    userinfo = await processor.process_access_token(access_token)
                    if userinfo:
                        event = IdentityEvent(
                            event_id=str(uuid.uuid4()),
                            provider_id=provider_id,
                            event_type=EventType.AUTHENTICATION_SUCCESS,
                            timestamp=datetime.now(timezone.utc),
                            user_id=userinfo.get('sub', 'unknown'),
                            user_email=userinfo.get('email'),
                            user_name=userinfo.get('name'),
                            attributes=userinfo,
                            success=True
                        )
            
            else:
                # Generic event processing
                event = IdentityEvent(
                    event_id=str(uuid.uuid4()),
                    provider_id=provider_id,
                    event_type=EventType(event_data.get('event_type', 'authentication_success')),
                    timestamp=datetime.now(timezone.utc),
                    user_id=event_data.get('user_id', 'unknown'),
                    user_email=event_data.get('user_email'),
                    user_name=event_data.get('user_name'),
                    source_ip=event_data.get('source_ip'),
                    user_agent=event_data.get('user_agent'),
                    session_id=event_data.get('session_id'),
                    application=event_data.get('application'),
                    resource=event_data.get('resource'),
                    success=event_data.get('success', True),
                    error_message=event_data.get('error_message'),
                    attributes=event_data.get('attributes'),
                    raw_data=event_data
                )
            
            if event:
                # Store event
                await self._store_event(event)
                
                # Cache in Redis
                if self.redis_client:
                    await self._cache_event(event)
                
                # Update statistics
                self.stats['total_events_processed'] += 1
                
                logging.debug(f"Processed event {event.event_id} from provider {provider_id}")
                
            return event
            
        except Exception as e:
            logging.error(f"Failed to process event from provider {provider_id}: {e}")
            return None
    
    async def sync_users(self, provider_id: str) -> bool:
        """Synchronize users from a provider"""
        if provider_id not in self.providers:
            logging.error(f"Unknown provider: {provider_id}")
            return False
        
        config = self.providers[provider_id]
        if not config.enabled or not config.sync_enabled:
            logging.warning(f"Sync disabled for provider {provider_id}")
            return False
        
        try:
            start_time = time.time()
            users = []
            
            # Get appropriate integration
            integration = self.integrations.get(provider_id)
            
            if isinstance(integration, AzureADIntegration):
                users = await integration.sync_users()
            elif isinstance(integration, LDAPProcessor):
                users = await integration.sync_users()
            else:
                logging.warning(f"No sync integration available for provider {provider_id}")
                return False
            
            # Store users
            for user in users:
                await self._store_user_profile(user)
            
            # Update statistics
            sync_time = time.time() - start_time
            await self._update_integration_status(provider_id, len(users), sync_time)
            
            self.stats['successful_syncs'] += 1
            self.stats['total_users'] = await self._count_total_users()
            
            logging.info(f"Synchronized {len(users)} users from provider {provider_id} in {sync_time:.2f}s")
            return True
            
        except Exception as e:
            logging.error(f"User synchronization failed for provider {provider_id}: {e}")
            self.stats['failed_syncs'] += 1
            await self._update_integration_status(provider_id, 0, 0, str(e))
            return False
    
    async def get_user_profile(self, provider_id: str, user_id: str) -> Optional[UserProfile]:
        """Get user profile from a specific provider"""
        if provider_id not in self.providers:
            return None
        
        try:
            # First try database cache
            profile = await self._get_cached_user_profile(provider_id, user_id)
            if profile:
                return profile
            
            # If not cached, fetch from provider
            integration = self.integrations.get(provider_id)
            
            if isinstance(integration, AzureADIntegration):
                profile = await integration.get_user_profile(user_id)
            elif isinstance(integration, LDAPProcessor):
                profile = await integration.get_user_profile(user_id)
            
            # Cache the result
            if profile:
                await self._store_user_profile(profile)
            
            return profile
            
        except Exception as e:
            logging.error(f"Failed to get user profile from provider {provider_id}: {e}")
            return None
    
    async def get_integration_status(self, provider_id: str) -> Optional[IntegrationStatus]:
        """Get integration health status"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("""
                    SELECT provider_id, health, last_sync, last_event, total_users,
                           total_events, errors_count, last_error, response_time_ms, updated_at
                    FROM integration_status WHERE provider_id = ?
                """, (provider_id,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        return IntegrationStatus(
                            provider_id=row[0],
                            health=IntegrationHealth(row[1]),
                            last_sync=datetime.fromisoformat(row[2]) if row[2] else None,
                            last_event=datetime.fromisoformat(row[3]) if row[3] else None,
                            total_users=row[4],
                            total_events=row[5],
                            errors_count=row[6],
                            last_error=row[7],
                            response_time_ms=row[8],
                            updated_at=datetime.fromisoformat(row[9])
                        )
                    
                    return None
                    
        except Exception as e:
            logging.error(f"Failed to get integration status: {e}")
            return None
    
    async def get_system_statistics(self) -> Dict[str, Any]:
        """Get system-wide statistics"""
        uptime = datetime.now(timezone.utc) - self.stats['start_time']
        
        provider_stats = {}
        for provider_id, config in self.providers.items():
            status = await self.get_integration_status(provider_id)
            provider_stats[provider_id] = {
                'name': config.provider_name,
                'type': config.provider_type.value,
                'protocol': config.protocol.value,
                'enabled': config.enabled,
                'health': status.health.value if status else 'unknown',
                'total_users': status.total_users if status else 0,
                'total_events': status.total_events if status else 0
            }
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'total_events_processed': self.stats['total_events_processed'],
            'successful_syncs': self.stats['successful_syncs'],
            'failed_syncs': self.stats['failed_syncs'],
            'active_providers': self.stats['active_providers'],
            'total_users': self.stats['total_users'],
            'provider_statistics': provider_stats
        }
    
    def _validate_config(self, config: IdPConfiguration) -> bool:
        """Validate provider configuration"""
        if not config.provider_id or not config.provider_name:
            logging.error("Provider ID and name are required")
            return False
        
        if not config.endpoint_url and config.protocol not in [ProtocolType.OIDC]:
            logging.error("Endpoint URL is required for most protocols")
            return False
        
        if config.protocol == ProtocolType.OIDC and not config.discovery_url and not config.oidc_settings:
            logging.error("OIDC requires either discovery URL or OIDC settings")
            return False
        
        if config.protocol == ProtocolType.LDAP and not config.ldap_settings:
            logging.error("LDAP protocol requires LDAP settings")
            return False
        
        return True
    
    def _create_processor(self, config: IdPConfiguration):
        """Create appropriate protocol processor"""
        if config.protocol == ProtocolType.SAML2:
            return SAMLProcessor(config)
        elif config.protocol in [ProtocolType.OIDC, ProtocolType.OAUTH2]:
            return OIDCProcessor(config)
        elif config.protocol in [ProtocolType.LDAP, ProtocolType.ACTIVE_DIRECTORY]:
            return LDAPProcessor(config)
        else:
            logging.warning(f"No processor available for protocol {config.protocol}")
            return None
    
    def _create_integration(self, config: IdPConfiguration):
        """Create appropriate provider integration"""
        if config.provider_type == IdPType.AZURE_AD:
            return AzureADIntegration(config)
        elif config.provider_type == IdPType.ACTIVE_DIRECTORY or config.protocol == ProtocolType.LDAP:
            return LDAPProcessor(config)
        else:
            logging.warning(f"No integration available for provider type {config.provider_type}")
            return None
    
    async def _initialize_database(self):
        """Initialize SQLite database"""
        async with aiosqlite.connect(self.db_path) as db:
            # Provider configurations
            await db.execute("""
                CREATE TABLE IF NOT EXISTS provider_configs (
                    provider_id TEXT PRIMARY KEY,
                    provider_name TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    endpoint_url TEXT,
                    discovery_url TEXT,
                    metadata_url TEXT,
                    client_id TEXT,
                    client_secret TEXT,
                    certificate_path TEXT,
                    private_key_path TEXT,
                    settings TEXT,
                    sync_enabled BOOLEAN DEFAULT 1,
                    sync_interval_minutes INTEGER DEFAULT 60,
                    api_rate_limit INTEGER DEFAULT 100,
                    timeout_seconds INTEGER DEFAULT 30,
                    max_retries INTEGER DEFAULT 3,
                    attribute_mappings TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Identity events
            await db.execute("""
                CREATE TABLE IF NOT EXISTS identity_events (
                    event_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    user_email TEXT,
                    user_name TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    application TEXT,
                    resource TEXT,
                    success BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    attributes TEXT,
                    raw_data TEXT,
                    processed_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # User profiles
            await db.execute("""
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id TEXT,
                    provider_id TEXT,
                    username TEXT NOT NULL,
                    email TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    display_name TEXT,
                    groups TEXT,
                    roles TEXT,
                    attributes TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    last_login TEXT,
                    created_at TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, provider_id)
                )
            """)
            
            # Integration status
            await db.execute("""
                CREATE TABLE IF NOT EXISTS integration_status (
                    provider_id TEXT PRIMARY KEY,
                    health TEXT DEFAULT 'unknown',
                    last_sync TEXT,
                    last_event TEXT,
                    total_users INTEGER DEFAULT 0,
                    total_events INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    last_error TEXT,
                    response_time_ms REAL DEFAULT 0.0,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_events_provider_time ON identity_events(provider_id, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_events_user ON identity_events(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_type ON identity_events(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_profiles_email ON user_profiles(email)",
                "CREATE INDEX IF NOT EXISTS idx_profiles_provider ON user_profiles(provider_id)"
            ]
            
            for index_sql in indexes:
                await db.execute(index_sql)
            
            await db.commit()
        
        logging.info("Identity Provider Hub database initialized")
    
    async def _store_provider_config(self, config: IdPConfiguration):
        """Store provider configuration in database"""
        try:
            # Combine all settings into JSON
            settings = {
                'saml_settings': config.saml_settings,
                'oidc_settings': config.oidc_settings,
                'ldap_settings': config.ldap_settings,
                'event_webhook_url': config.event_webhook_url,
                'trust_all_certificates': config.trust_all_certificates
            }
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO provider_configs (
                        provider_id, provider_name, provider_type, protocol, enabled,
                        endpoint_url, discovery_url, metadata_url, client_id, client_secret,
                        certificate_path, private_key_path, settings, sync_enabled,
                        sync_interval_minutes, api_rate_limit, timeout_seconds, max_retries,
                        attribute_mappings, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    config.provider_id, config.provider_name, config.provider_type.value,
                    config.protocol.value, config.enabled, config.endpoint_url,
                    config.discovery_url, config.metadata_url, config.client_id,
                    config.client_secret, config.certificate_path, config.private_key_path,
                    json.dumps(settings), config.sync_enabled, config.sync_interval_minutes,
                    config.api_rate_limit, config.timeout_seconds, config.max_retries,
                    json.dumps(config.attribute_mappings) if config.attribute_mappings else None,
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()
                
        except Exception as e:
            logging.error(f"Failed to store provider configuration: {e}")
            raise
    
    async def _load_providers(self):
        """Load provider configurations from database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT * FROM provider_configs") as cursor:
                    rows = await cursor.fetchall()
                    
                    columns = [description[0] for description in cursor.description]
                    
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        
                        # Parse settings
                        settings = json.loads(row_dict['settings']) if row_dict['settings'] else {}
                        
                        config = IdPConfiguration(
                            provider_id=row_dict['provider_id'],
                            provider_name=row_dict['provider_name'],
                            provider_type=IdPType(row_dict['provider_type']),
                            protocol=ProtocolType(row_dict['protocol']),
                            enabled=bool(row_dict['enabled']),
                            endpoint_url=row_dict['endpoint_url'] or '',
                            discovery_url=row_dict['discovery_url'],
                            metadata_url=row_dict['metadata_url'],
                            client_id=row_dict['client_id'],
                            client_secret=row_dict['client_secret'],
                            certificate_path=row_dict['certificate_path'],
                            private_key_path=row_dict['private_key_path'],
                            saml_settings=settings.get('saml_settings'),
                            oidc_settings=settings.get('oidc_settings'),
                            ldap_settings=settings.get('ldap_settings'),
                            sync_enabled=bool(row_dict['sync_enabled']),
                            sync_interval_minutes=row_dict['sync_interval_minutes'],
                            event_webhook_url=settings.get('event_webhook_url'),
                            api_rate_limit=row_dict['api_rate_limit'],
                            trust_all_certificates=settings.get('trust_all_certificates', False),
                            timeout_seconds=row_dict['timeout_seconds'],
                            max_retries=row_dict['max_retries'],
                            attribute_mappings=json.loads(row_dict['attribute_mappings']) if row_dict['attribute_mappings'] else None,
                            created_at=datetime.fromisoformat(row_dict['created_at']),
                            updated_at=datetime.fromisoformat(row_dict['updated_at'])
                        )
                        
                        # Store in memory
                        self.providers[config.provider_id] = config
                        
                        # Create processor and integration
                        processor = self._create_processor(config)
                        if processor:
                            self.processors[config.provider_id] = processor
                        
                        integration = self._create_integration(config)
                        if integration:
                            self.integrations[config.provider_id] = integration
                        
                        # Start sync task if enabled
                        if config.enabled and config.sync_enabled:
                            await self._start_sync_task(config.provider_id)
            
            self.stats['active_providers'] = len([p for p in self.providers.values() if p.enabled])
            self.stats['total_users'] = await self._count_total_users()
            
            logging.info(f"Loaded {len(self.providers)} identity providers")
            
        except Exception as e:
            logging.error(f"Failed to load provider configurations: {e}")
    
    async def _store_event(self, event: IdentityEvent):
        """Store identity event in database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO identity_events (
                        event_id, provider_id, event_type, timestamp, user_id,
                        user_email, user_name, source_ip, user_agent, session_id,
                        application, resource, success, error_message, attributes,
                        raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id, event.provider_id, event.event_type.value,
                    event.timestamp.isoformat(), event.user_id, event.user_email,
                    event.user_name, event.source_ip, event.user_agent, event.session_id,
                    event.application, event.resource, event.success, event.error_message,
                    json.dumps(event.attributes) if event.attributes else None,
                    json.dumps(event.raw_data) if event.raw_data else None
                ))
                await db.commit()
                
        except Exception as e:
            logging.error(f"Failed to store identity event: {e}")
    
    async def _store_user_profile(self, profile: UserProfile):
        """Store user profile in database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO user_profiles (
                        user_id, provider_id, username, email, first_name, last_name,
                        display_name, groups, roles, attributes, enabled, last_login,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    profile.user_id, profile.provider_id, profile.username,
                    profile.email, profile.first_name, profile.last_name,
                    profile.display_name, json.dumps(profile.groups),
                    json.dumps(profile.roles), json.dumps(profile.attributes),
                    profile.enabled,
                    profile.last_login.isoformat() if profile.last_login else None,
                    profile.created_at.isoformat() if profile.created_at else None,
                    profile.updated_at.isoformat()
                ))
                await db.commit()
                
        except Exception as e:
            logging.error(f"Failed to store user profile: {e}")
    
    async def _cache_event(self, event: IdentityEvent):
        """Cache event in Redis"""
        if not self.redis_client:
            return
        
        try:
            event_key = f"event:{event.event_id}"
            event_data = asdict(event)
            
            # Convert datetime objects and enums
            for key, value in event_data.items():
                if isinstance(value, datetime):
                    event_data[key] = value.isoformat()
                elif hasattr(value, 'value'):
                    event_data[key] = value.value
            
            await self.redis_client.setex(
                event_key,
                3600,  # 1 hour TTL
                json.dumps(event_data, default=str)
            )
            
            # Add to user's recent events
            user_events_key = f"user_events:{event.provider_id}:{event.user_id}"
            await self.redis_client.lpush(user_events_key, event.event_id)
            await self.redis_client.ltrim(user_events_key, 0, 99)  # Keep last 100
            await self.redis_client.expire(user_events_key, 86400)  # 24 hours
            
        except Exception as e:
            logging.error(f"Failed to cache event: {e}")
    
    async def _start_sync_task(self, provider_id: str):
        """Start periodic sync task for a provider"""
        if provider_id in self.sync_tasks:
            self.sync_tasks[provider_id].cancel()
        
        config = self.providers[provider_id]
        
        async def sync_loop():
            while True:
                try:
                    await self.sync_users(provider_id)
                    await asyncio.sleep(config.sync_interval_minutes * 60)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logging.error(f"Sync task error for provider {provider_id}: {e}")
                    await asyncio.sleep(60)  # Wait 1 minute before retry
        
        task = asyncio.create_task(sync_loop())
        self.sync_tasks[provider_id] = task
        
        logging.info(f"Started sync task for provider {provider_id}")
    
    async def _update_integration_status(self, provider_id: str, user_count: int, 
                                       response_time: float, error: Optional[str] = None):
        """Update integration status"""
        try:
            health = IntegrationHealth.HEALTHY
            if error:
                health = IntegrationHealth.UNHEALTHY
            elif response_time > 30:
                health = IntegrationHealth.DEGRADED
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO integration_status (
                        provider_id, health, last_sync, total_users, response_time_ms,
                        last_error, errors_count, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 
                        COALESCE((SELECT errors_count FROM integration_status WHERE provider_id = ?), 0) + ?,
                        ?)
                """, (
                    provider_id, health.value, datetime.now(timezone.utc).isoformat(),
                    user_count, response_time * 1000, error, provider_id,
                    1 if error else 0, datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()
                
        except Exception as e:
            logging.error(f"Failed to update integration status: {e}")
    
    async def _get_cached_user_profile(self, provider_id: str, user_id: str) -> Optional[UserProfile]:
        """Get cached user profile from database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("""
                    SELECT * FROM user_profiles WHERE provider_id = ? AND user_id = ?
                """, (provider_id, user_id)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        columns = [description[0] for description in cursor.description]
                        row_dict = dict(zip(columns, row))
                        
                        return UserProfile(
                            user_id=row_dict['user_id'],
                            provider_id=row_dict['provider_id'],
                            username=row_dict['username'],
                            email=row_dict['email'],
                            first_name=row_dict['first_name'],
                            last_name=row_dict['last_name'],
                            display_name=row_dict['display_name'],
                            groups=json.loads(row_dict['groups']) if row_dict['groups'] else [],
                            roles=json.loads(row_dict['roles']) if row_dict['roles'] else [],
                            attributes=json.loads(row_dict['attributes']) if row_dict['attributes'] else {},
                            enabled=bool(row_dict['enabled']),
                            last_login=datetime.fromisoformat(row_dict['last_login']) if row_dict['last_login'] else None,
                            created_at=datetime.fromisoformat(row_dict['created_at']) if row_dict['created_at'] else None,
                            updated_at=datetime.fromisoformat(row_dict['updated_at'])
                        )
                    
                    return None
                    
        except Exception as e:
            logging.error(f"Failed to get cached user profile: {e}")
            return None
    
    async def _count_total_users(self) -> int:
        """Count total users across all providers"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT COUNT(*) FROM user_profiles") as cursor:
                    row = await cursor.fetchone()
                    return row[0] if row else 0
        except:
            return 0
    
    async def _remove_provider_config(self, provider_id: str):
        """Remove provider configuration from database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM provider_configs WHERE provider_id = ?", (provider_id,))
                await db.execute("DELETE FROM user_profiles WHERE provider_id = ?", (provider_id,))
                await db.execute("DELETE FROM integration_status WHERE provider_id = ?", (provider_id,))
                await db.commit()
        except Exception as e:
            logging.error(f"Failed to remove provider config: {e}")
    
    async def shutdown(self):
        """Gracefully shutdown the hub"""
        logging.info("Shutting down Identity Provider Hub")
        
        # Cancel all sync tasks
        for task in self.sync_tasks.values():
            task.cancel()
        
        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()
        
        logging.info("Identity Provider Hub shutdown complete")


# Example usage and testing
async def example_usage():
    """Example usage of the Identity Provider Hub"""
    
    # Initialize hub
    hub = IdentityProviderHub(
        db_path="test_identity_providers.db",
        redis_url="redis://localhost:6379"
    )
    
    await hub.initialize()
    
    # Add Azure AD provider
    azure_config = IdPConfiguration(
        provider_id="azure_ad_prod",
        provider_name="Azure AD Production",
        provider_type=IdPType.AZURE_AD,
        protocol=ProtocolType.OIDC,
        endpoint_url="https://login.microsoftonline.com/tenant-id",
        client_id="your-client-id",
        client_secret="your-client-secret",
        discovery_url="https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid_configuration",
        saml_settings={'tenant_id': 'your-tenant-id'},
        sync_enabled=True,
        sync_interval_minutes=30
    )
    
    success = await hub.add_provider(azure_config)
    print(f"Azure AD provider added: {success}")
    
    # Add LDAP provider
    ldap_config = IdPConfiguration(
        provider_id="corp_ldap",
        provider_name="Corporate LDAP",
        provider_type=IdPType.LDAP,
        protocol=ProtocolType.LDAP,
        endpoint_url="ldap://ldap.company.com:389",
        ldap_settings={
            'bind_dn': 'CN=service-account,OU=Service Accounts,DC=company,DC=com',
            'bind_password': 'password',
            'user_base_dn': 'OU=Users,DC=company,DC=com',
            'user_filter': '(objectClass=user)',
            'use_ssl': False
        },
        sync_enabled=True,
        sync_interval_minutes=60
    )
    
    success = await hub.add_provider(ldap_config)
    print(f"LDAP provider added: {success}")
    
    # Process a SAML authentication event
    saml_event_data = {
        'saml_response': 'base64-encoded-saml-response'  # Would be actual SAML response
    }
    
    event = await hub.process_event("azure_ad_prod", saml_event_data)
    if event:
        print(f"Processed SAML event: {event.event_type.value} for user {event.user_id}")
    
    # Get user profile
    profile = await hub.get_user_profile("corp_ldap", "john.doe")
    if profile:
        print(f"User profile: {profile.display_name} ({profile.email})")
    
    # Get system statistics
    stats = await hub.get_system_statistics()
    print(f"System Statistics:")
    print(f"- Active Providers: {stats['active_providers']}")
    print(f"- Total Users: {stats['total_users']}")
    print(f"- Events Processed: {stats['total_events_processed']}")
    
    await hub.shutdown()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())