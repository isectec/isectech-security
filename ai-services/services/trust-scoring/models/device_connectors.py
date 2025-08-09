"""
Device Management API Connectors

This module implements real device management API connectors for Microsoft Intune,
VMware Workspace ONE, JAMF, and other MDM platforms to collect actual device
posture data for trust scoring.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import aiohttp
import base64
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class MDMCredentials:
    """Credentials for MDM platform authentication."""
    platform: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    base_url: Optional[str] = None
    additional_params: Dict[str, str] = None


class DeviceConnector(ABC):
    """Abstract base class for device management connectors."""
    
    def __init__(self, credentials: MDMCredentials):
        self.credentials = credentials
        self.session: Optional[aiohttp.ClientSession] = None
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def authenticate(self):
        """Authenticate with the MDM platform."""
        pass
    
    @abstractmethod
    async def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get basic device information."""
        pass
    
    @abstractmethod
    async def get_device_compliance(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device compliance status."""
        pass
    
    @abstractmethod
    async def get_device_apps(self, device_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get installed applications."""
        pass
    
    @abstractmethod 
    async def get_device_patches(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get patch/update status."""
        pass
    
    async def _ensure_authenticated(self):
        """Ensure we have a valid authentication token."""
        if not self.access_token or (
            self.token_expires_at and datetime.utcnow() >= self.token_expires_at
        ):
            await self.authenticate()


class MicrosoftIntuneConnector(DeviceConnector):
    """Microsoft Intune connector for device posture assessment."""
    
    def __init__(self, credentials: MDMCredentials):
        super().__init__(credentials)
        self.graph_base_url = "https://graph.microsoft.com/beta"
        
    async def authenticate(self):
        """Authenticate with Microsoft Graph API."""
        if not self.credentials.tenant_id or not self.credentials.client_id:
            raise ValueError("Microsoft Intune requires tenant_id and client_id")
            
        auth_url = f"https://login.microsoftonline.com/{self.credentials.tenant_id}/oauth2/v2.0/token"
        
        data = {
            "grant_type": "client_credentials",
            "client_id": self.credentials.client_id,
            "client_secret": self.credentials.client_secret,
            "scope": "https://graph.microsoft.com/.default"
        }
        
        try:
            async with self.session.post(auth_url, data=data) as response:
                if response.status == 200:
                    token_data = await response.json()
                    self.access_token = token_data["access_token"]
                    expires_in = token_data.get("expires_in", 3600)
                    self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 60)
                    logger.info("Successfully authenticated with Microsoft Intune")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to authenticate with Intune: {response.status} - {error_text}")
                    raise Exception(f"Authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error authenticating with Microsoft Intune: {e}")
            raise
    
    async def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device information from Intune."""
        await self._ensure_authenticated()
        
        url = f"{self.graph_base_url}/deviceManagement/managedDevices/{device_id}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    device_data = await response.json()
                    return self._transform_intune_device_data(device_data)
                elif response.status == 404:
                    logger.warning(f"Device {device_id} not found in Intune")
                    return None
                else:
                    logger.error(f"Failed to get device info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting device info from Intune: {e}")
            return None
    
    async def get_device_compliance(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device compliance status from Intune."""
        await self._ensure_authenticated()
        
        url = f"{self.graph_base_url}/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    compliance_data = await response.json()
                    return self._transform_intune_compliance_data(compliance_data)
                else:
                    logger.error(f"Failed to get compliance data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting compliance data from Intune: {e}")
            return None
    
    async def get_device_apps(self, device_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get installed apps from Intune."""
        await self._ensure_authenticated()
        
        url = f"{self.graph_base_url}/deviceManagement/managedDevices/{device_id}/detectedApps"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    apps_data = await response.json()
                    return self._transform_intune_apps_data(apps_data)
                else:
                    logger.error(f"Failed to get apps data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting apps data from Intune: {e}")
            return None
    
    async def get_device_patches(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get patch status from Intune."""
        await self._ensure_authenticated()
        
        # Get Windows update states
        url = f"{self.graph_base_url}/deviceManagement/managedDevices/{device_id}/windowsUpdateStates"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    update_data = await response.json()
                    return self._transform_intune_updates_data(update_data)
                else:
                    logger.error(f"Failed to get update data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting update data from Intune: {e}")
            return None
    
    def _transform_intune_device_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Intune device data to standard format."""
        return {
            "device_type": self._map_device_type(data.get("deviceType")),
            "os": self._map_os(data.get("operatingSystem")),
            "os_version": data.get("osVersion"),
            "os_build": data.get("operatingSystem"),
            "device_name": data.get("deviceName"),
            "manufacturer": data.get("manufacturer"),
            "model": data.get("model"),
            "enrollment_date": data.get("enrolledDateTime"),
            "last_sync": data.get("lastSyncDateTime"),
            "compliance_state": data.get("complianceState"),
            "managed": True,
            "mdm_enrolled": True,
            "device_health_attestation": data.get("deviceHealthAttestationState", {})
        }
    
    def _transform_intune_compliance_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Intune compliance data to standard format."""
        policies = data.get("value", [])
        
        compliant_policies = [p for p in policies if p.get("state") == "compliant"]
        total_policies = len(policies)
        
        return {
            "overall_compliance": len(compliant_policies) == total_policies,
            "compliance_score": len(compliant_policies) / max(total_policies, 1),
            "policy_violations": [
                p.get("settingName") for p in policies 
                if p.get("state") in ["nonCompliant", "error"]
            ],
            "last_compliance_check": max(
                (p.get("lastReportedDateTime") for p in policies if p.get("lastReportedDateTime")), 
                default=None
            )
        }
    
    def _transform_intune_apps_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Transform Intune apps data to standard format."""
        apps = data.get("value", [])
        
        return [
            {
                "name": app.get("displayName"),
                "version": app.get("version"),
                "publisher": app.get("publisher"),
                "size_bytes": app.get("sizeInByte"),
                "install_date": app.get("installedDateTime"),
                "device_count": app.get("deviceCount")
            }
            for app in apps
        ]
    
    def _transform_intune_updates_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Intune update data to standard format."""
        updates = data.get("value", [])
        
        if not updates:
            return {
                "last_patch_date": None,
                "patches_pending": 0,
                "critical_patches_pending": 0,
                "auto_updates_enabled": False
            }
        
        latest_update = max(updates, key=lambda x: x.get("lastScanDateTime", ""))
        
        pending_updates = [u for u in updates if u.get("state") in ["pendingInstall", "pendingReboot"]]
        critical_updates = [u for u in pending_updates if u.get("classification") == "Critical"]
        
        return {
            "last_patch_date": latest_update.get("lastSuccessfulScanDateTime"),
            "patches_pending": len(pending_updates),
            "critical_patches_pending": len(critical_updates),
            "auto_updates_enabled": latest_update.get("automaticUpdateEnabled", False),
            "last_scan": latest_update.get("lastScanDateTime"),
            "reboot_required": any(u.get("state") == "pendingReboot" for u in updates)
        }
    
    def _map_device_type(self, intune_type: str) -> str:
        """Map Intune device type to standard format."""
        mapping = {
            "desktop": "desktop",
            "laptop": "laptop",
            "phone": "mobile",
            "tablet": "tablet",
            "holoLens": "iot",
            "surfaceHub": "iot"
        }
        return mapping.get(intune_type, "unknown")
    
    def _map_os(self, intune_os: str) -> str:
        """Map Intune OS to standard format."""
        if not intune_os:
            return "unknown"
        
        intune_os_lower = intune_os.lower()
        if "windows" in intune_os_lower:
            return "windows"
        elif "macos" in intune_os_lower or "mac" in intune_os_lower:
            return "macos"
        elif "android" in intune_os_lower:
            return "android"
        elif "ios" in intune_os_lower:
            return "ios"
        elif "linux" in intune_os_lower:
            return "linux"
        else:
            return "unknown"


class VMwareWorkspaceOneConnector(DeviceConnector):
    """VMware Workspace ONE connector for device posture assessment."""
    
    def __init__(self, credentials: MDMCredentials):
        super().__init__(credentials)
        self.base_url = credentials.base_url or "https://as1234.awmdm.com"
        
    async def authenticate(self):
        """Authenticate with Workspace ONE API."""
        if not self.credentials.username or not self.credentials.password:
            raise ValueError("VMware Workspace ONE requires username and password")
            
        auth_string = f"{self.credentials.username}:{self.credentials.password}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        self.access_token = auth_b64
        # Workspace ONE uses basic auth, so token doesn't expire
        logger.info("Successfully authenticated with VMware Workspace ONE")
    
    async def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device information from Workspace ONE."""
        await self._ensure_authenticated()
        
        url = f"{self.base_url}/API/mdm/devices/{device_id}"
        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Accept": "application/json",
            "aw-tenant-code": self.credentials.api_key
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    device_data = await response.json()
                    return self._transform_ws1_device_data(device_data)
                elif response.status == 404:
                    logger.warning(f"Device {device_id} not found in Workspace ONE")
                    return None
                else:
                    logger.error(f"Failed to get device info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting device info from Workspace ONE: {e}")
            return None
    
    async def get_device_compliance(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device compliance from Workspace ONE."""
        await self._ensure_authenticated()
        
        url = f"{self.base_url}/API/mdm/devices/{device_id}/compliance"
        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Accept": "application/json",
            "aw-tenant-code": self.credentials.api_key
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    compliance_data = await response.json()
                    return self._transform_ws1_compliance_data(compliance_data)
                else:
                    logger.error(f"Failed to get compliance data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting compliance data from Workspace ONE: {e}")
            return None
    
    async def get_device_apps(self, device_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get installed apps from Workspace ONE."""
        await self._ensure_authenticated()
        
        url = f"{self.base_url}/API/mdm/devices/{device_id}/apps"
        headers = {
            "Authorization": f"Basic {self.access_token}",
            "Accept": "application/json",
            "aw-tenant-code": self.credentials.api_key
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    apps_data = await response.json()
                    return self._transform_ws1_apps_data(apps_data)
                else:
                    logger.error(f"Failed to get apps data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting apps data from Workspace ONE: {e}")
            return None
    
    async def get_device_patches(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get patch status from Workspace ONE."""
        # Workspace ONE patch information is typically included in device info
        device_info = await self.get_device_info(device_id)
        if device_info:
            return {
                "last_patch_date": device_info.get("last_sync"),
                "patches_pending": 0,  # Would need specific patch management API
                "critical_patches_pending": 0,
                "auto_updates_enabled": device_info.get("auto_updates", False)
            }
        return None
    
    def _transform_ws1_device_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Workspace ONE device data to standard format."""
        return {
            "device_type": self._map_device_type(data.get("Platform")),
            "os": self._map_os(data.get("Platform")),
            "os_version": data.get("OperatingSystem"),
            "device_name": data.get("DeviceFriendlyName"),
            "manufacturer": data.get("DeviceManufacturer"),
            "model": data.get("Model"),
            "enrollment_date": data.get("EnrolledOn"),
            "last_sync": data.get("LastSeen"),
            "compliance_state": "compliant" if data.get("ComplianceStatus") else "nonCompliant",
            "managed": True,
            "mdm_enrolled": True,
            "supervised": data.get("IsSupervised", False)
        }
    
    def _transform_ws1_compliance_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Workspace ONE compliance data to standard format."""
        return {
            "overall_compliance": data.get("IsCompliant", False),
            "compliance_score": 1.0 if data.get("IsCompliant") else 0.0,
            "policy_violations": data.get("NonComplianceReasons", []),
            "last_compliance_check": data.get("LastComplianceCheck")
        }
    
    def _transform_ws1_apps_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Transform Workspace ONE apps data to standard format."""
        apps = data.get("Application", [])
        
        return [
            {
                "name": app.get("ApplicationName"),
                "version": app.get("Version"),
                "bundle_id": app.get("BundleId"),
                "install_date": app.get("InstalledOn"),
                "status": app.get("Status")
            }
            for app in apps
        ]
    
    def _map_device_type(self, platform: str) -> str:
        """Map Workspace ONE platform to device type."""
        if not platform:
            return "unknown"
        
        platform_lower = platform.lower()
        if "apple" in platform_lower:
            return "laptop" if "mac" in platform_lower else "mobile"
        elif "android" in platform_lower:
            return "mobile"
        elif "windows" in platform_lower:
            return "desktop"
        else:
            return "unknown"
    
    def _map_os(self, platform: str) -> str:
        """Map Workspace ONE platform to OS."""
        if not platform:
            return "unknown"
        
        platform_lower = platform.lower()
        if "apple" in platform_lower:
            return "macos" if "mac" in platform_lower else "ios"
        elif "android" in platform_lower:
            return "android"
        elif "windows" in platform_lower:
            return "windows"
        else:
            return "unknown"


class JAMFConnector(DeviceConnector):
    """JAMF Pro connector for macOS device posture assessment."""
    
    def __init__(self, credentials: MDMCredentials):
        super().__init__(credentials)
        self.base_url = credentials.base_url or "https://your-jamf-server.jamfcloud.com"
        
    async def authenticate(self):
        """Authenticate with JAMF Pro API."""
        if not self.credentials.username or not self.credentials.password:
            raise ValueError("JAMF Pro requires username and password")
            
        auth_url = f"{self.base_url}/api/v1/auth/token"
        
        auth_string = f"{self.credentials.username}:{self.credentials.password}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        headers = {
            "Authorization": f"Basic {auth_b64}",
            "Accept": "application/json"
        }
        
        try:
            async with self.session.post(auth_url, headers=headers) as response:
                if response.status == 200:
                    token_data = await response.json()
                    self.access_token = token_data["token"]
                    expires_in = token_data.get("expires", 1800)  # 30 minutes default
                    self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 60)
                    logger.info("Successfully authenticated with JAMF Pro")
                else:
                    logger.error(f"Failed to authenticate with JAMF: {response.status}")
                    raise Exception(f"Authentication failed: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error authenticating with JAMF Pro: {e}")
            raise
    
    async def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device information from JAMF Pro."""
        await self._ensure_authenticated()
        
        url = f"{self.base_url}/JSSResource/computers/id/{device_id}"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    device_data = await response.json()
                    return self._transform_jamf_device_data(device_data)
                elif response.status == 404:
                    logger.warning(f"Device {device_id} not found in JAMF")
                    return None
                else:
                    logger.error(f"Failed to get device info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting device info from JAMF: {e}")
            return None
    
    async def get_device_compliance(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device compliance from JAMF Pro."""
        await self._ensure_authenticated()
        
        # JAMF uses policies for compliance - get policy status
        url = f"{self.base_url}/JSSResource/computers/id/{device_id}/subset/configuration_profiles"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    profile_data = await response.json()
                    return self._transform_jamf_compliance_data(profile_data)
                else:
                    logger.error(f"Failed to get compliance data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting compliance data from JAMF: {e}")
            return None
    
    async def get_device_apps(self, device_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get installed apps from JAMF Pro."""
        await self._ensure_authenticated()
        
        url = f"{self.base_url}/JSSResource/computers/id/{device_id}/subset/software"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    software_data = await response.json()
                    return self._transform_jamf_apps_data(software_data)
                else:
                    logger.error(f"Failed to get apps data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting apps data from JAMF: {e}")
            return None
    
    async def get_device_patches(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get patch status from JAMF Pro."""
        await self._ensure_authenticated()
        
        url = f"{self.base_url}/JSSResource/computers/id/{device_id}/subset/software"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    software_data = await response.json()
                    return self._transform_jamf_patches_data(software_data)
                else:
                    logger.error(f"Failed to get patch data: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting patch data from JAMF: {e}")
            return None
    
    def _transform_jamf_device_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform JAMF device data to standard format."""
        computer = data.get("computer", {})
        general = computer.get("general", {})
        hardware = computer.get("hardware", {})
        
        return {
            "device_type": "laptop",  # JAMF manages mostly macOS devices
            "os": "macos",
            "os_version": general.get("operating_system"),
            "os_build": general.get("os_build"),
            "device_name": general.get("name"),
            "manufacturer": "Apple",
            "model": hardware.get("model"),
            "serial_number": general.get("serial_number"),
            "last_check_in": general.get("last_contact_time"),
            "managed": True,
            "supervised": general.get("supervised", False),
            "filevault_enabled": hardware.get("filevault2_users", []) != []
        }
    
    def _transform_jamf_compliance_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform JAMF compliance data to standard format."""
        profiles = data.get("computer", {}).get("configuration_profiles", [])
        
        installed_profiles = [p for p in profiles if p.get("is_removable") is False]
        total_profiles = len(profiles)
        
        return {
            "overall_compliance": len(installed_profiles) == total_profiles,
            "compliance_score": len(installed_profiles) / max(total_profiles, 1),
            "profile_count": total_profiles,
            "installed_profiles": len(installed_profiles),
            "last_compliance_check": None  # Would need additional API call
        }
    
    def _transform_jamf_apps_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Transform JAMF apps data to standard format."""
        applications = data.get("computer", {}).get("software", {}).get("applications", [])
        
        return [
            {
                "name": app.get("name"),
                "version": app.get("version"),
                "bundle_id": app.get("bundle_id"),
                "path": app.get("path")
            }
            for app in applications
        ]
    
    def _transform_jamf_patches_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform JAMF patch data to standard format."""
        # JAMF patch information would come from patch management policies
        # This is a simplified implementation
        return {
            "last_patch_date": None,  # Would need patch policy API
            "patches_pending": 0,
            "critical_patches_pending": 0,
            "auto_updates_enabled": False
        }


class DeviceConnectorFactory:
    """Factory class for creating device management connectors."""
    
    @staticmethod
    def create_connector(credentials: MDMCredentials) -> DeviceConnector:
        """Create appropriate connector based on platform."""
        platform_map = {
            "intune": MicrosoftIntuneConnector,
            "microsoft_intune": MicrosoftIntuneConnector,
            "workspace_one": VMwareWorkspaceOneConnector,
            "vmware": VMwareWorkspaceOneConnector,
            "jamf": JAMFConnector,
            "jamf_pro": JAMFConnector
        }
        
        connector_class = platform_map.get(credentials.platform.lower())
        if not connector_class:
            raise ValueError(f"Unsupported MDM platform: {credentials.platform}")
        
        return connector_class(credentials)


# Export main classes
__all__ = [
    "MDMCredentials",
    "DeviceConnector", 
    "MicrosoftIntuneConnector",
    "VMwareWorkspaceOneConnector",
    "JAMFConnector",
    "DeviceConnectorFactory"
]