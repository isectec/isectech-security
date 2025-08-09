"""
Geolocation and IP Enrichment Services

This module provides production-ready integrations with geolocation APIs for IP
address enrichment, location consistency checking, and travel feasibility analysis.
"""

import asyncio
import json
import logging
import math
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import aiohttp
from geopy.distance import geodesic

from .network_context import GeoLocation

logger = logging.getLogger(__name__)


@dataclass
class GeoServiceConfig:
    """Configuration for geolocation service providers."""
    provider_name: str
    api_key: str
    base_url: str
    rate_limit_per_minute: int = 1000
    timeout_seconds: int = 5
    enabled: bool = True
    priority: int = 1


@dataclass
class UserLocationHistory:
    """Historical location data for a user."""
    user_id: str
    locations: List[Tuple[datetime, GeoLocation]] = None
    typical_countries: List[str] = None
    typical_cities: List[str] = None
    home_location: Optional[GeoLocation] = None
    work_location: Optional[GeoLocation] = None
    
    def __post_init__(self):
        if self.locations is None:
            self.locations = []
        if self.typical_countries is None:
            self.typical_countries = []
        if self.typical_cities is None:
            self.typical_cities = []


class GeoLocationProvider(ABC):
    """Abstract base class for geolocation providers."""
    
    def __init__(self, config: GeoServiceConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_count = 0
        self.last_reset_time = datetime.utcnow()
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geolocation data for an IP address."""
        pass
    
    def _check_rate_limit(self) -> bool:
        """Check if within rate limits."""
        now = datetime.utcnow()
        
        # Reset counter every minute
        if (now - self.last_reset_time).seconds >= 60:
            self.request_count = 0
            self.last_reset_time = now
        
        return self.request_count < self.config.rate_limit_per_minute
    
    def _increment_request_count(self):
        """Increment request counter."""
        self.request_count += 1


class MaxMindProvider(GeoLocationProvider):
    """MaxMind GeoIP2 provider (GeoLite2 and GeoIP2 databases)."""
    
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location from MaxMind GeoIP2 API."""
        if not self._check_rate_limit():
            logger.warning("MaxMind rate limit reached")
            return None
        
        try:
            url = f"{self.config.base_url}/geoip/v2.1/city/{ip_address}"
            auth = aiohttp.BasicAuth(self.config.api_key, "")
            
            async with self.session.get(url, auth=auth) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_maxmind_response(data)
                elif response.status == 404:
                    logger.debug(f"MaxMind: IP {ip_address} not found in database")
                    return None
                else:
                    logger.error(f"MaxMind API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying MaxMind for {ip_address}: {e}")
            return None
    
    def _parse_maxmind_response(self, data: Dict[str, Any]) -> GeoLocation:
        """Parse MaxMind API response."""
        country = data.get("country", {})
        subdivisions = data.get("subdivisions", [])
        city = data.get("city", {})
        location = data.get("location", {})
        traits = data.get("traits", {})
        
        region = subdivisions[0].get("names", {}).get("en") if subdivisions else None
        
        return GeoLocation(
            country=country.get("names", {}).get("en"),
            country_code=country.get("iso_code"),
            region=region,
            city=city.get("names", {}).get("en"),
            latitude=location.get("latitude"),
            longitude=location.get("longitude"),
            timezone=location.get("time_zone"),
            isp=traits.get("isp"),
            organization=traits.get("organization"),
            as_number=traits.get("autonomous_system_number"),
            as_organization=traits.get("autonomous_system_organization")
        )


class IPInfoProvider(GeoLocationProvider):
    """IPinfo.io geolocation provider."""
    
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location from IPinfo API."""
        if not self._check_rate_limit():
            logger.warning("IPinfo rate limit reached")
            return None
        
        try:
            url = f"{self.config.base_url}/{ip_address}"
            params = {"token": self.config.api_key}
            
            async with self.session.get(url, params=params) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_ipinfo_response(data)
                elif response.status == 429:
                    logger.warning("IPinfo rate limit exceeded")
                    return None
                else:
                    logger.error(f"IPinfo API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying IPinfo for {ip_address}: {e}")
            return None
    
    def _parse_ipinfo_response(self, data: Dict[str, Any]) -> GeoLocation:
        """Parse IPinfo API response."""
        # Parse coordinates
        loc = data.get("loc", "")
        latitude, longitude = None, None
        if loc and "," in loc:
            try:
                lat_str, lon_str = loc.split(",", 1)
                latitude = float(lat_str.strip())
                longitude = float(lon_str.strip())
            except ValueError:
                pass
        
        return GeoLocation(
            country=data.get("country"),
            region=data.get("region"),
            city=data.get("city"),
            latitude=latitude,
            longitude=longitude,
            timezone=data.get("timezone"),
            isp=data.get("org"),  # IPinfo returns org field for ISP info
            organization=data.get("org")
        )


class IP2LocationProvider(GeoLocationProvider):
    """IP2Location.com geolocation provider."""
    
    async def get_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get location from IP2Location API."""
        if not self._check_rate_limit():
            logger.warning("IP2Location rate limit reached")
            return None
        
        try:
            url = self.config.base_url
            params = {
                "ip": ip_address,
                "key": self.config.api_key,
                "package": "WS24",  # Full package with ISP info
                "format": "json"
            }
            
            async with self.session.get(url, params=params) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_ip2location_response(data)
                elif response.status == 429:
                    logger.warning("IP2Location rate limit exceeded")
                    return None
                else:
                    logger.error(f"IP2Location API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying IP2Location for {ip_address}: {e}")
            return None
    
    def _parse_ip2location_response(self, data: Dict[str, Any]) -> GeoLocation:
        """Parse IP2Location API response."""
        return GeoLocation(
            country=data.get("country_name"),
            country_code=data.get("country_code"),
            region=data.get("region_name"),
            city=data.get("city_name"),
            latitude=float(data.get("latitude", 0)) if data.get("latitude") else None,
            longitude=float(data.get("longitude", 0)) if data.get("longitude") else None,
            timezone=data.get("time_zone"),
            isp=data.get("isp"),
            as_number=int(data.get("asn", 0)) if data.get("asn") else None,
            as_organization=data.get("as")
        )


class GeolocationService:
    """Service for geolocation analysis and location consistency checking."""
    
    def __init__(self, providers: List[GeoLocationProvider]):
        self.providers = sorted(providers, key=lambda p: p.config.priority)
        self.location_cache = {}
        self.cache_ttl = timedelta(hours=24)  # Cache for 24 hours
        self.user_history = {}  # User location history cache
        
        self.metrics = {
            "lookups": 0,
            "cache_hits": 0,
            "provider_queries": {p.config.provider_name: 0 for p in providers},
            "consistency_checks": 0
        }
    
    async def get_ip_location(self, ip_address: str) -> Optional[GeoLocation]:
        """Get geolocation for IP address with provider fallback."""
        # Check cache first
        if ip_address in self.location_cache:
            cached_location, cached_time = self.location_cache[ip_address]
            if datetime.utcnow() - cached_time < self.cache_ttl:
                self.metrics["cache_hits"] += 1
                return cached_location
        
        self.metrics["lookups"] += 1
        
        # Try providers in priority order
        for provider in self.providers:
            if not provider.config.enabled:
                continue
            
            try:
                location = await provider.get_location(ip_address)
                if location and location.country:  # Valid location data
                    self.metrics["provider_queries"][provider.config.provider_name] += 1
                    
                    # Cache the result
                    self.location_cache[ip_address] = (location, datetime.utcnow())
                    
                    return location
                    
            except Exception as e:
                logger.warning(f"Provider {provider.config.provider_name} failed: {e}")
                continue
        
        logger.warning(f"No geolocation data available for {ip_address}")
        return None
    
    async def check_location_consistency(self, 
                                       user_id: str,
                                       current_ip: str,
                                       session_time: datetime = None) -> Tuple[float, float]:
        """Check location consistency and travel feasibility for a user.
        
        Returns:
            Tuple of (location_consistency, travel_feasibility) scores (0.0-1.0)
        """
        self.metrics["consistency_checks"] += 1
        session_time = session_time or datetime.utcnow()
        
        # Get current location
        current_location = await self.get_ip_location(current_ip)
        if not current_location:
            return 0.5, 0.5  # Neutral scores if no location data
        
        # Get user's location history
        user_history = self._get_user_location_history(user_id)
        
        # Add current location to history
        user_history.locations.append((session_time, current_location))
        
        # Keep only last 30 days of location data
        cutoff_date = session_time - timedelta(days=30)
        user_history.locations = [
            (timestamp, location) for timestamp, location in user_history.locations
            if timestamp >= cutoff_date
        ]
        
        # Update user's typical locations
        self._update_typical_locations(user_history)
        
        # Calculate consistency score
        consistency_score = self._calculate_location_consistency(current_location, user_history)
        
        # Calculate travel feasibility
        feasibility_score = self._calculate_travel_feasibility(
            current_location, session_time, user_history
        )
        
        # Update cache
        self.user_history[user_id] = user_history
        
        return consistency_score, feasibility_score
    
    def _get_user_location_history(self, user_id: str) -> UserLocationHistory:
        """Get or create user location history."""
        if user_id not in self.user_history:
            self.user_history[user_id] = UserLocationHistory(user_id=user_id)
        
        return self.user_history[user_id]
    
    def _update_typical_locations(self, user_history: UserLocationHistory):
        """Update user's typical countries and cities."""
        if not user_history.locations:
            return
        
        # Count occurrences of countries and cities
        country_counts = {}
        city_counts = {}
        
        for _, location in user_history.locations:
            if location.country:
                country_counts[location.country] = country_counts.get(location.country, 0) + 1
            if location.city:
                city_counts[location.city] = city_counts.get(location.city, 0) + 1
        
        # Update typical locations (countries/cities with >20% of sessions)
        total_sessions = len(user_history.locations)
        threshold = max(1, total_sessions * 0.2)  # At least 20% of sessions
        
        user_history.typical_countries = [
            country for country, count in country_counts.items()
            if count >= threshold
        ]
        
        user_history.typical_cities = [
            city for city, count in city_counts.items()
            if count >= threshold
        ]
        
        # Set home location (most frequent location during business hours)
        business_hour_locations = []
        for timestamp, location in user_history.locations:
            if 8 <= timestamp.hour <= 18:  # Business hours
                business_hour_locations.append(location)
        
        if business_hour_locations:
            # Find most common business hour location
            location_counts = {}
            for location in business_hour_locations:
                key = (location.city, location.country)
                location_counts[key] = location_counts.get(key, 0) + 1
            
            if location_counts:
                most_common = max(location_counts, key=location_counts.get)
                # Find a representative location for the most common city/country
                for location in business_hour_locations:
                    if location.city == most_common[0] and location.country == most_common[1]:
                        user_history.home_location = location
                        break
    
    def _calculate_location_consistency(self, 
                                      current_location: GeoLocation,
                                      user_history: UserLocationHistory) -> float:
        """Calculate location consistency score (0.0 = inconsistent, 1.0 = consistent)."""
        if not user_history.typical_countries:
            return 0.5  # Neutral for new users
        
        # Check if current country is in typical countries
        if current_location.country in user_history.typical_countries:
            consistency_score = 0.8
            
            # Bonus if city is also typical
            if current_location.city in user_history.typical_cities:
                consistency_score = 0.9
        else:
            # Check neighboring countries or same continent
            consistency_score = 0.3
            
            # Could add continent checking here for better scoring
            # For now, any foreign country gets low consistency
        
        return consistency_score
    
    def _calculate_travel_feasibility(self,
                                    current_location: GeoLocation,
                                    current_time: datetime,
                                    user_history: UserLocationHistory) -> float:
        """Calculate travel feasibility score (0.0 = impossible, 1.0 = feasible)."""
        if not user_history.locations or len(user_history.locations) < 2:
            return 1.0  # No previous location to compare
        
        # Find the most recent previous location
        previous_locations = [
            (timestamp, location) for timestamp, location in user_history.locations
            if timestamp < current_time
        ]
        
        if not previous_locations:
            return 1.0
        
        # Get most recent location
        previous_time, previous_location = max(previous_locations, key=lambda x: x[0])
        
        # Calculate distance between locations
        if (current_location.latitude and current_location.longitude and
            previous_location.latitude and previous_location.longitude):
            
            current_coords = (current_location.latitude, current_location.longitude)
            previous_coords = (previous_location.latitude, previous_location.longitude)
            
            distance_km = geodesic(previous_coords, current_coords).kilometers
            time_diff_hours = (current_time - previous_time).total_seconds() / 3600
            
            if time_diff_hours == 0:
                return 0.0 if distance_km > 1 else 1.0  # Simultaneous distant locations impossible
            
            # Calculate required speed (km/h)
            required_speed = distance_km / time_diff_hours
            
            # Feasibility thresholds
            if required_speed <= 5:  # Walking/local travel
                return 1.0
            elif required_speed <= 100:  # Driving
                return 0.9
            elif required_speed <= 500:  # Domestic flight
                return 0.8
            elif required_speed <= 900:  # International flight
                return 0.7
            elif required_speed <= 1200:  # Fast international flight
                return 0.5
            else:  # Impossible travel speed
                return 0.1
        
        # If no coordinates, use country-level checks
        if current_location.country == previous_location.country:
            return 0.9  # Same country is usually feasible
        else:
            time_diff_hours = (current_time - previous_time).total_seconds() / 3600
            if time_diff_hours >= 2:  # 2+ hours for international travel
                return 0.7
            else:
                return 0.3  # Quick international travel is suspicious
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get geolocation service metrics."""
        cache_hit_rate = (
            self.metrics["cache_hits"] / max(self.metrics["lookups"], 1) * 100
        )
        
        return {
            "total_lookups": self.metrics["lookups"],
            "cache_hits": self.metrics["cache_hits"],
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "consistency_checks": self.metrics["consistency_checks"],
            "provider_queries": self.metrics["provider_queries"],
            "cached_locations": len(self.location_cache),
            "tracked_users": len(self.user_history)
        }
    
    def clear_cache(self):
        """Clear all caches."""
        self.location_cache.clear()
        self.user_history.clear()


def create_geolocation_service() -> GeolocationService:
    """Create geolocation service with available providers."""
    providers = []
    
    # MaxMind GeoIP2
    if os.getenv("MAXMIND_USER_ID") and os.getenv("MAXMIND_LICENSE_KEY"):
        config = GeoServiceConfig(
            provider_name="maxmind",
            api_key=f"{os.getenv('MAXMIND_USER_ID')}:{os.getenv('MAXMIND_LICENSE_KEY')}",
            base_url="https://geoip.maxmind.com",
            rate_limit_per_minute=1000,
            priority=1
        )
        providers.append(MaxMindProvider(config))
    
    # IPinfo
    if os.getenv("IPINFO_API_KEY"):
        config = GeoServiceConfig(
            provider_name="ipinfo",
            api_key=os.getenv("IPINFO_API_KEY"),
            base_url="https://ipinfo.io",
            rate_limit_per_minute=1000,
            priority=2
        )
        providers.append(IPInfoProvider(config))
    
    # IP2Location
    if os.getenv("IP2LOCATION_API_KEY"):
        config = GeoServiceConfig(
            provider_name="ip2location",
            api_key=os.getenv("IP2LOCATION_API_KEY"),
            base_url="https://api.ip2location.com/v2/",
            rate_limit_per_minute=500,
            priority=3
        )
        providers.append(IP2LocationProvider(config))
    
    if not providers:
        logger.warning("No geolocation providers configured - location analysis will be limited")
    
    return GeolocationService(providers)


# Export main classes
__all__ = [
    "GeoServiceConfig",
    "UserLocationHistory",
    "GeoLocationProvider",
    "MaxMindProvider",
    "IPInfoProvider", 
    "IP2LocationProvider",
    "GeolocationService",
    "create_geolocation_service"
]