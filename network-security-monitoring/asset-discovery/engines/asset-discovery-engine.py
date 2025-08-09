#!/usr/bin/env python3
"""
iSECTECH Asset Discovery and Network Mapping Engine

This module provides comprehensive asset discovery and network topology mapping
capabilities for the network security monitoring platform. It combines active
and passive discovery techniques to maintain an accurate inventory of network
assets and their relationships.

Author: iSECTECH Security Team
Version: 1.0.0
"""

import asyncio
import ipaddress
import json
import logging
import sqlite3
import threading
import time
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
import xml.etree.ElementTree as ET

import networkx as nx
import redis
import requests
import subprocess
import yaml

# Third-party libraries for network discovery
try:
    import nmap
    import scapy.all as scapy
    from pysnmp.hlapi import *
    import netifaces
    import psutil
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    ENHANCED_FEATURES = True
except ImportError as e:
    logging.warning(f"Enhanced features disabled due to missing dependencies: {e}")
    ENHANCED_FEATURES = False

# Asset data structures
@dataclass
class NetworkAsset:
    """Network asset information"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    operating_system: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[int, str] = None
    last_seen: datetime = None
    first_seen: datetime = None
    discovery_method: str = None
    confidence: float = 0.0
    location: Optional[str] = None
    network_segment: Optional[str] = None
    asset_criticality: str = "unknown"
    vulnerability_score: float = 0.0
    tags: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.tags is None:
            self.tags = []
        if self.last_seen is None:
            self.last_seen = datetime.utcnow()
        if self.first_seen is None:
            self.first_seen = datetime.utcnow()

@dataclass
class NetworkConnection:
    """Network connection between assets"""
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    connection_count: int = 1
    first_seen: datetime = None
    last_seen: datetime = None
    connection_type: str = "unknown"  # client-server, peer-peer, etc.
    
    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.utcnow()
        if self.first_seen is None:
            self.first_seen = datetime.utcnow()

@dataclass
class NetworkSegment:
    """Network segment information"""
    network: str  # CIDR notation
    name: str
    description: str
    vlan_id: Optional[int] = None
    gateway: Optional[str] = None
    dns_servers: List[str] = None
    asset_count: int = 0
    criticality: str = "medium"
    monitoring_enabled: bool = True
    
    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = []

class PassiveAssetDiscovery:
    """Passive asset discovery using network traffic analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.assets: Dict[str, NetworkAsset] = {}
        self.connections: List[NetworkConnection] = []
        
        # Initialize Redis connection
        if config.get('redis', {}).get('enabled', False):
            self._initialize_redis()
    
    def _initialize_redis(self):
        """Initialize Redis connection for flow data"""
        try:
            redis_config = self.config['redis']
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                password=redis_config.get('password'),
                decode_responses=True
            )
            self.redis_client.ping()
            self.logger.info("Connected to Redis for passive discovery")
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    def process_network_flows(self, flows: List[Dict[str, Any]]) -> List[NetworkAsset]:
        """Process network flows to discover assets"""
        discovered_assets = []
        
        for flow in flows:
            try:
                # Extract source and destination assets
                src_asset = self._extract_asset_from_flow(flow, 'source')
                dst_asset = self._extract_asset_from_flow(flow, 'destination')
                
                if src_asset:
                    discovered_assets.append(src_asset)
                if dst_asset:
                    discovered_assets.append(dst_asset)
                
                # Track connection
                self._track_connection(flow)
                
            except Exception as e:
                self.logger.error(f"Error processing flow: {e}")
        
        return discovered_assets
    
    def _extract_asset_from_flow(self, flow: Dict[str, Any], direction: str) -> Optional[NetworkAsset]:
        """Extract asset information from network flow"""
        try:
            ip_key = f"{direction}_ip"
            port_key = f"{direction}_port"
            
            if ip_key not in flow:
                return None
            
            ip_address = flow[ip_key]
            
            # Skip broadcast and multicast addresses
            if self._is_special_address(ip_address):
                return None
            
            # Check if asset already exists
            if ip_address in self.assets:
                asset = self.assets[ip_address]
                asset.last_seen = datetime.utcnow()
                
                # Update port information
                if port_key in flow and direction == 'destination':
                    port = int(flow[port_key])
                    if port not in asset.open_ports:
                        asset.open_ports.append(port)
                        
                    # Identify service
                    service = self._identify_service(port, flow.get('protocol', 'tcp'))
                    if service:
                        asset.services[port] = service
                
                return asset
            
            # Create new asset
            asset = NetworkAsset(
                ip_address=ip_address,
                discovery_method="passive_flow",
                confidence=0.7
            )
            
            # Extract additional information
            if 'user_agent' in flow:
                asset.tags.append(f"user_agent:{flow['user_agent']}")
            
            if 'ja3' in flow:
                asset.tags.append(f"ja3:{flow['ja3']}")
            
            # Determine device type from flow patterns
            asset.device_type = self._infer_device_type(flow)
            
            # Set network segment
            asset.network_segment = self._determine_network_segment(ip_address)
            
            self.assets[ip_address] = asset
            return asset
            
        except Exception as e:
            self.logger.error(f"Error extracting asset from flow: {e}")
            return None
    
    def _track_connection(self, flow: Dict[str, Any]):
        """Track network connections between assets"""
        try:
            connection = NetworkConnection(
                source_ip=flow.get('source_ip'),
                destination_ip=flow.get('destination_ip'),
                protocol=flow.get('protocol', 'tcp'),
                port=int(flow.get('destination_port', 0))
            )
            
            # Check for existing connection
            existing = None
            for conn in self.connections:
                if (conn.source_ip == connection.source_ip and
                    conn.destination_ip == connection.destination_ip and
                    conn.protocol == connection.protocol and
                    conn.port == connection.port):
                    existing = conn
                    break
            
            if existing:
                existing.connection_count += 1
                existing.last_seen = datetime.utcnow()
            else:
                self.connections.append(connection)
                
        except Exception as e:
            self.logger.error(f"Error tracking connection: {e}")
    
    def _is_special_address(self, ip: str) -> bool:
        """Check if IP address is broadcast, multicast, or reserved"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_multicast or addr.is_broadcast or addr.is_reserved
        except:
            return True
    
    def _identify_service(self, port: int, protocol: str) -> Optional[str]:
        """Identify service based on port and protocol"""
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 3389: "rdp", 5432: "postgresql", 3306: "mysql",
            1433: "mssql", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch"
        }
        
        return common_services.get(port)
    
    def _infer_device_type(self, flow: Dict[str, Any]) -> str:
        """Infer device type from flow characteristics"""
        # Simple heuristics for device type inference
        user_agent = flow.get('user_agent', '').lower()
        
        if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
            return "mobile_device"
        elif 'windows' in user_agent:
            return "windows_workstation"
        elif 'mac' in user_agent:
            return "mac_workstation"
        elif 'linux' in user_agent:
            return "linux_workstation"
        
        # Check for server patterns
        if flow.get('destination_port') in [80, 443, 22, 21, 25]:
            return "server"
        
        return "unknown"
    
    def _determine_network_segment(self, ip_address: str) -> str:
        """Determine network segment for IP address"""
        try:
            addr = ipaddress.ip_address(ip_address)
            
            # Common network segments
            if addr in ipaddress.ip_network('10.0.0.0/8'):
                return "internal"
            elif addr in ipaddress.ip_network('172.16.0.0/12'):
                return "internal"
            elif addr in ipaddress.ip_network('192.168.0.0/16'):
                return "internal"
            else:
                return "external"
                
        except:
            return "unknown"

class ActiveAssetDiscovery:
    """Active asset discovery using network scanning"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.nm = None
        
        if ENHANCED_FEATURES:
            try:
                self.nm = nmap.PortScanner()
                self.logger.info("Nmap scanner initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Nmap: {e}")
    
    def discover_network_range(self, network_range: str) -> List[NetworkAsset]:
        """Discover assets in a network range using active scanning"""
        if not self.nm:
            self.logger.error("Nmap not available for active discovery")
            return []
        
        assets = []
        
        try:
            self.logger.info(f"Starting active discovery for {network_range}")
            
            # Perform host discovery scan
            scan_result = self.nm.scan(
                hosts=network_range,
                arguments=self.config.get('nmap_args', '-sn -PE -PP -PS21,22,23,25,53,80,443 -PA80,443')
            )
            
            for host in scan_result['scan']:
                if scan_result['scan'][host]['status']['state'] == 'up':
                    asset = self._create_asset_from_scan(host, scan_result['scan'][host])
                    if asset:
                        assets.append(asset)
            
            # Perform detailed scanning on discovered hosts
            if assets and self.config.get('detailed_scan', True):
                assets = self._perform_detailed_scan(assets)
            
            self.logger.info(f"Discovered {len(assets)} assets in {network_range}")
            
        except Exception as e:
            self.logger.error(f"Error during active discovery: {e}")
        
        return assets
    
    def _create_asset_from_scan(self, host: str, scan_data: Dict[str, Any]) -> NetworkAsset:
        """Create asset from Nmap scan data"""
        try:
            asset = NetworkAsset(
                ip_address=host,
                discovery_method="active_scan",
                confidence=0.9
            )
            
            # Extract hostname
            if 'hostnames' in scan_data and scan_data['hostnames']:
                asset.hostname = scan_data['hostnames'][0]['name']
            
            # Extract MAC address and vendor
            if 'addresses' in scan_data:
                if 'mac' in scan_data['addresses']:
                    asset.mac_address = scan_data['addresses']['mac']
                    
            if 'vendor' in scan_data and scan_data['vendor']:
                asset.vendor = list(scan_data['vendor'].values())[0]
            
            # Extract OS information
            if 'osmatch' in scan_data and scan_data['osmatch']:
                asset.operating_system = scan_data['osmatch'][0]['name']
            
            # Set network segment
            asset.network_segment = self._determine_network_segment(host)
            
            return asset
            
        except Exception as e:
            self.logger.error(f"Error creating asset from scan data: {e}")
            return None
    
    def _perform_detailed_scan(self, assets: List[NetworkAsset]) -> List[NetworkAsset]:
        """Perform detailed port scanning on discovered assets"""
        detailed_assets = []
        
        for asset in assets:
            try:
                self.logger.debug(f"Performing detailed scan on {asset.ip_address}")
                
                # Perform service scan
                scan_result = self.nm.scan(
                    hosts=asset.ip_address,
                    arguments=self.config.get('detailed_nmap_args', '-sS -sV -O --version-intensity 3 -T4')
                )
                
                if asset.ip_address in scan_result['scan']:
                    scan_data = scan_result['scan'][asset.ip_address]
                    
                    # Update asset with detailed information
                    self._update_asset_with_scan_details(asset, scan_data)
                
                detailed_assets.append(asset)
                
                # Rate limiting
                time.sleep(self.config.get('scan_delay', 1))
                
            except Exception as e:
                self.logger.error(f"Error in detailed scan for {asset.ip_address}: {e}")
                detailed_assets.append(asset)  # Keep original asset
        
        return detailed_assets
    
    def _update_asset_with_scan_details(self, asset: NetworkAsset, scan_data: Dict[str, Any]):
        """Update asset with detailed scan information"""
        try:
            # Extract open ports and services
            if 'tcp' in scan_data:
                for port, port_data in scan_data['tcp'].items():
                    if port_data['state'] == 'open':
                        asset.open_ports.append(port)
                        
                        # Extract service information
                        service_name = port_data.get('name', 'unknown')
                        service_version = port_data.get('version', '')
                        service_product = port_data.get('product', '')
                        
                        service_info = service_name
                        if service_product:
                            service_info += f" ({service_product}"
                            if service_version:
                                service_info += f" {service_version}"
                            service_info += ")"
                        
                        asset.services[port] = service_info
            
            # Update OS information
            if 'osmatch' in scan_data and scan_data['osmatch']:
                os_match = scan_data['osmatch'][0]
                asset.operating_system = os_match['name']
                asset.confidence = max(asset.confidence, float(os_match['accuracy']) / 100)
            
            # Determine device type based on services
            asset.device_type = self._infer_device_type_from_services(asset.services)
            
        except Exception as e:
            self.logger.error(f"Error updating asset with scan details: {e}")
    
    def _infer_device_type_from_services(self, services: Dict[int, str]) -> str:
        """Infer device type from running services"""
        service_names = [service.lower() for service in services.values()]
        
        # Server indicators
        server_services = ['http', 'https', 'ssh', 'ftp', 'smtp', 'dns', 'mysql', 'postgresql']
        if any(service in ' '.join(service_names) for service in server_services):
            return "server"
        
        # Network device indicators
        network_services = ['snmp', 'telnet', 'ssh']
        if any(service in ' '.join(service_names) for service in network_services):
            if 22 in services and 161 in services:  # SSH + SNMP
                return "network_device"
        
        # Workstation indicators
        workstation_services = ['netbios', 'smb', 'rdp']
        if any(service in ' '.join(service_names) for service in workstation_services):
            return "workstation"
        
        return "unknown"
    
    def _determine_network_segment(self, ip_address: str) -> str:
        """Determine network segment for IP address"""
        try:
            addr = ipaddress.ip_address(ip_address)
            
            if addr in ipaddress.ip_network('10.0.0.0/8'):
                return "internal"
            elif addr in ipaddress.ip_network('172.16.0.0/12'):
                return "internal"
            elif addr in ipaddress.ip_network('192.168.0.0/16'):
                return "internal"
            else:
                return "external"
                
        except:
            return "unknown"
    
    def ping_sweep(self, network_range: str) -> List[str]:
        """Perform ping sweep to identify live hosts"""
        live_hosts = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            # Use threading for faster scanning
            with ThreadPoolExecutor(max_workers=self.config.get('ping_threads', 50)) as executor:
                futures = {
                    executor.submit(self._ping_host, str(ip)): str(ip) 
                    for ip in network.hosts()
                }
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            live_hosts.append(ip)
                    except Exception as e:
                        self.logger.debug(f"Ping failed for {ip}: {e}")
            
            self.logger.info(f"Ping sweep found {len(live_hosts)} live hosts in {network_range}")
            
        except Exception as e:
            self.logger.error(f"Error during ping sweep: {e}")
        
        return live_hosts
    
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            if ENHANCED_FEATURES:
                # Use scapy for more reliable ping
                response = scapy.sr1(
                    scapy.IP(dst=ip)/scapy.ICMP(),
                    timeout=2,
                    verbose=0
                )
                return response is not None
            else:
                # Fallback to system ping
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', ip],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
        except:
            return False

class NetworkTopologyMapper:
    """Network topology mapping and visualization"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.graph = nx.Graph()
        self.assets: Dict[str, NetworkAsset] = {}
        self.connections: List[NetworkConnection] = []
        self.segments: Dict[str, NetworkSegment] = {}
    
    def build_topology(self, assets: List[NetworkAsset], connections: List[NetworkConnection]):
        """Build network topology from discovered assets and connections"""
        self.assets = {asset.ip_address: asset for asset in assets}
        self.connections = connections
        
        # Clear existing graph
        self.graph.clear()
        
        # Add nodes (assets)
        for asset in assets:
            self.graph.add_node(
                asset.ip_address,
                hostname=asset.hostname,
                device_type=asset.device_type,
                operating_system=asset.operating_system,
                network_segment=asset.network_segment,
                criticality=asset.asset_criticality
            )
        
        # Add edges (connections)
        for connection in connections:
            if (connection.source_ip in self.assets and 
                connection.destination_ip in self.assets):
                
                self.graph.add_edge(
                    connection.source_ip,
                    connection.destination_ip,
                    protocol=connection.protocol,
                    port=connection.port,
                    connection_count=connection.connection_count,
                    connection_type=connection.connection_type
                )
        
        self.logger.info(f"Built topology with {len(self.graph.nodes)} nodes and {len(self.graph.edges)} edges")
    
    def detect_network_segments(self) -> Dict[str, NetworkSegment]:
        """Detect and define network segments"""
        segments = {}
        
        # Group assets by network range
        network_groups = defaultdict(list)
        
        for asset in self.assets.values():
            try:
                ip = ipaddress.ip_address(asset.ip_address)
                
                # Determine /24 network
                if ip.version == 4:
                    network = ipaddress.ip_network(f"{ip}/{24}", strict=False)
                    network_groups[str(network)].append(asset)
            except:
                continue
        
        # Create network segments
        for network_str, assets_in_segment in network_groups.items():
            if len(assets_in_segment) >= self.config.get('min_segment_size', 2):
                segment = NetworkSegment(
                    network=network_str,
                    name=f"Segment_{network_str.replace('.', '_').replace('/', '_')}",
                    description=f"Auto-detected network segment for {network_str}",
                    asset_count=len(assets_in_segment)
                )
                
                # Determine criticality based on asset types
                server_count = sum(1 for asset in assets_in_segment if asset.device_type == 'server')
                if server_count > len(assets_in_segment) * 0.5:
                    segment.criticality = "high"
                elif server_count > 0:
                    segment.criticality = "medium"
                else:
                    segment.criticality = "low"
                
                segments[network_str] = segment
        
        self.segments = segments
        return segments
    
    def identify_critical_paths(self) -> List[List[str]]:
        """Identify critical network paths and chokepoints"""
        critical_paths = []
        
        try:
            # Find bridges (edges whose removal would disconnect the graph)
            bridges = list(nx.bridges(self.graph))
            
            # Find articulation points (nodes whose removal would disconnect the graph)
            articulation_points = list(nx.articulation_points(self.graph))
            
            self.logger.info(f"Identified {len(bridges)} network bridges and {len(articulation_points)} articulation points")
            
            # Analyze paths between different network segments
            segments = set()
            for asset in self.assets.values():
                if asset.network_segment:
                    segments.add(asset.network_segment)
            
            # Find shortest paths between segments
            for segment1 in segments:
                for segment2 in segments:
                    if segment1 != segment2:
                        segment1_nodes = [ip for ip, asset in self.assets.items() 
                                        if asset.network_segment == segment1]
                        segment2_nodes = [ip for ip, asset in self.assets.items() 
                                        if asset.network_segment == segment2]
                        
                        for node1 in segment1_nodes[:3]:  # Limit to avoid too many paths
                            for node2 in segment2_nodes[:3]:
                                try:
                                    if nx.has_path(self.graph, node1, node2):
                                        path = nx.shortest_path(self.graph, node1, node2)
                                        if len(path) > 2:  # Non-direct connections
                                            critical_paths.append(path)
                                except nx.NetworkXNoPath:
                                    continue
                                    
        except Exception as e:
            self.logger.error(f"Error identifying critical paths: {e}")
        
        return critical_paths
    
    def generate_network_map(self, output_path: str = None):
        """Generate visual network map"""
        if not ENHANCED_FEATURES:
            self.logger.warning("Visualization features not available")
            return
        
        try:
            # Create figure
            plt.figure(figsize=(16, 12))
            plt.title("Network Topology Map", fontsize=16, fontweight='bold')
            
            # Use spring layout for better visualization
            pos = nx.spring_layout(self.graph, k=3, iterations=50)
            
            # Define colors for different device types
            device_colors = {
                'server': 'red',
                'workstation': 'lightblue',
                'network_device': 'orange',
                'mobile_device': 'lightgreen',
                'unknown': 'gray'
            }
            
            # Draw nodes
            for device_type, color in device_colors.items():
                nodes = [node for node in self.graph.nodes() 
                        if self.assets.get(node, {}).device_type == device_type]
                if nodes:
                    nx.draw_networkx_nodes(
                        self.graph, pos, nodelist=nodes,
                        node_color=color, node_size=300, alpha=0.8,
                        label=device_type.replace('_', ' ').title()
                    )
            
            # Draw edges
            nx.draw_networkx_edges(self.graph, pos, alpha=0.5, edge_color='gray', width=0.5)
            
            # Add labels for critical nodes
            critical_nodes = {node: node for node in self.graph.nodes() 
                            if self.graph.degree(node) > 5 or 
                               self.assets.get(node, {}).device_type == 'server'}
            
            nx.draw_networkx_labels(self.graph, pos, labels=critical_nodes, font_size=8)
            
            # Add legend
            plt.legend(loc='upper left', bbox_to_anchor=(0, 1))
            
            # Remove axes
            plt.axis('off')
            
            # Save if path provided
            if output_path:
                plt.savefig(output_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"Network map saved to {output_path}")
            
            plt.tight_layout()
            
            # Don't show in production
            if self.config.get('show_plots', False):
                plt.show()
            else:
                plt.close()
                
        except Exception as e:
            self.logger.error(f"Error generating network map: {e}")
    
    def export_topology_data(self, output_format: str = 'json') -> str:
        """Export topology data in specified format"""
        try:
            topology_data = {
                'assets': [asdict(asset) for asset in self.assets.values()],
                'connections': [asdict(conn) for conn in self.connections],
                'segments': [asdict(segment) for segment in self.segments.values()],
                'graph_stats': {
                    'node_count': len(self.graph.nodes),
                    'edge_count': len(self.graph.edges),
                    'density': nx.density(self.graph),
                    'connected_components': nx.number_connected_components(self.graph)
                }
            }
            
            if output_format.lower() == 'json':
                return json.dumps(topology_data, default=str, indent=2)
            elif output_format.lower() == 'yaml':
                return yaml.dump(topology_data, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported format: {output_format}")
                
        except Exception as e:
            self.logger.error(f"Error exporting topology data: {e}")
            return ""

class AssetInventoryManager:
    """Asset inventory management and correlation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.db_path = config.get('database_path', '/var/lib/nsm/asset_inventory.db')
        self.assets: Dict[str, NetworkAsset] = {}
        
        # Initialize database
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize SQLite database for asset inventory"""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                # Create tables
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS assets (
                        ip_address TEXT PRIMARY KEY,
                        mac_address TEXT,
                        hostname TEXT,
                        vendor TEXT,
                        device_type TEXT,
                        operating_system TEXT,
                        open_ports TEXT,
                        services TEXT,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        discovery_method TEXT,
                        confidence REAL,
                        location TEXT,
                        network_segment TEXT,
                        asset_criticality TEXT,
                        vulnerability_score REAL,
                        tags TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_ip TEXT,
                        destination_ip TEXT,
                        protocol TEXT,
                        port INTEGER,
                        connection_count INTEGER,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        connection_type TEXT,
                        UNIQUE(source_ip, destination_ip, protocol, port)
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS network_segments (
                        network TEXT PRIMARY KEY,
                        name TEXT,
                        description TEXT,
                        vlan_id INTEGER,
                        gateway TEXT,
                        dns_servers TEXT,
                        asset_count INTEGER,
                        criticality TEXT,
                        monitoring_enabled BOOLEAN
                    )
                ''')
                
                # Create indexes
                conn.execute('CREATE INDEX IF NOT EXISTS idx_assets_device_type ON assets(device_type)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_connections_source ON connections(source_ip)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_connections_dest ON connections(destination_ip)')
                
                conn.commit()
                
            self.logger.info("Asset inventory database initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def update_asset(self, asset: NetworkAsset) -> bool:
        """Update or insert asset in inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if asset exists
                cursor = conn.execute(
                    'SELECT ip_address FROM assets WHERE ip_address = ?',
                    (asset.ip_address,)
                )
                exists = cursor.fetchone() is not None
                
                if exists:
                    # Update existing asset
                    conn.execute('''
                        UPDATE assets SET
                            mac_address = ?, hostname = ?, vendor = ?, device_type = ?,
                            operating_system = ?, open_ports = ?, services = ?,
                            last_seen = ?, discovery_method = ?, confidence = ?,
                            location = ?, network_segment = ?, asset_criticality = ?,
                            vulnerability_score = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE ip_address = ?
                    ''', (
                        asset.mac_address, asset.hostname, asset.vendor, asset.device_type,
                        asset.operating_system, json.dumps(asset.open_ports), json.dumps(asset.services),
                        asset.last_seen, asset.discovery_method, asset.confidence,
                        asset.location, asset.network_segment, asset.asset_criticality,
                        asset.vulnerability_score, json.dumps(asset.tags), asset.ip_address
                    ))
                else:
                    # Insert new asset
                    conn.execute('''
                        INSERT INTO assets (
                            ip_address, mac_address, hostname, vendor, device_type,
                            operating_system, open_ports, services, first_seen, last_seen,
                            discovery_method, confidence, location, network_segment,
                            asset_criticality, vulnerability_score, tags
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        asset.ip_address, asset.mac_address, asset.hostname, asset.vendor,
                        asset.device_type, asset.operating_system, json.dumps(asset.open_ports),
                        json.dumps(asset.services), asset.first_seen, asset.last_seen,
                        asset.discovery_method, asset.confidence, asset.location,
                        asset.network_segment, asset.asset_criticality, asset.vulnerability_score,
                        json.dumps(asset.tags)
                    ))
                
                conn.commit()
                self.assets[asset.ip_address] = asset
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update asset {asset.ip_address}: {e}")
            return False
    
    def get_asset(self, ip_address: str) -> Optional[NetworkAsset]:
        """Get asset from inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    'SELECT * FROM assets WHERE ip_address = ?',
                    (ip_address,)
                )
                row = cursor.fetchone()
                
                if row:
                    return self._row_to_asset(row)
                
        except Exception as e:
            self.logger.error(f"Failed to get asset {ip_address}: {e}")
        
        return None
    
    def get_all_assets(self, filters: Dict[str, Any] = None) -> List[NetworkAsset]:
        """Get all assets with optional filters"""
        try:
            query = 'SELECT * FROM assets'
            params = []
            
            if filters:
                conditions = []
                if 'device_type' in filters:
                    conditions.append('device_type = ?')
                    params.append(filters['device_type'])
                if 'network_segment' in filters:
                    conditions.append('network_segment = ?')
                    params.append(filters['network_segment'])
                if 'since' in filters:
                    conditions.append('last_seen >= ?')
                    params.append(filters['since'])
                
                if conditions:
                    query += ' WHERE ' + ' AND '.join(conditions)
            
            query += ' ORDER BY last_seen DESC'
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                return [self._row_to_asset(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Failed to get assets: {e}")
            return []
    
    def _row_to_asset(self, row: sqlite3.Row) -> NetworkAsset:
        """Convert database row to NetworkAsset"""
        return NetworkAsset(
            ip_address=row['ip_address'],
            mac_address=row['mac_address'],
            hostname=row['hostname'],
            vendor=row['vendor'],
            device_type=row['device_type'],
            operating_system=row['operating_system'],
            open_ports=json.loads(row['open_ports']) if row['open_ports'] else [],
            services=json.loads(row['services']) if row['services'] else {},
            first_seen=datetime.fromisoformat(row['first_seen']) if row['first_seen'] else None,
            last_seen=datetime.fromisoformat(row['last_seen']) if row['last_seen'] else None,
            discovery_method=row['discovery_method'],
            confidence=row['confidence'] or 0.0,
            location=row['location'],
            network_segment=row['network_segment'],
            asset_criticality=row['asset_criticality'] or 'unknown',
            vulnerability_score=row['vulnerability_score'] or 0.0,
            tags=json.loads(row['tags']) if row['tags'] else []
        )
    
    def correlate_with_vulnerability_data(self, vuln_data: Dict[str, Any]):
        """Correlate asset inventory with vulnerability data"""
        try:
            updated_count = 0
            
            for ip_address, vulnerabilities in vuln_data.items():
                asset = self.get_asset(ip_address)
                if asset:
                    # Calculate vulnerability score
                    total_score = 0
                    vuln_count = len(vulnerabilities)
                    
                    for vuln in vulnerabilities:
                        cvss_score = vuln.get('cvss_score', 0)
                        total_score += cvss_score
                    
                    if vuln_count > 0:
                        asset.vulnerability_score = total_score / vuln_count
                        
                        # Update criticality based on vulnerability score
                        if asset.vulnerability_score >= 7.0:
                            asset.asset_criticality = "critical"
                        elif asset.vulnerability_score >= 4.0:
                            asset.asset_criticality = "high"
                        else:
                            asset.asset_criticality = "medium"
                        
                        # Add vulnerability tags
                        for vuln in vulnerabilities:
                            cve_id = vuln.get('cve_id')
                            if cve_id:
                                asset.tags.append(f"vuln:{cve_id}")
                        
                        if self.update_asset(asset):
                            updated_count += 1
            
            self.logger.info(f"Updated {updated_count} assets with vulnerability data")
            
        except Exception as e:
            self.logger.error(f"Error correlating vulnerability data: {e}")
    
    def cleanup_stale_assets(self, max_age_days: int = 30):
        """Remove assets not seen for specified number of days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'DELETE FROM assets WHERE last_seen < ?',
                    (cutoff_date,)
                )
                deleted_count = cursor.rowcount
                conn.commit()
            
            self.logger.info(f"Cleaned up {deleted_count} stale assets older than {max_age_days} days")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up stale assets: {e}")

class AssetDiscoveryEngine:
    """Main asset discovery and network mapping engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/asset-discovery.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.passive_discovery = PassiveAssetDiscovery(self.config.get('passive_discovery', {}))
        self.active_discovery = ActiveAssetDiscovery(self.config.get('active_discovery', {}))
        self.topology_mapper = NetworkTopologyMapper(self.config.get('topology_mapping', {}))
        self.inventory_manager = AssetInventoryManager(self.config.get('inventory_management', {}))
        
        # Discovery state
        self.discovery_running = False
        self.discovery_thread = None
        
        # Performance metrics
        self.metrics = {
            'assets_discovered': 0,
            'connections_tracked': 0,
            'discovery_cycles': 0,
            'last_discovery_time': None
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, self.config.get('log_level', 'INFO')))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def start_discovery(self):
        """Start continuous asset discovery"""
        if self.discovery_running:
            self.logger.warning("Discovery already running")
            return
        
        self.discovery_running = True
        self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self.discovery_thread.start()
        
        self.logger.info("Asset discovery started")
    
    def stop_discovery(self):
        """Stop asset discovery"""
        self.discovery_running = False
        if self.discovery_thread:
            self.discovery_thread.join(timeout=30)
        
        self.logger.info("Asset discovery stopped")
    
    def _discovery_loop(self):
        """Main discovery loop"""
        while self.discovery_running:
            try:
                self.logger.info("Starting discovery cycle")
                
                # Perform passive discovery
                if self.config.get('passive_discovery', {}).get('enabled', True):
                    self._run_passive_discovery()
                
                # Perform active discovery
                if self.config.get('active_discovery', {}).get('enabled', True):
                    self._run_active_discovery()
                
                # Update topology
                self._update_topology()
                
                # Cleanup old data
                self._cleanup_old_data()
                
                self.metrics['discovery_cycles'] += 1
                self.metrics['last_discovery_time'] = datetime.utcnow()
                
                self.logger.info("Discovery cycle completed")
                
                # Sleep until next cycle
                sleep_time = self.config.get('discovery_interval', 3600)  # Default 1 hour
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
    
    def _run_passive_discovery(self):
        """Run passive asset discovery"""
        try:
            # Get network flows from Redis or other sources
            flows = self._get_network_flows()
            
            if flows:
                discovered_assets = self.passive_discovery.process_network_flows(flows)
                
                # Update inventory
                for asset in discovered_assets:
                    self.inventory_manager.update_asset(asset)
                    self.metrics['assets_discovered'] += 1
                
                self.logger.info(f"Passive discovery found {len(discovered_assets)} assets")
            
        except Exception as e:
            self.logger.error(f"Error in passive discovery: {e}")
    
    def _run_active_discovery(self):
        """Run active asset discovery"""
        try:
            # Get network ranges to scan
            scan_ranges = self.config.get('active_discovery', {}).get('scan_ranges', [])
            
            if not scan_ranges:
                # Auto-detect local networks
                scan_ranges = self._auto_detect_networks()
            
            all_discovered_assets = []
            
            for network_range in scan_ranges:
                self.logger.info(f"Scanning network range: {network_range}")
                
                # Perform ping sweep first for efficiency
                live_hosts = self.active_discovery.ping_sweep(network_range)
                
                if live_hosts:
                    # Convert to asset objects for detailed scanning
                    for host in live_hosts:
                        discovered_assets = self.active_discovery.discover_network_range(host)
                        all_discovered_assets.extend(discovered_assets)
                
                # Rate limiting between ranges
                time.sleep(self.config.get('active_discovery', {}).get('range_delay', 5))
            
            # Update inventory
            for asset in all_discovered_assets:
                self.inventory_manager.update_asset(asset)
                self.metrics['assets_discovered'] += 1
            
            self.logger.info(f"Active discovery found {len(all_discovered_assets)} assets")
            
        except Exception as e:
            self.logger.error(f"Error in active discovery: {e}")
    
    def _get_network_flows(self) -> List[Dict[str, Any]]:
        """Get network flows from data sources"""
        flows = []
        
        try:
            # Get flows from Redis
            if self.passive_discovery.redis_client:
                flow_keys = self.passive_discovery.redis_client.keys("flow:*")
                for key in flow_keys[:1000]:  # Limit batch size
                    flow_data = self.passive_discovery.redis_client.get(key)
                    if flow_data:
                        flows.append(json.loads(flow_data))
            
            # Get flows from files or other sources
            flow_sources = self.config.get('passive_discovery', {}).get('flow_sources', [])
            for source in flow_sources:
                if source.get('type') == 'file':
                    file_flows = self._read_flows_from_file(source['path'])
                    flows.extend(file_flows)
            
        except Exception as e:
            self.logger.error(f"Error getting network flows: {e}")
        
        return flows
    
    def _read_flows_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Read network flows from file"""
        flows = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            flow = json.loads(line.strip())
                            flows.append(flow)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            self.logger.error(f"Error reading flows from {file_path}: {e}")
        
        return flows
    
    def _auto_detect_networks(self) -> List[str]:
        """Auto-detect local networks to scan"""
        networks = []
        
        try:
            if ENHANCED_FEATURES:
                # Get network interfaces
                interfaces = netifaces.interfaces()
                
                for interface in interfaces:
                    addrs = netifaces.ifaddresses(interface)
                    
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            
                            if ip and netmask and not ip.startswith('127.'):
                                try:
                                    network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                                    networks.append(str(network))
                                except:
                                    continue
            
            if not networks:
                # Fallback to common private networks
                networks = ['192.168.1.0/24', '10.0.0.0/24', '172.16.0.0/24']
            
        except Exception as e:
            self.logger.error(f"Error auto-detecting networks: {e}")
            networks = ['192.168.1.0/24']  # Default fallback
        
        return networks
    
    def _update_topology(self):
        """Update network topology"""
        try:
            # Get all assets and connections
            assets = self.inventory_manager.get_all_assets()
            connections = self.passive_discovery.connections
            
            # Build topology
            self.topology_mapper.build_topology(assets, connections)
            
            # Detect network segments
            segments = self.topology_mapper.detect_network_segments()
            
            # Generate network map if enabled
            if self.config.get('topology_mapping', {}).get('generate_maps', False):
                output_path = self.config.get('topology_mapping', {}).get('map_output_path')
                self.topology_mapper.generate_network_map(output_path)
            
            self.logger.info(f"Updated topology with {len(assets)} assets and {len(connections)} connections")
            
        except Exception as e:
            self.logger.error(f"Error updating topology: {e}")
    
    def _cleanup_old_data(self):
        """Cleanup old discovery data"""
        try:
            # Cleanup stale assets
            max_age = self.config.get('cleanup', {}).get('asset_max_age_days', 30)
            self.inventory_manager.cleanup_stale_assets(max_age)
            
            # Cleanup old connections
            cutoff_date = datetime.utcnow() - timedelta(days=max_age)
            self.passive_discovery.connections = [
                conn for conn in self.passive_discovery.connections
                if conn.last_seen > cutoff_date
            ]
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
    
    def get_discovery_status(self) -> Dict[str, Any]:
        """Get current discovery status"""
        return {
            'running': self.discovery_running,
            'metrics': self.metrics,
            'asset_count': len(self.inventory_manager.assets),
            'connection_count': len(self.passive_discovery.connections),
            'last_discovery': self.metrics.get('last_discovery_time')
        }
    
    def force_discovery_cycle(self):
        """Force immediate discovery cycle"""
        if not self.discovery_running:
            self.logger.info("Running one-time discovery cycle")
            
            try:
                self._run_passive_discovery()
                self._run_active_discovery()
                self._update_topology()
                
                self.logger.info("One-time discovery cycle completed")
                
            except Exception as e:
                self.logger.error(f"Error in forced discovery cycle: {e}")
        else:
            self.logger.warning("Discovery already running, cannot force cycle")
    
    def export_asset_inventory(self, output_format: str = 'json') -> str:
        """Export complete asset inventory"""
        try:
            assets = self.inventory_manager.get_all_assets()
            topology_data = self.topology_mapper.export_topology_data(output_format)
            
            export_data = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'asset_count': len(assets),
                'assets': [asdict(asset) for asset in assets],
                'topology': topology_data
            }
            
            if output_format.lower() == 'json':
                return json.dumps(export_data, default=str, indent=2)
            elif output_format.lower() == 'yaml':
                return yaml.dump(export_data, default_flow_style=False)
            
        except Exception as e:
            self.logger.error(f"Error exporting asset inventory: {e}")
            return ""

def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='iSECTECH Asset Discovery Engine')
    parser.add_argument('--config', default='/etc/nsm/asset-discovery.yaml',
                       help='Configuration file path')
    parser.add_argument('--mode', choices=['daemon', 'scan-once', 'export'],
                       default='daemon', help='Operation mode')
    parser.add_argument('--target', help='Target network range for scan-once mode')
    parser.add_argument('--output', help='Output file for export mode')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json',
                       help='Output format for export mode')
    
    args = parser.parse_args()
    
    # Initialize engine
    engine = AssetDiscoveryEngine(args.config)
    
    if args.mode == 'daemon':
        try:
            engine.start_discovery()
            
            # Keep running until interrupted
            while True:
                time.sleep(60)
                status = engine.get_discovery_status()
                engine.logger.info(f"Discovery status: {status}")
                
        except KeyboardInterrupt:
            engine.logger.info("Shutdown requested")
            engine.stop_discovery()
            
    elif args.mode == 'scan-once':
        if not args.target:
            print("Target network range required for scan-once mode")
            return
        
        # Perform single scan
        assets = engine.active_discovery.discover_network_range(args.target)
        
        for asset in assets:
            engine.inventory_manager.update_asset(asset)
        
        print(f"Discovered {len(assets)} assets in {args.target}")
        
    elif args.mode == 'export':
        # Export asset inventory
        export_data = engine.export_asset_inventory(args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(export_data)
            print(f"Asset inventory exported to {args.output}")
        else:
            print(export_data)

if __name__ == "__main__":
    main()