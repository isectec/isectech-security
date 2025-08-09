#!/usr/bin/env python3
# iSECTECH Network Flow Processor
# Production-grade network flow ingestion and preprocessing for anomaly detection

import json
import csv
import asyncio
import aiofiles
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any, AsyncIterator
from dataclasses import dataclass, asdict
from pathlib import Path
import re
import hashlib
import socket
import struct
import time
from collections import defaultdict, deque
import subprocess
import ipaddress
from urllib.parse import urlparse

# Network processing imports
import dpkt
import pcap
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
import pyshark

# Data processing imports
from kafka import KafkaConsumer, KafkaProducer
import redis
import elasticsearch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/flow-processor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class NetworkFlow:
    """Enhanced network flow representation"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration: float
    flags: Set[str] = None
    application: Optional[str] = None
    user: Optional[str] = None
    
    # Enhanced attributes
    flow_id: Optional[str] = None
    session_id: Optional[str] = None
    connection_state: Optional[str] = None
    tos: Optional[int] = None
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    payload_entropy: Optional[float] = None
    inter_arrival_time: Optional[float] = None
    
    # Geolocation and context
    source_country: Optional[str] = None
    destination_country: Optional[str] = None
    source_asn: Optional[str] = None
    destination_asn: Optional[str] = None
    is_internal_source: Optional[bool] = None
    is_internal_destination: Optional[bool] = None
    
    # Application layer information
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_method: Optional[str] = None
    http_status_code: Optional[int] = None
    dns_query: Optional[str] = None
    dns_response_code: Optional[int] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    ja3_fingerprint: Optional[str] = None
    
    # Statistical features
    packet_size_stats: Dict[str, float] = None
    inter_packet_time_stats: Dict[str, float] = None
    flow_iat_stats: Dict[str, float] = None

@dataclass
class FlowAggregation:
    """Aggregated flow statistics for time windows"""
    time_window: datetime
    window_duration: int  # seconds
    total_flows: int
    total_bytes: int
    total_packets: int
    unique_sources: int
    unique_destinations: int
    protocol_distribution: Dict[str, int]
    port_distribution: Dict[int, int]
    top_talkers: List[Tuple[str, int]]  # (IP, byte_count)
    
class NetworkFlowParser:
    """Parse network flows from various data sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.private_networks = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8')
        ]
        
        # Initialize parsers for different formats
        self.parsers = {
            'zeek': self._parse_zeek_conn_log,
            'suricata': self._parse_suricata_eve,
            'netflow': self._parse_netflow,
            'pcap': self._parse_pcap,
            'csv': self._parse_csv
        }
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP address is internal"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.private_networks)
        except:
            return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of payload data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _extract_statistical_features(self, packet_sizes: List[int], 
                                    inter_packet_times: List[float]) -> Tuple[Dict, Dict]:
        """Extract statistical features from packet data"""
        if not packet_sizes:
            return {}, {}
        
        # Packet size statistics
        size_stats = {
            'mean': np.mean(packet_sizes),
            'std': np.std(packet_sizes),
            'min': np.min(packet_sizes),
            'max': np.max(packet_sizes),
            'median': np.median(packet_sizes),
            'q25': np.percentile(packet_sizes, 25),
            'q75': np.percentile(packet_sizes, 75),
            'skewness': float(pd.Series(packet_sizes).skew()),
            'kurtosis': float(pd.Series(packet_sizes).kurtosis())
        }
        
        # Inter-packet time statistics
        if inter_packet_times:
            ipt_stats = {
                'mean': np.mean(inter_packet_times),
                'std': np.std(inter_packet_times),
                'min': np.min(inter_packet_times),
                'max': np.max(inter_packet_times),
                'median': np.median(inter_packet_times),
                'cv': np.std(inter_packet_times) / max(np.mean(inter_packet_times), 0.001)
            }
        else:
            ipt_stats = {}
        
        return size_stats, ipt_stats
    
    async def _parse_zeek_conn_log(self, file_path: str) -> AsyncIterator[NetworkFlow]:
        """Parse Zeek connection logs"""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                async for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Parse tab-separated Zeek format
                        fields = line.split('\t')
                        
                        if len(fields) < 15:  # Minimum required fields
                            continue
                        
                        # Map Zeek fields to our format
                        timestamp = datetime.fromtimestamp(float(fields[0]))
                        uid = fields[1]
                        source_ip = fields[2]
                        source_port = int(fields[3]) if fields[3] != '-' else 0
                        destination_ip = fields[4]
                        destination_port = int(fields[5]) if fields[5] != '-' else 0
                        protocol = fields[6].lower()
                        service = fields[7] if fields[7] != '-' else None
                        duration = float(fields[8]) if fields[8] != '-' else 0.0
                        orig_bytes = int(fields[9]) if fields[9] != '-' else 0
                        resp_bytes = int(fields[10]) if fields[10] != '-' else 0
                        conn_state = fields[11] if fields[11] != '-' else None
                        orig_pkts = int(fields[12]) if fields[12] != '-' else 0
                        resp_pkts = int(fields[13]) if fields[13] != '-' else 0
                        
                        # Create flow object
                        flow = NetworkFlow(
                            timestamp=timestamp,
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            source_port=source_port,
                            destination_port=destination_port,
                            protocol=protocol,
                            bytes_sent=orig_bytes,
                            bytes_received=resp_bytes,
                            packets_sent=orig_pkts,
                            packets_received=resp_pkts,
                            duration=duration,
                            flow_id=uid,
                            connection_state=conn_state,
                            application=service,
                            is_internal_source=self._is_internal_ip(source_ip),
                            is_internal_destination=self._is_internal_ip(destination_ip)
                        )
                        
                        yield flow
                        
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Error parsing Zeek line: {line[:100]}... - {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading Zeek log file {file_path}: {e}")
    
    async def _parse_suricata_eve(self, file_path: str) -> AsyncIterator[NetworkFlow]:
        """Parse Suricata EVE JSON logs"""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                async for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        # Only process flow events
                        if data.get('event_type') != 'flow':
                            continue
                        
                        flow_data = data.get('flow', {})
                        
                        # Extract basic flow information
                        timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                        source_ip = data.get('src_ip', '')
                        destination_ip = data.get('dest_ip', '')
                        source_port = data.get('src_port', 0)
                        destination_port = data.get('dest_port', 0)
                        protocol = data.get('proto', '').lower()
                        
                        # Extract flow metrics
                        bytes_toserver = flow_data.get('bytes_toserver', 0)
                        bytes_toclient = flow_data.get('bytes_toclient', 0)
                        pkts_toserver = flow_data.get('pkts_toserver', 0)
                        pkts_toclient = flow_data.get('pkts_toclient', 0)
                        
                        # Calculate duration
                        start_time = flow_data.get('start')
                        end_time = flow_data.get('end')
                        duration = 0.0
                        if start_time and end_time:
                            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                            duration = (end_dt - start_dt).total_seconds()
                        
                        # Extract application information
                        app_proto = data.get('app_proto')
                        http = data.get('http')
                        dns = data.get('dns')
                        tls = data.get('tls')
                        
                        flow = NetworkFlow(
                            timestamp=timestamp,
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            source_port=source_port,
                            destination_port=destination_port,
                            protocol=protocol,
                            bytes_sent=bytes_toserver,
                            bytes_received=bytes_toclient,
                            packets_sent=pkts_toserver,
                            packets_received=pkts_toclient,
                            duration=duration,
                            application=app_proto,
                            connection_state=flow_data.get('state'),
                            is_internal_source=self._is_internal_ip(source_ip),
                            is_internal_destination=self._is_internal_ip(destination_ip)
                        )
                        
                        # Add HTTP details if available
                        if http:
                            flow.http_host = http.get('hostname')
                            flow.http_uri = http.get('url')
                            flow.http_user_agent = http.get('http_user_agent')
                            flow.http_method = http.get('http_method')
                            flow.http_status_code = http.get('status')
                        
                        # Add DNS details if available
                        if dns:
                            flow.dns_query = dns.get('rrname')
                            flow.dns_response_code = dns.get('rcode')
                        
                        # Add TLS details if available
                        if tls:
                            flow.tls_version = tls.get('version')
                            flow.tls_cipher = tls.get('cipher')
                            flow.ja3_fingerprint = tls.get('ja3')
                        
                        yield flow
                        
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        logger.warning(f"Error parsing Suricata EVE line: {line[:100]}... - {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading Suricata EVE log file {file_path}: {e}")
    
    async def _parse_netflow(self, data: bytes) -> AsyncIterator[NetworkFlow]:
        """Parse NetFlow records"""
        # This is a simplified NetFlow parser
        # In production, you'd use a proper NetFlow library
        try:
            # NetFlow v5 record parsing (simplified)
            if len(data) < 24:
                return
            
            # Extract header
            version = struct.unpack('!H', data[0:2])[0]
            count = struct.unpack('!H', data[2:4])[0]
            
            if version != 5:
                logger.warning(f"Unsupported NetFlow version: {version}")
                return
            
            # Parse records
            offset = 24  # Header size
            record_size = 48  # NetFlow v5 record size
            
            for i in range(count):
                if offset + record_size > len(data):
                    break
                
                record = data[offset:offset + record_size]
                
                # Extract fields
                srcaddr = socket.inet_ntoa(record[0:4])
                dstaddr = socket.inet_ntoa(record[4:8])
                nexthop = socket.inet_ntoa(record[8:12])
                input_int = struct.unpack('!H', record[12:14])[0]
                output_int = struct.unpack('!H', record[14:16])[0]
                dPkts = struct.unpack('!I', record[16:20])[0]
                dOctets = struct.unpack('!I', record[20:24])[0]
                first = struct.unpack('!I', record[24:28])[0]
                last = struct.unpack('!I', record[28:32])[0]
                srcport = struct.unpack('!H', record[32:34])[0]
                dstport = struct.unpack('!H', record[34:36])[0]
                tcp_flags = struct.unpack('!B', record[37:38])[0]
                prot = struct.unpack('!B', record[38:39])[0]
                tos = struct.unpack('!B', record[39:40])[0]
                
                # Convert timestamp
                timestamp = datetime.fromtimestamp(first / 1000.0)
                duration = (last - first) / 1000.0
                
                # Map protocol number to name
                protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
                protocol = protocol_map.get(prot, str(prot))
                
                flow = NetworkFlow(
                    timestamp=timestamp,
                    source_ip=srcaddr,
                    destination_ip=dstaddr,
                    source_port=srcport,
                    destination_port=dstport,
                    protocol=protocol,
                    bytes_sent=dOctets,
                    bytes_received=0,  # NetFlow doesn't distinguish direction
                    packets_sent=dPkts,
                    packets_received=0,
                    duration=duration,
                    tos=tos,
                    is_internal_source=self._is_internal_ip(srcaddr),
                    is_internal_destination=self._is_internal_ip(dstaddr)
                )
                
                yield flow
                offset += record_size
                
        except Exception as e:
            logger.error(f"Error parsing NetFlow data: {e}")
    
    async def _parse_pcap(self, file_path: str) -> AsyncIterator[NetworkFlow]:
        """Parse PCAP files using tshark"""
        try:
            # Use tshark to extract flow data
            cmd = [
                'tshark', '-r', file_path, '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src', '-e', 'ip.dst',
                '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'udp.srcport', '-e', 'udp.dstport',
                '-e', 'ip.proto',
                '-e', 'frame.len',
                '-e', 'tcp.flags',
                '-e', 'http.host', '-e', 'http.request.uri',
                '-e', 'dns.qry.name',
                '-E', 'header=n', '-E', 'separator=|'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            flow_cache = defaultdict(lambda: {
                'packets': [], 'bytes': 0, 'start_time': None, 'end_time': None
            })
            
            async for line in process.stdout:
                line = line.decode('utf-8').strip()
                if not line:
                    continue
                
                try:
                    fields = line.split('|')
                    
                    if len(fields) < 8:
                        continue
                    
                    timestamp = float(fields[0]) if fields[0] else 0
                    src_ip = fields[1] if fields[1] else ''
                    dst_ip = fields[2] if fields[2] else ''
                    
                    # Handle TCP/UDP ports
                    src_port = 0
                    dst_port = 0
                    if fields[3]:  # TCP srcport
                        src_port = int(fields[3])
                        dst_port = int(fields[4]) if fields[4] else 0
                        protocol = 'tcp'
                    elif fields[5]:  # UDP srcport
                        src_port = int(fields[5])
                        dst_port = int(fields[6]) if fields[6] else 0
                        protocol = 'udp'
                    else:
                        # Other protocol
                        protocol_num = int(fields[7]) if fields[7] else 0
                        protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
                        protocol = protocol_map.get(protocol_num, str(protocol_num))
                    
                    frame_len = int(fields[8]) if fields[8] else 0
                    
                    # Create flow key
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                    
                    # Update flow cache
                    flow_data = flow_cache[flow_key]
                    flow_data['packets'].append({
                        'timestamp': timestamp,
                        'size': frame_len
                    })
                    flow_data['bytes'] += frame_len
                    
                    if not flow_data['start_time'] or timestamp < flow_data['start_time']:
                        flow_data['start_time'] = timestamp
                    if not flow_data['end_time'] or timestamp > flow_data['end_time']:
                        flow_data['end_time'] = timestamp
                    
                    # Extract application data
                    http_host = fields[10] if len(fields) > 10 and fields[10] else None
                    http_uri = fields[11] if len(fields) > 11 and fields[11] else None
                    dns_query = fields[12] if len(fields) > 12 and fields[12] else None
                    
                    flow_data['http_host'] = http_host
                    flow_data['http_uri'] = http_uri
                    flow_data['dns_query'] = dns_query
                    
                except (ValueError, IndexError) as e:
                    continue
            
            await process.wait()
            
            # Convert cached flows to NetworkFlow objects
            for flow_key, flow_data in flow_cache.items():
                if not flow_data['packets']:
                    continue
                
                # Parse flow key
                src_dst, protocol = flow_key.rsplit('-', 1)
                src_part, dst_part = src_dst.split('-', 1)
                src_ip, src_port = src_part.rsplit(':', 1)
                dst_ip, dst_port = dst_part.rsplit(':', 1)
                
                # Calculate statistics
                packets = flow_data['packets']
                packet_sizes = [p['size'] for p in packets]
                times = [p['timestamp'] for p in packets]
                
                duration = flow_data['end_time'] - flow_data['start_time']
                
                # Calculate inter-arrival times
                inter_arrival_times = []
                for i in range(1, len(times)):
                    inter_arrival_times.append(times[i] - times[i-1])
                
                # Extract statistical features
                size_stats, ipt_stats = self._extract_statistical_features(
                    packet_sizes, inter_arrival_times
                )
                
                flow = NetworkFlow(
                    timestamp=datetime.fromtimestamp(flow_data['start_time']),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=int(src_port),
                    destination_port=int(dst_port),
                    protocol=protocol,
                    bytes_sent=flow_data['bytes'],
                    bytes_received=0,  # PCAP doesn't distinguish direction easily
                    packets_sent=len(packets),
                    packets_received=0,
                    duration=duration,
                    http_host=flow_data.get('http_host'),
                    http_uri=flow_data.get('http_uri'),
                    dns_query=flow_data.get('dns_query'),
                    packet_size_stats=size_stats,
                    inter_packet_time_stats=ipt_stats,
                    is_internal_source=self._is_internal_ip(src_ip),
                    is_internal_destination=self._is_internal_ip(dst_ip)
                )
                
                yield flow
                
        except Exception as e:
            logger.error(f"Error parsing PCAP file {file_path}: {e}")
    
    async def _parse_csv(self, file_path: str) -> AsyncIterator[NetworkFlow]:
        """Parse CSV format flow files"""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                content = await f.read()
                
            # Use pandas for efficient CSV parsing
            df = pd.read_csv(file_path)
            
            # Map common CSV column names
            column_mapping = {
                'timestamp': ['timestamp', 'time', 'ts'],
                'source_ip': ['src_ip', 'source_ip', 'srcaddr', 'src'],
                'destination_ip': ['dst_ip', 'dest_ip', 'dstaddr', 'dst'],
                'source_port': ['src_port', 'source_port', 'srcport'],
                'destination_port': ['dst_port', 'dest_port', 'dstport'],
                'protocol': ['protocol', 'proto', 'prot'],
                'bytes': ['bytes', 'octets', 'size'],
                'packets': ['packets', 'pkts'],
                'duration': ['duration', 'dur']
            }
            
            # Find actual column names
            actual_columns = {}
            for field, possible_names in column_mapping.items():
                for name in possible_names:
                    if name in df.columns:
                        actual_columns[field] = name
                        break
            
            # Process each row
            for _, row in df.iterrows():
                try:
                    # Extract timestamp
                    timestamp_col = actual_columns.get('timestamp')
                    if timestamp_col:
                        timestamp = pd.to_datetime(row[timestamp_col])
                        if timestamp.tz is None:
                            timestamp = timestamp.tz_localize('UTC')
                        timestamp = timestamp.to_pydatetime()
                    else:
                        timestamp = datetime.now()
                    
                    # Extract required fields
                    source_ip = str(row[actual_columns.get('source_ip', 'src_ip')])
                    destination_ip = str(row[actual_columns.get('destination_ip', 'dst_ip')])
                    
                    # Extract optional fields with defaults
                    source_port = int(row.get(actual_columns.get('source_port'), 0))
                    destination_port = int(row.get(actual_columns.get('destination_port'), 0))
                    protocol = str(row.get(actual_columns.get('protocol'), 'unknown')).lower()
                    bytes_val = int(row.get(actual_columns.get('bytes'), 0))
                    packets_val = int(row.get(actual_columns.get('packets'), 1))
                    duration = float(row.get(actual_columns.get('duration'), 0.0))
                    
                    flow = NetworkFlow(
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        source_port=source_port,
                        destination_port=destination_port,
                        protocol=protocol,
                        bytes_sent=bytes_val,
                        bytes_received=0,
                        packets_sent=packets_val,
                        packets_received=0,
                        duration=duration,
                        is_internal_source=self._is_internal_ip(source_ip),
                        is_internal_destination=self._is_internal_ip(destination_ip)
                    )
                    
                    yield flow
                    
                except (ValueError, KeyError) as e:
                    logger.warning(f"Error parsing CSV row: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error parsing CSV file {file_path}: {e}")
    
    async def parse_flows(self, source_type: str, source_path: str) -> AsyncIterator[NetworkFlow]:
        """Parse flows from specified source"""
        if source_type not in self.parsers:
            logger.error(f"Unsupported source type: {source_type}")
            return
        
        logger.info(f"Parsing flows from {source_type} source: {source_path}")
        
        async for flow in self.parsers[source_type](source_path):
            yield flow

class FlowAggregator:
    """Aggregate network flows for temporal analysis"""
    
    def __init__(self, window_size: int = 300):  # 5 minutes default
        self.window_size = window_size
        self.current_window = {}
        self.aggregated_flows = deque(maxlen=1000)  # Keep last 1000 windows
    
    def add_flow(self, flow: NetworkFlow) -> Optional[FlowAggregation]:
        """Add flow to aggregation and return completed window if any"""
        # Calculate window timestamp
        window_timestamp = datetime.fromtimestamp(
            (flow.timestamp.timestamp() // self.window_size) * self.window_size
        )
        
        # Initialize window if needed
        if window_timestamp not in self.current_window:
            self.current_window[window_timestamp] = {
                'flows': [],
                'total_bytes': 0,
                'total_packets': 0,
                'unique_sources': set(),
                'unique_destinations': set(),
                'protocols': defaultdict(int),
                'ports': defaultdict(int),
                'source_bytes': defaultdict(int)
            }
        
        # Add flow to current window
        window = self.current_window[window_timestamp]
        window['flows'].append(flow)
        window['total_bytes'] += flow.bytes_sent + flow.bytes_received
        window['total_packets'] += flow.packets_sent + flow.packets_received
        window['unique_sources'].add(flow.source_ip)
        window['unique_destinations'].add(flow.destination_ip)
        window['protocols'][flow.protocol] += 1
        window['ports'][flow.destination_port] += 1
        window['source_bytes'][flow.source_ip] += flow.bytes_sent + flow.bytes_received
        
        # Check if we should close old windows
        current_time = datetime.now()
        completed_aggregation = None
        
        for timestamp, data in list(self.current_window.items()):
            window_age = (current_time - timestamp).total_seconds()
            
            if window_age > self.window_size * 2:  # Close window after 2x window size
                # Create aggregation
                top_talkers = sorted(
                    data['source_bytes'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
                
                aggregation = FlowAggregation(
                    time_window=timestamp,
                    window_duration=self.window_size,
                    total_flows=len(data['flows']),
                    total_bytes=data['total_bytes'],
                    total_packets=data['total_packets'],
                    unique_sources=len(data['unique_sources']),
                    unique_destinations=len(data['unique_destinations']),
                    protocol_distribution=dict(data['protocols']),
                    port_distribution=dict(data['ports']),
                    top_talkers=top_talkers
                )
                
                self.aggregated_flows.append(aggregation)
                
                if timestamp == window_timestamp:
                    completed_aggregation = aggregation
                
                # Remove from current windows
                del self.current_window[timestamp]
        
        return completed_aggregation

class NetworkFlowProcessor:
    """Main network flow processor orchestrating ingestion and processing"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.parser = NetworkFlowParser(config)
        self.aggregator = FlowAggregator(config.get('aggregation_window', 300))
        
        # Output queues
        self.flow_queue = asyncio.Queue(maxsize=10000)
        self.aggregation_queue = asyncio.Queue(maxsize=1000)
        
        # Processing state
        self.is_running = False
        self.processed_flows = 0
        self.processing_errors = 0
        
        # Initialize outputs
        self.outputs = self._initialize_outputs()
    
    def _initialize_outputs(self) -> Dict[str, Any]:
        """Initialize output connections"""
        outputs = {}
        
        # Redis output
        if self.config.get('outputs', {}).get('redis', {}).get('enabled'):
            redis_config = self.config['outputs']['redis']
            outputs['redis'] = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                password=redis_config.get('password')
            )
        
        # Kafka output
        if self.config.get('outputs', {}).get('kafka', {}).get('enabled'):
            kafka_config = self.config['outputs']['kafka']
            outputs['kafka'] = KafkaProducer(
                bootstrap_servers=kafka_config.get('bootstrap_servers', ['localhost:9092']),
                value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8')
            )
        
        # Elasticsearch output
        if self.config.get('outputs', {}).get('elasticsearch', {}).get('enabled'):
            es_config = self.config['outputs']['elasticsearch']
            outputs['elasticsearch'] = elasticsearch.Elasticsearch(
                es_config.get('hosts', ['localhost:9200']),
                http_auth=(es_config.get('username'), es_config.get('password'))
            )
        
        return outputs
    
    async def process_source(self, source_config: Dict[str, Any]):
        """Process flows from a single source"""
        source_type = source_config.get('type')
        source_path = source_config.get('path')
        
        if not source_type or not source_path:
            logger.error(f"Invalid source configuration: {source_config}")
            return
        
        try:
            async for flow in self.parser.parse_flows(source_type, source_path):
                # Add to processing queue
                await self.flow_queue.put(flow)
                
                # Check for completed aggregations
                aggregation = self.aggregator.add_flow(flow)
                if aggregation:
                    await self.aggregation_queue.put(aggregation)
                
                self.processed_flows += 1
                
                if self.processed_flows % 10000 == 0:
                    logger.info(f"Processed {self.processed_flows} flows")
                    
        except Exception as e:
            logger.error(f"Error processing source {source_config}: {e}")
            self.processing_errors += 1
    
    async def output_flows(self):
        """Output processed flows to configured destinations"""
        while self.is_running:
            try:
                # Get flow from queue
                flow = await asyncio.wait_for(self.flow_queue.get(), timeout=1.0)
                
                # Convert to dict for serialization
                flow_dict = asdict(flow)
                
                # Convert datetime to string
                flow_dict['timestamp'] = flow.timestamp.isoformat()
                
                # Convert sets to lists
                if flow_dict['flags']:
                    flow_dict['flags'] = list(flow_dict['flags'])
                
                # Output to Redis
                if 'redis' in self.outputs:
                    try:
                        self.outputs['redis'].lpush(
                            'network_flows',
                            json.dumps(flow_dict, default=str)
                        )
                        self.outputs['redis'].ltrim('network_flows', 0, 99999)
                    except Exception as e:
                        logger.error(f"Error outputting to Redis: {e}")
                
                # Output to Kafka
                if 'kafka' in self.outputs:
                    try:
                        self.outputs['kafka'].send(
                            'network-flows',
                            value=flow_dict
                        )
                    except Exception as e:
                        logger.error(f"Error outputting to Kafka: {e}")
                
                # Output to Elasticsearch
                if 'elasticsearch' in self.outputs:
                    try:
                        index_name = f"network-flows-{flow.timestamp.strftime('%Y-%m-%d')}"
                        self.outputs['elasticsearch'].index(
                            index=index_name,
                            body=flow_dict
                        )
                    except Exception as e:
                        logger.error(f"Error outputting to Elasticsearch: {e}")
                
                # Mark task as done
                self.flow_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in flow output loop: {e}")
                await asyncio.sleep(1)
    
    async def output_aggregations(self):
        """Output flow aggregations"""
        while self.is_running:
            try:
                # Get aggregation from queue
                aggregation = await asyncio.wait_for(self.aggregation_queue.get(), timeout=1.0)
                
                # Convert to dict
                agg_dict = asdict(aggregation)
                agg_dict['time_window'] = aggregation.time_window.isoformat()
                
                # Output to Redis
                if 'redis' in self.outputs:
                    try:
                        self.outputs['redis'].lpush(
                            'flow_aggregations',
                            json.dumps(agg_dict, default=str)
                        )
                        self.outputs['redis'].ltrim('flow_aggregations', 0, 9999)
                    except Exception as e:
                        logger.error(f"Error outputting aggregation to Redis: {e}")
                
                # Mark task as done
                self.aggregation_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in aggregation output loop: {e}")
                await asyncio.sleep(1)
    
    async def start_processing(self):
        """Start the flow processor"""
        logger.info("Starting network flow processor")
        self.is_running = True
        
        # Start output tasks
        asyncio.create_task(self.output_flows())
        asyncio.create_task(self.output_aggregations())
        
        # Process configured sources
        sources = self.config.get('sources', [])
        
        if not sources:
            logger.warning("No sources configured")
            return
        
        # Process sources concurrently
        source_tasks = []
        for source in sources:
            if source.get('enabled', True):
                task = asyncio.create_task(self.process_source(source))
                source_tasks.append(task)
        
        # Wait for all source tasks to complete
        await asyncio.gather(*source_tasks, return_exceptions=True)
        
        logger.info(f"Flow processing completed. Processed: {self.processed_flows}, Errors: {self.processing_errors}")
    
    def stop_processing(self):
        """Stop the flow processor"""
        logger.info("Stopping network flow processor")
        self.is_running = False
        
        # Close output connections
        for output_name, output in self.outputs.items():
            try:
                if hasattr(output, 'close'):
                    output.close()
            except Exception as e:
                logger.error(f"Error closing {output_name}: {e}")

async def main():
    """Main function for flow processor"""
    # Example configuration
    config = {
        'sources': [
            {
                'type': 'zeek',
                'path': '/var/log/zeek/conn.log',
                'enabled': True
            },
            {
                'type': 'suricata',
                'path': '/var/log/suricata/eve.json',
                'enabled': True
            }
        ],
        'outputs': {
            'redis': {
                'enabled': True,
                'host': 'localhost',
                'port': 6379,
                'db': 0
            }
        },
        'aggregation_window': 300
    }
    
    processor = NetworkFlowProcessor(config)
    
    try:
        await processor.start_processing()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        processor.stop_processing()

if __name__ == "__main__":
    asyncio.run(main())