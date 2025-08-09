#!/usr/bin/env python3
"""
iSECTECH Integration Orchestrator
Unified orchestration of SIEM and SOAR integrations for Network Security Monitoring

This orchestrator manages the flow of security events from NSM components
to SIEM platforms and incidents to SOAR platforms, providing centralized
coordination and correlation.
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum

import redis
import yaml
from siem.siem_integration_engine import SIEMIntegrationEngine, SIEMEvent
from soar.soar_integration_engine import SOARIntegrationEngine, SOARIncident, IncidentSeverity


class EventPriority(Enum):
    """Event processing priority"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class IntegratedEvent:
    """Unified event structure for orchestration"""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    priority: EventPriority
    title: str
    description: str
    raw_data: Dict[str, Any]
    metadata: Dict[str, Any]
    enrichment: Dict[str, Any]
    
    # Processing flags
    send_to_siem: bool = True
    create_incident: bool = False
    auto_execute_playbooks: bool = False
    
    # Correlation data
    correlation_id: Optional[str] = None
    related_events: List[str] = None
    
    def __post_init__(self):
        if self.related_events is None:
            self.related_events = []
    
    def to_siem_event(self) -> SIEMEvent:
        """Convert to SIEM event format"""
        return SIEMEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            source=self.source,
            event_type=self.event_type,
            severity=self.severity,
            title=self.title,
            description=self.description,
            raw_data=self.raw_data,
            metadata=self.metadata,
            enrichment=self.enrichment
        )
    
    def to_soar_incident(self, playbooks: List[str] = None) -> SOARIncident:
        """Convert to SOAR incident format"""
        # Convert severity to IncidentSeverity enum
        severity_map = {
            'critical': IncidentSeverity.CRITICAL,
            'high': IncidentSeverity.HIGH,
            'medium': IncidentSeverity.MEDIUM,
            'low': IncidentSeverity.LOW,
            'info': IncidentSeverity.INFO
        }
        
        # Create artifacts from metadata
        artifacts = []
        if self.metadata.get('src_ip'):
            artifacts.append({
                'name': 'Source IP',
                'type': 'ip',
                'value': self.metadata['src_ip'],
                'description': 'Source IP address of the event'
            })
        
        if self.metadata.get('dst_ip'):
            artifacts.append({
                'name': 'Destination IP',
                'type': 'ip',
                'value': self.metadata['dst_ip'],
                'description': 'Destination IP address of the event'
            })
        
        if self.metadata.get('domain'):
            artifacts.append({
                'name': 'Domain',
                'type': 'domain',
                'value': self.metadata['domain'],
                'description': 'Domain name associated with the event'
            })
        
        if self.metadata.get('file_hash'):
            artifacts.append({
                'name': 'File Hash',
                'type': 'hash',
                'value': self.metadata['file_hash'],
                'description': 'File hash associated with the event'
            })
        
        return SOARIncident(
            incident_id=f"NSM-{self.event_id}",
            title=self.title,
            description=self.description,
            severity=severity_map.get(self.severity, IncidentSeverity.MEDIUM),
            source=self.source,
            timestamp=self.timestamp,
            artifacts=artifacts,
            metadata=self.metadata,
            enrichment=self.enrichment,
            playbooks=playbooks or []
        )


class IntegrationOrchestrator:
    """Main integration orchestrator"""
    
    def __init__(self, config_path: str = "/etc/nsm/integration-orchestrator.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.redis_client = self._init_redis()
        self.database = self._init_database()
        
        # Initialize integration engines
        self.siem_engine = None
        self.soar_engine = None
        self._init_integration_engines()
        
        # Event processing
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.correlation_window = self.config.get('correlation', {}).get('window_seconds', 300)
        self.correlation_cache = {}
        
        # Processing rules
        self.escalation_rules = self._load_escalation_rules()
        self.correlation_rules = self._load_correlation_rules()
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'events_sent_to_siem': 0,
            'incidents_created': 0,
            'playbooks_executed': 0,
            'correlations_found': 0,
            'last_processing_time': None
        }
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=8)
        
        # Control flags
        self.running = False
        self.shutdown_event = asyncio.Event()
    
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
        logger = logging.getLogger('IntegrationOrchestrator')
        logger.setLevel(getattr(logging, self.config.get('general', {}).get('log_level', 'INFO')))
        
        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _init_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            if not redis_config.get('enabled', False):
                return None
                
            return redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                db=redis_config.get('db', 0),
                password=redis_config.get('password'),
                decode_responses=True,
                socket_timeout=30,
                socket_connect_timeout=30,
                retry_on_timeout=True,
                max_connections=50
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis: {e}")
            return None
    
    def _init_database(self) -> Optional[sqlite3.Connection]:
        """Initialize SQLite database for orchestration tracking"""
        try:
            db_config = self.config.get('database', {})
            db_path = db_config.get('path', '/var/lib/nsm/integration_orchestrator.db')
            
            # Create directory if it doesn't exist
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(db_path, check_same_thread=False)
            
            # Create events table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS orchestrated_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    timestamp DATETIME,
                    source TEXT,
                    event_type TEXT,
                    severity TEXT,
                    priority TEXT,
                    title TEXT,
                    sent_to_siem BOOLEAN DEFAULT FALSE,
                    incident_created BOOLEAN DEFAULT FALSE,
                    correlation_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    processed_at DATETIME
                )
            ''')
            
            # Create correlations table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS event_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_id TEXT,
                    event_id TEXT,
                    correlation_type TEXT,
                    confidence_score REAL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES orchestrated_events (event_id)
                )
            ''')
            
            # Create escalations table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS escalations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    escalation_reason TEXT,
                    original_severity TEXT,
                    new_severity TEXT,
                    incident_created BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES orchestrated_events (event_id)
                )
            ''')
            
            conn.commit()
            return conn
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            return None
    
    def _init_integration_engines(self):
        """Initialize SIEM and SOAR integration engines"""
        try:
            # Initialize SIEM integration engine
            siem_config_path = self.config.get('integrations', {}).get('siem', {}).get('config_path', '/etc/nsm/siem-integration.yaml')
            if Path(siem_config_path).exists():
                self.siem_engine = SIEMIntegrationEngine(siem_config_path)
                self.logger.info("Initialized SIEM integration engine")
            else:
                self.logger.warning(f"SIEM config not found at {siem_config_path}")
            
            # Initialize SOAR integration engine
            soar_config_path = self.config.get('integrations', {}).get('soar', {}).get('config_path', '/etc/nsm/soar-integration.yaml')
            if Path(soar_config_path).exists():
                self.soar_engine = SOARIntegrationEngine(soar_config_path)
                self.logger.info("Initialized SOAR integration engine")
            else:
                self.logger.warning(f"SOAR config not found at {soar_config_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize integration engines: {e}")
    
    def _load_escalation_rules(self) -> List[Dict[str, Any]]:
        """Load escalation rules from configuration"""
        return self.config.get('escalation_rules', [])
    
    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        """Load correlation rules from configuration"""
        return self.config.get('correlation_rules', [])
    
    async def add_event(self, event_data: Dict[str, Any]) -> bool:
        """Add event to orchestration queue"""
        try:
            # Convert to IntegratedEvent
            event = IntegratedEvent(
                event_id=event_data.get('event_id', str(uuid.uuid4())),
                timestamp=datetime.fromisoformat(event_data['timestamp']) if isinstance(event_data['timestamp'], str) else event_data['timestamp'],
                source=event_data['source'],
                event_type=event_data['event_type'],
                severity=event_data['severity'],
                priority=EventPriority(event_data.get('priority', 'medium')),
                title=event_data['title'],
                description=event_data['description'],
                raw_data=event_data.get('raw_data', {}),
                metadata=event_data.get('metadata', {}),
                enrichment=event_data.get('enrichment', {}),
                send_to_siem=event_data.get('send_to_siem', True),
                create_incident=event_data.get('create_incident', False),
                auto_execute_playbooks=event_data.get('auto_execute_playbooks', False)
            )
            
            # Add to processing queue
            await self.event_queue.put(event)
            
            # Store in database
            if self.database:
                cursor = self.database.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO orchestrated_events 
                    (event_id, timestamp, source, event_type, severity, priority, title)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.timestamp,
                    event.source,
                    event.event_type,
                    event.severity,
                    event.priority.value,
                    event.title
                ))
                self.database.commit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding event to orchestration queue: {e}")
            return False
    
    async def process_events(self):
        """Main event processing loop"""
        self.logger.info("Starting event orchestration loop")
        
        while self.running:
            try:
                # Get event from queue
                try:
                    event = await asyncio.wait_for(
                        self.event_queue.get(),
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the event
                await self._process_event(event)
                self.stats['events_processed'] += 1
                self.stats['last_processing_time'] = datetime.utcnow()
                
            except Exception as e:
                self.logger.error(f"Error in event orchestration loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_event(self, event: IntegratedEvent):
        """Process a single event through the orchestration pipeline"""
        self.logger.debug(f"Processing event {event.event_id}")
        
        try:
            # Step 1: Apply escalation rules
            escalated = await self._apply_escalation_rules(event)
            if escalated:
                self.logger.info(f"Event {event.event_id} escalated")
            
            # Step 2: Check for correlations
            correlation_id = await self._check_correlations(event)
            if correlation_id:
                event.correlation_id = correlation_id
                self.stats['correlations_found'] += 1
                self.logger.info(f"Event {event.event_id} correlated with {correlation_id}")
            
            # Step 3: Send to SIEM if configured
            if event.send_to_siem and self.siem_engine:
                await self._send_to_siem(event)
            
            # Step 4: Create incident in SOAR if needed
            if event.create_incident and self.soar_engine:
                await self._create_soar_incident(event)
            
            # Step 5: Update database
            await self._update_event_processing_status(event)
            
        except Exception as e:
            self.logger.error(f"Error processing event {event.event_id}: {e}")
    
    async def _apply_escalation_rules(self, event: IntegratedEvent) -> bool:
        """Apply escalation rules to determine if event should be escalated"""
        for rule in self.escalation_rules:
            try:
                if await self._evaluate_escalation_rule(event, rule):
                    # Apply escalation
                    original_severity = event.severity
                    original_create_incident = event.create_incident
                    
                    # Update event based on rule
                    if rule.get('new_severity'):
                        event.severity = rule['new_severity']
                    
                    if rule.get('create_incident'):
                        event.create_incident = True
                        event.auto_execute_playbooks = rule.get('auto_execute_playbooks', False)
                    
                    if rule.get('new_priority'):
                        event.priority = EventPriority(rule['new_priority'])
                    
                    # Log escalation
                    if self.database:
                        cursor = self.database.cursor()
                        cursor.execute('''
                            INSERT INTO escalations 
                            (event_id, escalation_reason, original_severity, new_severity, incident_created)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            event.event_id,
                            rule.get('name', 'Unknown rule'),
                            original_severity,
                            event.severity,
                            event.create_incident and not original_create_incident
                        ))
                        self.database.commit()
                    
                    return True
                    
            except Exception as e:
                self.logger.error(f"Error applying escalation rule {rule.get('name', 'unknown')}: {e}")
        
        return False
    
    async def _evaluate_escalation_rule(self, event: IntegratedEvent, rule: Dict[str, Any]) -> bool:
        """Evaluate if an escalation rule matches an event"""
        conditions = rule.get('conditions', {})
        
        # Check each condition
        for field, expected_value in conditions.items():
            event_value = None
            
            # Get event value
            if hasattr(event, field):
                event_value = getattr(event, field)
                if isinstance(event_value, Enum):
                    event_value = event_value.value
            elif field in event.metadata:
                event_value = event.metadata[field]
            elif field in event.enrichment:
                event_value = event.enrichment[field]
            else:
                # Check for nested fields
                if '.' in field:
                    parts = field.split('.')
                    if parts[0] == 'metadata':
                        event_value = event.metadata.get(parts[1])
                    elif parts[0] == 'enrichment':
                        event_value = event.enrichment.get(parts[1])
            
            # Evaluate condition
            if not self._evaluate_condition(event_value, expected_value):
                return False
        
        return True
    
    def _evaluate_condition(self, actual_value: Any, expected_value: Any) -> bool:
        """Evaluate a single condition"""
        if isinstance(expected_value, str):
            if expected_value.startswith('>='):
                return float(actual_value) >= float(expected_value[2:])
            elif expected_value.startswith('<='):
                return float(actual_value) <= float(expected_value[2:])
            elif expected_value.startswith('>'):
                return float(actual_value) > float(expected_value[1:])
            elif expected_value.startswith('<'):
                return float(actual_value) < float(expected_value[1:])
            elif expected_value.startswith('!='):
                return actual_value != expected_value[2:]
            else:
                return actual_value == expected_value
        else:
            return actual_value == expected_value
    
    async def _check_correlations(self, event: IntegratedEvent) -> Optional[str]:
        """Check for event correlations"""
        current_time = datetime.utcnow()
        
        # Clean old correlations
        cutoff_time = current_time - timedelta(seconds=self.correlation_window)
        self.correlation_cache = {
            k: v for k, v in self.correlation_cache.items()
            if v['timestamp'] > cutoff_time
        }
        
        # Check correlation rules
        for rule in self.correlation_rules:
            try:
                correlation_id = await self._evaluate_correlation_rule(event, rule)
                if correlation_id:
                    return correlation_id
            except Exception as e:
                self.logger.error(f"Error evaluating correlation rule {rule.get('name', 'unknown')}: {e}")
        
        # Add event to correlation cache for future matching
        cache_key = f"{event.source}_{event.event_type}_{event.metadata.get('src_ip', 'unknown')}"
        self.correlation_cache[cache_key] = {
            'event_id': event.event_id,
            'timestamp': current_time,
            'event': event
        }
        
        return None
    
    async def _evaluate_correlation_rule(self, event: IntegratedEvent, rule: Dict[str, Any]) -> Optional[str]:
        """Evaluate correlation rule against cached events"""
        # This is a simplified correlation logic
        # In a production system, this would be much more sophisticated
        
        rule_name = rule.get('name', 'unknown')
        conditions = rule.get('conditions', {})
        time_window = rule.get('time_window', self.correlation_window)
        
        # Look for matching events in cache
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=time_window)
        
        for cache_key, cached_data in self.correlation_cache.items():
            if cached_data['timestamp'] < cutoff_time:
                continue
            
            cached_event = cached_data['event']
            
            # Check if events match correlation conditions
            if self._events_correlate(event, cached_event, conditions):
                # Generate correlation ID
                correlation_id = str(uuid.uuid4())
                
                # Store correlation in database
                if self.database:
                    cursor = self.database.cursor()
                    for corr_event_id in [event.event_id, cached_event.event_id]:
                        cursor.execute('''
                            INSERT INTO event_correlations 
                            (correlation_id, event_id, correlation_type, confidence_score)
                            VALUES (?, ?, ?, ?)
                        ''', (correlation_id, corr_event_id, rule_name, 0.8))
                    self.database.commit()
                
                return correlation_id
        
        return None
    
    def _events_correlate(self, event1: IntegratedEvent, event2: IntegratedEvent, conditions: Dict[str, Any]) -> bool:
        """Check if two events correlate based on conditions"""
        # Simple correlation logic - can be extended
        for field, correlation_type in conditions.items():
            if correlation_type == 'same':
                if getattr(event1, field, None) != getattr(event2, field, None):
                    if event1.metadata.get(field) != event2.metadata.get(field):
                        return False
            elif correlation_type == 'sequence':
                # Check if events form a logical sequence
                # This would require more sophisticated logic
                pass
        
        return True
    
    async def _send_to_siem(self, event: IntegratedEvent):
        """Send event to SIEM platforms"""
        try:
            siem_event = event.to_siem_event()
            result = await self.siem_engine.add_event(siem_event.to_dict())
            
            if result:
                self.stats['events_sent_to_siem'] += 1
                self.logger.debug(f"Event {event.event_id} sent to SIEM")
                
                # Update database
                if self.database:
                    cursor = self.database.cursor()
                    cursor.execute('''
                        UPDATE orchestrated_events 
                        SET sent_to_siem = TRUE, processed_at = ?
                        WHERE event_id = ?
                    ''', (datetime.utcnow(), event.event_id))
                    self.database.commit()
            else:
                self.logger.error(f"Failed to send event {event.event_id} to SIEM")
                
        except Exception as e:
            self.logger.error(f"Error sending event {event.event_id} to SIEM: {e}")
    
    async def _create_soar_incident(self, event: IntegratedEvent):
        """Create incident in SOAR platforms"""
        try:
            # Determine playbooks to execute
            playbooks = self._determine_playbooks(event)
            
            # Create SOAR incident
            soar_incident = event.to_soar_incident(playbooks)
            result = await self.soar_engine.create_incident(soar_incident.to_dict())
            
            if result.get('success'):
                self.stats['incidents_created'] += 1
                self.logger.info(f"Incident created for event {event.event_id}")
                
                # Execute playbooks if configured
                if event.auto_execute_playbooks and playbooks:
                    for playbook in playbooks:
                        await self.soar_engine.execute_playbook(
                            soar_incident.incident_id,
                            playbook
                        )
                        self.stats['playbooks_executed'] += 1
                
                # Update database
                if self.database:
                    cursor = self.database.cursor()
                    cursor.execute('''
                        UPDATE orchestrated_events 
                        SET incident_created = TRUE, processed_at = ?
                        WHERE event_id = ?
                    ''', (datetime.utcnow(), event.event_id))
                    self.database.commit()
            else:
                self.logger.error(f"Failed to create incident for event {event.event_id}: {result.get('error')}")
                
        except Exception as e:
            self.logger.error(f"Error creating SOAR incident for event {event.event_id}: {e}")
    
    def _determine_playbooks(self, event: IntegratedEvent) -> List[str]:
        """Determine which playbooks to execute for an event"""
        playbooks = []
        
        playbook_mapping = self.config.get('playbook_mapping', {})
        
        # Check event type mapping
        if event.event_type in playbook_mapping:
            playbooks.extend(playbook_mapping[event.event_type])
        
        # Check severity-based mapping
        severity_mapping = playbook_mapping.get('by_severity', {})
        if event.severity in severity_mapping:
            playbooks.extend(severity_mapping[event.severity])
        
        # Check source-based mapping
        source_mapping = playbook_mapping.get('by_source', {})
        if event.source in source_mapping:
            playbooks.extend(source_mapping[event.source])
        
        # Remove duplicates
        return list(set(playbooks))
    
    async def _update_event_processing_status(self, event: IntegratedEvent):
        """Update event processing status in database"""
        if self.database:
            try:
                cursor = self.database.cursor()
                cursor.execute('''
                    UPDATE orchestrated_events 
                    SET correlation_id = ?, processed_at = ?
                    WHERE event_id = ?
                ''', (event.correlation_id, datetime.utcnow(), event.event_id))
                self.database.commit()
            except Exception as e:
                self.logger.error(f"Error updating event processing status: {e}")
    
    async def process_redis_events(self):
        """Process events from Redis streams"""
        if not self.redis_client:
            return
        
        self.logger.info("Starting Redis event processing")
        
        while self.running:
            try:
                # Get events from Redis stream
                events = self.redis_client.xread(
                    {'nsm:orchestrator_events': '$'},
                    count=10,
                    block=30000
                )
                
                for stream, messages in events:
                    for message_id, fields in messages:
                        try:
                            event_data = json.loads(fields.get('data', '{}'))
                            await self.add_event(event_data)
                        except Exception as e:
                            self.logger.error(f"Error processing Redis event {message_id}: {e}")
                
            except Exception as e:
                self.logger.error(f"Error processing Redis events: {e}")
                await asyncio.sleep(1)
    
    async def start(self):
        """Start the integration orchestrator"""
        self.logger.info("Starting Integration Orchestrator")
        self.running = True
        
        # Start integration engines
        engine_tasks = []
        if self.siem_engine:
            engine_tasks.append(asyncio.create_task(self.siem_engine.start()))
        if self.soar_engine:
            engine_tasks.append(asyncio.create_task(self.soar_engine.start()))
        
        # Start orchestrator tasks
        orchestrator_tasks = [
            asyncio.create_task(self.process_events()),
        ]
        
        # Add Redis processing if configured
        if self.redis_client:
            orchestrator_tasks.append(asyncio.create_task(self.process_redis_events()))
        
        all_tasks = engine_tasks + orchestrator_tasks
        
        try:
            # Wait for shutdown signal
            await self.shutdown_event.wait()
        finally:
            # Stop integration engines
            if self.siem_engine:
                self.siem_engine.stop()
            if self.soar_engine:
                self.soar_engine.stop()
            
            # Cancel all tasks
            for task in all_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*all_tasks, return_exceptions=True)
            
            # Cleanup
            if self.database:
                self.database.close()
            
            if self.redis_client:
                self.redis_client.close()
            
            self.executor.shutdown(wait=True)
    
    def stop(self):
        """Stop the integration orchestrator"""
        self.logger.info("Stopping Integration Orchestrator")
        self.running = False
        self.shutdown_event.set()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        stats = {
            'orchestrator_stats': self.stats,
            'queue_size': self.event_queue.qsize(),
            'correlation_cache_size': len(self.correlation_cache)
        }
        
        # Add SIEM engine stats if available
        if self.siem_engine:
            stats['siem_stats'] = self.siem_engine.get_stats()
        
        # Add SOAR engine stats if available
        if self.soar_engine:
            stats['soar_stats'] = self.soar_engine.get_stats()
        
        return stats


async def main():
    """Main entry point"""
    import signal
    
    # Initialize orchestrator
    orchestrator = IntegrationOrchestrator()
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        print(f"Received signal {signum}, shutting down...")
        orchestrator.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the orchestrator
    await orchestrator.start()


if __name__ == "__main__":
    asyncio.run(main())