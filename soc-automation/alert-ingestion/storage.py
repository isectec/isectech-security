"""
Elasticsearch Storage Engine for SOC Automation Platform

Handles efficient storage and retrieval of normalized security alerts
with proper indexing, data lifecycle management, and search capabilities.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, AsyncGenerator
from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import ElasticsearchException, NotFoundError
import structlog

logger = structlog.get_logger(__name__)

class ElasticsearchStorage:
    """
    Elasticsearch storage engine for security alerts with optimized indexing,
    retention policies, and search capabilities.
    
    Features:
    - Time-based index management (daily/weekly rotation)
    - Index templates with proper field mappings
    - Data lifecycle management (retention policies)
    - Bulk operations for high throughput
    - Search and aggregation APIs
    - Index health monitoring
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client: AsyncElasticsearch = None
        
        # Configuration
        self.hosts = config.get('hosts', ['localhost:9200'])
        self.index_prefix = config.get('index_prefix', 'soc-alerts')
        self.index_pattern = config.get('index_pattern', 'daily')  # daily, weekly, monthly
        self.replicas = config.get('replicas', 1)
        self.shards = config.get('shards', 1)
        self.retention_days = config.get('retention_days', 90)
        self.bulk_size = config.get('bulk_size', 1000)
        
        # Authentication
        self.username = config.get('username')
        self.password = config.get('password')
        self.api_key = config.get('api_key')
        self.ca_cert = config.get('ca_cert')
        
        # Index settings
        self.index_settings = {
            "number_of_shards": self.shards,
            "number_of_replicas": self.replicas,
            "refresh_interval": "1s",
            "max_result_window": 50000,
            "lifecycle": {
                "name": f"{self.index_prefix}-policy",
                "rollover_alias": f"{self.index_prefix}-write"
            }
        }
        
        logger.info("ElasticsearchStorage initialized",
                   hosts=self.hosts,
                   index_prefix=self.index_prefix,
                   retention_days=self.retention_days)
    
    async def initialize(self):
        """Initialize Elasticsearch connection and setup indices"""
        try:
            # Create client
            client_config = {
                'hosts': self.hosts,
                'verify_certs': True,
                'ssl_show_warn': False,
                'request_timeout': 30,
                'max_retries': 3,
                'retry_on_timeout': True
            }
            
            # Add authentication
            if self.api_key:
                client_config['api_key'] = self.api_key
            elif self.username and self.password:
                client_config['basic_auth'] = (self.username, self.password)
            
            if self.ca_cert:
                client_config['ca_certs'] = self.ca_cert
            
            self.client = AsyncElasticsearch(**client_config)
            
            # Test connection
            await self.client.ping()
            logger.info("Elasticsearch connection established")
            
            # Setup index templates and policies
            await self._setup_index_template()
            await self._setup_lifecycle_policy()
            await self._create_initial_index()
            
            logger.info("Elasticsearch initialization completed")
            
        except Exception as e:
            logger.error("Failed to initialize Elasticsearch", error=str(e))
            raise
    
    async def close(self):
        """Close Elasticsearch connection"""
        if self.client:
            await self.client.close()
            logger.info("Elasticsearch connection closed")
    
    async def store_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Store a single normalized alert
        
        Args:
            alert: Normalized alert dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            index_name = self._get_index_name(alert.get('timestamp'))
            
            # Ensure timestamp is properly formatted
            if 'timestamp' in alert and isinstance(alert['timestamp'], datetime):
                alert['timestamp'] = alert['timestamp'].isoformat()
            
            # Add ingestion timestamp
            alert['@timestamp'] = datetime.now(timezone.utc).isoformat()
            
            response = await self.client.index(
                index=index_name,
                id=alert.get('alert_id'),
                document=alert
            )
            
            if response.get('result') in ['created', 'updated']:
                logger.debug("Alert stored successfully",
                           alert_id=alert.get('alert_id'),
                           index=index_name)
                return True
            
            return False
            
        except ElasticsearchException as e:
            logger.error("Failed to store alert",
                        alert_id=alert.get('alert_id'),
                        error=str(e))
            return False
    
    async def store_alerts_bulk(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Store multiple alerts using bulk API for high throughput
        
        Args:
            alerts: List of normalized alert dictionaries
            
        Returns:
            Dictionary with success/failure counts
        """
        if not alerts:
            return {'success': 0, 'failed': 0, 'total': 0}
        
        try:
            # Prepare bulk operations
            operations = []
            for alert in alerts:
                index_name = self._get_index_name(alert.get('timestamp'))
                
                # Format timestamp
                if 'timestamp' in alert and isinstance(alert['timestamp'], datetime):
                    alert['timestamp'] = alert['timestamp'].isoformat()
                
                alert['@timestamp'] = datetime.now(timezone.utc).isoformat()
                
                # Add index operation
                operations.append({
                    "_index": index_name,
                    "_id": alert.get('alert_id'),
                    "_source": alert
                })
            
            # Execute bulk operation
            response = await self.client.bulk(
                operations=operations,
                refresh='wait_for'
            )
            
            # Count results
            success_count = 0
            failed_count = 0
            
            for item in response.get('items', []):
                operation_result = item.get('index', {})
                if operation_result.get('status') in [200, 201]:
                    success_count += 1
                else:
                    failed_count += 1
                    logger.warning("Bulk operation failed for item",
                                 error=operation_result.get('error'))
            
            logger.info("Bulk alert storage completed",
                       total=len(alerts),
                       success=success_count,
                       failed=failed_count)
            
            return {
                'success': success_count,
                'failed': failed_count,
                'total': len(alerts)
            }
            
        except ElasticsearchException as e:
            logger.error("Bulk storage failed", error=str(e))
            return {'success': 0, 'failed': len(alerts), 'total': len(alerts)}
    
    async def search_alerts(
        self,
        query: Dict[str, Any] = None,
        filters: Dict[str, Any] = None,
        sort: List[Dict[str, str]] = None,
        size: int = 100,
        from_: int = 0,
        index_pattern: str = None
    ) -> Dict[str, Any]:
        """
        Search alerts with flexible query options
        
        Args:
            query: Elasticsearch query DSL
            filters: Simple field filters
            sort: Sort configuration
            size: Number of results
            from_: Starting offset
            index_pattern: Specific index pattern to search
            
        Returns:
            Search results with hits and aggregations
        """
        try:
            # Build search body
            search_body = {
                "size": min(size, 10000),  # Limit max size
                "from": from_
            }
            
            # Build query
            if query or filters:
                search_body["query"] = self._build_query(query, filters)
            else:
                search_body["query"] = {"match_all": {}}
            
            # Add sorting
            if sort:
                search_body["sort"] = sort
            else:
                search_body["sort"] = [{"timestamp": {"order": "desc"}}]
            
            # Add basic aggregations
            search_body["aggs"] = {
                "severity_counts": {
                    "terms": {"field": "severity.keyword"}
                },
                "category_counts": {
                    "terms": {"field": "category.keyword"}
                },
                "source_counts": {
                    "terms": {"field": "source.keyword"}
                },
                "timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "1h"
                    }
                }
            }
            
            # Determine index to search
            index = index_pattern or f"{self.index_prefix}-*"
            
            response = await self.client.search(
                index=index,
                body=search_body
            )
            
            logger.debug("Alert search completed",
                        index=index,
                        total_hits=response['hits']['total']['value'],
                        returned=len(response['hits']['hits']))
            
            return response
            
        except ElasticsearchException as e:
            logger.error("Alert search failed", error=str(e))
            raise
    
    async def get_alert(self, alert_id: str, index_pattern: str = None) -> Optional[Dict[str, Any]]:
        """Get a specific alert by ID"""
        try:
            index = index_pattern or f"{self.index_prefix}-*"
            
            response = await self.client.get(
                index=index,
                id=alert_id
            )
            
            return response['_source']
            
        except NotFoundError:
            logger.debug("Alert not found", alert_id=alert_id)
            return None
        except ElasticsearchException as e:
            logger.error("Failed to get alert", alert_id=alert_id, error=str(e))
            return None
    
    async def get_alerts_stream(
        self,
        query: Dict[str, Any] = None,
        batch_size: int = 1000
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream alerts using scroll API for large result sets"""
        try:
            search_body = {
                "size": batch_size,
                "query": query or {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            response = await self.client.search(
                index=f"{self.index_prefix}-*",
                body=search_body,
                scroll='5m'
            )
            
            scroll_id = response.get('_scroll_id')
            
            # Yield initial results
            for hit in response['hits']['hits']:
                yield hit['_source']
            
            # Continue scrolling
            while scroll_id and response['hits']['hits']:
                response = await self.client.scroll(
                    scroll_id=scroll_id,
                    scroll='5m'
                )
                
                for hit in response['hits']['hits']:
                    yield hit['_source']
            
            # Clean up scroll
            if scroll_id:
                await self.client.clear_scroll(scroll_id=scroll_id)
                
        except ElasticsearchException as e:
            logger.error("Alert streaming failed", error=str(e))
    
    async def delete_old_indices(self, retention_days: int = None) -> List[str]:
        """Delete indices older than retention period"""
        retention_days = retention_days or self.retention_days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        try:
            # Get all indices matching our pattern
            indices = await self.client.indices.get(
                index=f"{self.index_prefix}-*",
                ignore=[404]
            )
            
            deleted_indices = []
            
            for index_name in indices:
                # Extract date from index name
                index_date = self._extract_date_from_index_name(index_name)
                
                if index_date and index_date < cutoff_date:
                    await self.client.indices.delete(index=index_name)
                    deleted_indices.append(index_name)
                    logger.info("Deleted old index", index=index_name, date=index_date)
            
            return deleted_indices
            
        except ElasticsearchException as e:
            logger.error("Failed to delete old indices", error=str(e))
            return []
    
    async def get_index_stats(self) -> Dict[str, Any]:
        """Get statistics about alert indices"""
        try:
            stats = await self.client.indices.stats(
                index=f"{self.index_prefix}-*"
            )
            
            return {
                'total_indices': len(stats.get('indices', {})),
                'total_size_bytes': stats.get('_all', {}).get('total', {}).get('store', {}).get('size_in_bytes', 0),
                'total_documents': stats.get('_all', {}).get('total', {}).get('docs', {}).get('count', 0),
                'indices': stats.get('indices', {})
            }
            
        except ElasticsearchException as e:
            logger.error("Failed to get index stats", error=str(e))
            return {}
    
    def _get_index_name(self, timestamp: datetime = None) -> str:
        """Generate index name based on timestamp and pattern"""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        elif isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        if self.index_pattern == 'daily':
            suffix = timestamp.strftime('%Y-%m-%d')
        elif self.index_pattern == 'weekly':
            year, week, _ = timestamp.isocalendar()
            suffix = f"{year}-w{week:02d}"
        elif self.index_pattern == 'monthly':
            suffix = timestamp.strftime('%Y-%m')
        else:
            suffix = timestamp.strftime('%Y-%m-%d')  # Default to daily
        
        return f"{self.index_prefix}-{suffix}"
    
    def _extract_date_from_index_name(self, index_name: str) -> Optional[datetime]:
        """Extract date from index name for lifecycle management"""
        try:
            date_part = index_name.replace(f"{self.index_prefix}-", "")
            
            if self.index_pattern == 'daily':
                return datetime.strptime(date_part, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            elif self.index_pattern == 'weekly':
                year, week = date_part.split('-w')
                return datetime.strptime(f"{year}-W{week}-1", '%Y-W%W-%w').replace(tzinfo=timezone.utc)
            elif self.index_pattern == 'monthly':
                return datetime.strptime(date_part + "-01", '%Y-%m-%d').replace(tzinfo=timezone.utc)
            
        except (ValueError, IndexError):
            pass
        
        return None
    
    def _build_query(self, query: Dict[str, Any], filters: Dict[str, Any]) -> Dict[str, Any]:
        """Build Elasticsearch query from parameters"""
        if query and filters:
            return {
                "bool": {
                    "must": [query],
                    "filter": [{"terms" if isinstance(v, list) else "term": {k: v}} 
                              for k, v in filters.items()]
                }
            }
        elif query:
            return query
        elif filters:
            return {
                "bool": {
                    "filter": [{"terms" if isinstance(v, list) else "term": {k: v}} 
                              for k, v in filters.items()]
                }
            }
        else:
            return {"match_all": {}}
    
    async def _setup_index_template(self):
        """Setup index template for alert indices"""
        template_name = f"{self.index_prefix}-template"
        
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "settings": self.index_settings,
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "timestamp": {"type": "date"},
                        "alert_id": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "source_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "alert_type": {"type": "keyword"},
                        "signature": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                        "rule_id": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "source_port": {"type": "integer"},
                        "destination_port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "hostname": {"type": "keyword"},
                        "user": {"type": "keyword"},
                        "process": {"type": "keyword"},
                        "file_path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                        "description": {"type": "text"},
                        "details": {"type": "object", "enabled": False},
                        "raw_data": {"type": "object", "enabled": False},
                        "mitre_tactics": {"type": "keyword"},
                        "mitre_techniques": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "metadata": {
                            "properties": {
                                "ingestion_time": {"type": "date"},
                                "processing_stage": {"type": "keyword"},
                                "enrichment_count": {"type": "integer"},
                                "priority": {"type": "keyword"}
                            }
                        }
                    }
                }
            }
        }
        
        await self.client.indices.put_index_template(
            name=template_name,
            body=template
        )
        
        logger.info("Index template created", name=template_name)
    
    async def _setup_lifecycle_policy(self):
        """Setup Index Lifecycle Management policy"""
        policy_name = f"{self.index_prefix}-policy"
        
        policy = {
            "policy": {
                "phases": {
                    "hot": {
                        "actions": {
                            "rollover": {
                                "max_size": "10gb",
                                "max_age": "7d"
                            }
                        }
                    },
                    "warm": {
                        "min_age": "7d",
                        "actions": {
                            "shrink": {"number_of_shards": 1},
                            "forcemerge": {"max_num_segments": 1}
                        }
                    },
                    "cold": {
                        "min_age": "30d",
                        "actions": {
                            "allocate": {"number_of_replicas": 0}
                        }
                    },
                    "delete": {
                        "min_age": f"{self.retention_days}d"
                    }
                }
            }
        }
        
        try:
            await self.client.ilm.put_lifecycle(
                name=policy_name,
                body=policy
            )
            logger.info("ILM policy created", name=policy_name)
        except Exception as e:
            logger.warning("Failed to create ILM policy", error=str(e))
    
    async def _create_initial_index(self):
        """Create initial index if it doesn't exist"""
        index_name = self._get_index_name()
        
        try:
            exists = await self.client.indices.exists(index=index_name)
            if not exists:
                await self.client.indices.create(
                    index=index_name,
                    body={"settings": self.index_settings}
                )
                logger.info("Initial index created", index=index_name)
        except Exception as e:
            logger.warning("Failed to create initial index", error=str(e))