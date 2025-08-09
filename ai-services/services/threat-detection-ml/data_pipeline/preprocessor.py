"""
Data Preprocessing Pipeline for AI/ML Threat Detection

This module implements comprehensive data preprocessing including cleaning,
normalization, anonymization, feature engineering, and data validation
for security event data used in ML model training and inference.
"""

import asyncio
import logging
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum

import pandas as pd
import numpy as np
from sklearn.preprocessing import (
    StandardScaler, RobustScaler, MinMaxScaler,
    LabelEncoder, OneHotEncoder, TargetEncoder
)
from sklearn.impute import SimpleImputer, KNNImputer
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import re
from cryptography.fernet import Fernet

from .collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.security.encryption import EncryptionManager
from ...shared.api.monitoring import MetricsCollector


logger = logging.getLogger(__name__)

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('wordnet', quiet=True)
except Exception as e:
    logger.warning(f"Failed to download NLTK data: {e}")


class DataQualityIssue(Enum):
    """Types of data quality issues."""
    MISSING_VALUE = "missing_value"
    INVALID_FORMAT = "invalid_format"
    OUTLIER = "outlier"
    DUPLICATE = "duplicate"
    INCONSISTENT_TYPE = "inconsistent_type"
    PRIVACY_VIOLATION = "privacy_violation"


@dataclass
class PreprocessingConfig:
    """Configuration for data preprocessing."""
    # Cleaning options
    handle_missing_values: str = "impute"  # 'drop', 'impute', 'flag'
    outlier_detection_method: str = "iqr"  # 'iqr', 'zscore', 'isolation_forest'
    outlier_threshold: float = 3.0
    duplicate_removal: bool = True
    
    # Normalization options
    numerical_scaler: str = "robust"  # 'standard', 'robust', 'minmax'
    categorical_encoder: str = "target"  # 'onehot', 'label', 'target'
    text_preprocessing: bool = True
    
    # Privacy and anonymization
    anonymize_pii: bool = True
    hash_sensitive_fields: List[str] = None
    ip_anonymization: str = "subnet"  # 'hash', 'subnet', 'none'
    
    # Feature engineering
    create_temporal_features: bool = True
    create_statistical_features: bool = True
    feature_selection_method: str = "mutual_info"  # 'f_classif', 'mutual_info', 'none'
    max_features: Optional[int] = 1000
    
    # Validation
    data_validation: bool = True
    quality_threshold: float = 0.95
    
    def __post_init__(self):
        if self.hash_sensitive_fields is None:
            self.hash_sensitive_fields = [
                'username', 'email', 'user_id', 'session_id',
                'file_path', 'command_line'
            ]


class DataValidator:
    """Validates data quality and consistency."""
    
    def __init__(self, config: PreprocessingConfig, metrics: MetricsCollector):
        self.config = config
        self.metrics = metrics
        self.quality_issues: List[Dict] = []
    
    def validate_event(self, event: SecurityEvent) -> Tuple[bool, List[DataQualityIssue]]:
        """Validate a single security event."""
        issues = []
        
        # Check required fields
        if not event.timestamp:
            issues.append(DataQualityIssue.MISSING_VALUE)
        if not event.event_type:
            issues.append(DataQualityIssue.MISSING_VALUE)
        
        # Validate timestamp format
        if event.timestamp and not isinstance(event.timestamp, datetime):
            issues.append(DataQualityIssue.INVALID_FORMAT)
        
        # Validate IP addresses
        for ip_field in ['source_ip', 'dest_ip']:
            ip_value = getattr(event, ip_field, None)
            if ip_value and not self._is_valid_ip(ip_value):
                issues.append(DataQualityIssue.INVALID_FORMAT)
        
        # Validate port numbers
        if event.port and (event.port < 0 or event.port > 65535):
            issues.append(DataQualityIssue.INVALID_FORMAT)
        
        # Check for PII that should be anonymized
        if self.config.anonymize_pii:
            if self._contains_pii(event):
                issues.append(DataQualityIssue.PRIVACY_VIOLATION)
        
        # Record quality issues
        for issue in issues:
            self.quality_issues.append({
                'event_id': event.event_id,
                'issue_type': issue.value,
                'timestamp': datetime.utcnow()
            })
            self.metrics.increment_counter("data_quality_issues", 
                                         tags={"issue_type": issue.value})
        
        is_valid = len(issues) == 0
        return is_valid, issues
    
    def _is_valid_ip(self, ip_string: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    def _contains_pii(self, event: SecurityEvent) -> bool:
        """Check if event contains personally identifiable information."""
        pii_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email pattern
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'  # Credit card pattern
        ]
        
        # Check all string fields for PII patterns
        for field_name, field_value in event.dict().items():
            if isinstance(field_value, str):
                for pattern in pii_patterns:
                    if re.search(pattern, field_value):
                        return True
        
        return False
    
    def get_quality_report(self) -> Dict[str, Any]:
        """Generate a data quality report."""
        if not self.quality_issues:
            return {"quality_score": 1.0, "issues": [], "total_events": 0}
        
        issue_counts = {}
        for issue in self.quality_issues:
            issue_type = issue['issue_type']
            issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
        
        total_issues = len(self.quality_issues)
        total_events = len(set(issue['event_id'] for issue in self.quality_issues))
        quality_score = max(0.0, 1.0 - (total_issues / max(total_events * 5, 1)))
        
        return {
            "quality_score": quality_score,
            "total_issues": total_issues,
            "total_events": total_events,
            "issue_breakdown": issue_counts,
            "recent_issues": self.quality_issues[-10:]  # Last 10 issues
        }


class PrivacyPreprocessor:
    """Handles privacy protection and data anonymization."""
    
    def __init__(self, config: PreprocessingConfig):
        self.config = config
        self.encryption_manager = EncryptionManager()
        self.hash_salt = self._generate_salt()
    
    def _generate_salt(self) -> bytes:
        """Generate a salt for hashing."""
        return b"isectech_ml_threat_detection_salt_2024"  # Fixed salt for consistency
    
    def anonymize_event(self, event: SecurityEvent) -> SecurityEvent:
        """Anonymize sensitive data in security event."""
        anonymized_data = event.dict().copy()
        
        # Hash sensitive fields
        for field in self.config.hash_sensitive_fields:
            if field in anonymized_data and anonymized_data[field]:
                anonymized_data[field] = self._hash_field(anonymized_data[field])
        
        # Anonymize IP addresses
        if self.config.ip_anonymization != 'none':
            for ip_field in ['source_ip', 'dest_ip']:
                if ip_field in anonymized_data and anonymized_data[ip_field]:
                    anonymized_data[ip_field] = self._anonymize_ip(
                        anonymized_data[ip_field]
                    )
        
        # Remove or redact command line arguments that might contain sensitive data
        if 'command_line' in anonymized_data and anonymized_data['command_line']:
            anonymized_data['command_line'] = self._sanitize_command_line(
                anonymized_data['command_line']
            )
        
        # Create new SecurityEvent with anonymized data
        return SecurityEvent(**anonymized_data)
    
    def _hash_field(self, field_value: str) -> str:
        """Hash a sensitive field value."""
        if not isinstance(field_value, str):
            field_value = str(field_value)
        
        hash_input = field_value.encode('utf-8') + self.hash_salt
        return hashlib.sha256(hash_input).hexdigest()[:16]  # Truncate for storage efficiency
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            if self.config.ip_anonymization == 'hash':
                return self._hash_field(ip_address)
            elif self.config.ip_anonymization == 'subnet':
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    # Mask last octet for IPv4
                    return str(ipaddress.IPv4Network(f"{ip_address}/24", strict=False).network_address)
                else:
                    # Mask last 64 bits for IPv6
                    return str(ipaddress.IPv6Network(f"{ip_address}/64", strict=False).network_address)
        except ValueError:
            # Invalid IP address, return hashed version
            return self._hash_field(ip_address)
        
        return ip_address
    
    def _sanitize_command_line(self, command_line: str) -> str:
        """Remove sensitive information from command line."""
        # Common sensitive patterns to remove
        sensitive_patterns = [
            r'--password[=\s]+\S+',
            r'--token[=\s]+\S+',
            r'--key[=\s]+\S+',
            r'--secret[=\s]+\S+',
            r'-p\s+\S+',
            r'password=\S+',
            r'token=\S+',
            r'apikey=\S+'
        ]
        
        sanitized = command_line
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        return sanitized


class FeatureEngineer:
    """Creates features for machine learning models."""
    
    def __init__(self, config: PreprocessingConfig):
        self.config = config
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
    
    def create_temporal_features(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Create time-based features from timestamps."""
        if not self.config.create_temporal_features:
            return events_df
        
        df = events_df.copy()
        
        # Convert timestamp to datetime if it's not already
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Extract temporal components
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['day_of_month'] = df['timestamp'].dt.day
        df['month'] = df['timestamp'].dt.month
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        # Create cyclical features for better ML model understanding
        df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        
        return df
    
    def create_network_features(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Create network-based features."""
        df = events_df.copy()
        
        # Port-based features
        if 'port' in df.columns:
            df['is_well_known_port'] = (df['port'] <= 1023).astype(int)
            df['is_registered_port'] = ((df['port'] > 1023) & (df['port'] <= 49151)).astype(int)
            df['is_dynamic_port'] = (df['port'] > 49151).astype(int)
        
        # Protocol-based features
        if 'network_protocol' in df.columns:
            common_protocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'ssh', 'ftp']
            for protocol in common_protocols:
                df[f'is_{protocol}'] = (
                    df['network_protocol'].str.lower() == protocol
                ).astype(int)
        
        # IP-based features (for non-anonymized data)
        for ip_col in ['source_ip', 'dest_ip']:
            if ip_col in df.columns:
                df[f'{ip_col}_is_private'] = df[ip_col].apply(
                    self._is_private_ip
                ).astype(int)
                df[f'{ip_col}_is_loopback'] = df[ip_col].apply(
                    self._is_loopback_ip
                ).astype(int)
        
        return df
    
    def create_text_features(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Create features from text fields."""
        if not self.config.text_preprocessing:
            return events_df
        
        df = events_df.copy()
        
        # Process command line features
        if 'command_line' in df.columns:
            df['cmd_length'] = df['command_line'].fillna('').str.len()
            df['cmd_word_count'] = df['command_line'].fillna('').str.split().str.len()
            df['cmd_has_special_chars'] = df['command_line'].fillna('').str.contains(
                r'[;&|><$`]'
            ).astype(int)
            df['cmd_has_network_words'] = df['command_line'].fillna('').str.contains(
                r'\b(wget|curl|nc|netcat|ssh|scp|ftp)\b', case=False
            ).astype(int)
            df['cmd_has_file_ops'] = df['command_line'].fillna('').str.contains(
                r'\b(rm|del|copy|move|cp|mv|chmod)\b', case=False
            ).astype(int)
            
            # Extract key command components
            df['base_command'] = df['command_line'].fillna('').str.split().str[0]
        
        # Process process name features
        if 'process_name' in df.columns:
            df['proc_is_system'] = df['process_name'].fillna('').str.contains(
                r'\b(system|kernel|svchost|services)\b', case=False
            ).astype(int)
            df['proc_is_browser'] = df['process_name'].fillna('').str.contains(
                r'\b(chrome|firefox|safari|edge|browser)\b', case=False
            ).astype(int)
            df['proc_is_office'] = df['process_name'].fillna('').str.contains(
                r'\b(word|excel|powerpoint|outlook|office)\b', case=False
            ).astype(int)
        
        return df
    
    def create_statistical_features(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Create statistical features based on event patterns."""
        if not self.config.create_statistical_features:
            return events_df
        
        df = events_df.copy()
        
        # Count-based features per user/host
        for group_col in ['username', 'hostname', 'source_ip']:
            if group_col in df.columns:
                # Event frequency features
                event_counts = df.groupby(group_col).size()
                df[f'{group_col}_event_count'] = df[group_col].map(event_counts)
                
                # Unique destination count
                if 'dest_ip' in df.columns:
                    unique_dests = df.groupby(group_col)['dest_ip'].nunique()
                    df[f'{group_col}_unique_dests'] = df[group_col].map(unique_dests)
                
                # Time-based patterns
                if 'hour' in df.columns:
                    hour_std = df.groupby(group_col)['hour'].std()
                    df[f'{group_col}_hour_variance'] = df[group_col].map(hour_std).fillna(0)
        
        # Sequence-based features
        df_sorted = df.sort_values(['username', 'timestamp'])
        df['time_since_last_event'] = df_sorted.groupby('username')['timestamp'].diff().dt.total_seconds()
        df['time_since_last_event'] = df['time_since_last_event'].fillna(0)
        
        return df
    
    def _is_private_ip(self, ip_string: str) -> bool:
        """Check if IP is in private address space."""
        try:
            ip_obj = ipaddress.ip_address(ip_string)
            return ip_obj.is_private
        except (ValueError, AttributeError):
            return False
    
    def _is_loopback_ip(self, ip_string: str) -> bool:
        """Check if IP is a loopback address."""
        try:
            ip_obj = ipaddress.ip_address(ip_string)
            return ip_obj.is_loopback
        except (ValueError, AttributeError):
            return False


class DataPreprocessor:
    """Main data preprocessing pipeline."""
    
    def __init__(self, config: PreprocessingConfig, settings: Settings):
        self.config = config
        self.settings = settings
        self.metrics = MetricsCollector("ml_data_preprocessing")
        
        # Initialize components
        self.validator = DataValidator(config, self.metrics)
        self.privacy_processor = PrivacyPreprocessor(config)
        self.feature_engineer = FeatureEngineer(config)
        
        # Initialize scalers and encoders (to be fitted during preprocessing)
        self.numerical_scaler = self._create_scaler()
        self.categorical_encoders = {}
        self.feature_selector = None
        self.fitted = False
    
    def _create_scaler(self):
        """Create the appropriate scaler based on configuration."""
        if self.config.numerical_scaler == 'standard':
            return StandardScaler()
        elif self.config.numerical_scaler == 'robust':
            return RobustScaler()
        elif self.config.numerical_scaler == 'minmax':
            return MinMaxScaler()
        else:
            return RobustScaler()  # Default fallback
    
    async def preprocess_batch(
        self,
        events: List[SecurityEvent],
        is_training: bool = False
    ) -> pd.DataFrame:
        """Preprocess a batch of security events."""
        start_time = datetime.utcnow()
        
        try:
            # Step 1: Validate events
            valid_events = []
            for event in events:
                is_valid, issues = self.validator.validate_event(event)
                if is_valid or len(issues) <= 2:  # Allow minor quality issues
                    valid_events.append(event)
            
            logger.info(f"Validated {len(valid_events)}/{len(events)} events")
            self.metrics.increment_counter("events_validated", value=len(valid_events))
            
            if not valid_events:
                return pd.DataFrame()
            
            # Step 2: Privacy processing
            if self.config.anonymize_pii:
                valid_events = [
                    self.privacy_processor.anonymize_event(event)
                    for event in valid_events
                ]
            
            # Step 3: Convert to DataFrame
            events_df = pd.DataFrame([event.dict() for event in valid_events])
            
            # Step 4: Handle missing values
            events_df = self._handle_missing_values(events_df)
            
            # Step 5: Remove duplicates
            if self.config.duplicate_removal:
                initial_count = len(events_df)
                events_df = events_df.drop_duplicates(
                    subset=['event_id', 'timestamp', 'event_type']
                )
                removed_count = initial_count - len(events_df)
                if removed_count > 0:
                    logger.info(f"Removed {removed_count} duplicate events")
                    self.metrics.increment_counter("duplicates_removed", value=removed_count)
            
            # Step 6: Feature engineering
            events_df = self.feature_engineer.create_temporal_features(events_df)
            events_df = self.feature_engineer.create_network_features(events_df)
            events_df = self.feature_engineer.create_text_features(events_df)
            events_df = self.feature_engineer.create_statistical_features(events_df)
            
            # Step 7: Outlier detection and removal
            events_df = self._handle_outliers(events_df)
            
            # Step 8: Encoding and scaling
            events_df = self._encode_categorical_features(events_df, is_training)
            events_df = self._scale_numerical_features(events_df, is_training)
            
            # Step 9: Feature selection (for training data)
            if is_training and self.config.feature_selection_method != 'none':
                events_df = self._select_features(events_df, is_training)
            elif not is_training and self.feature_selector:
                # Apply pre-fitted feature selector
                feature_cols = [col for col in events_df.columns 
                               if col not in ['event_id', 'timestamp', 'target']]
                if feature_cols:
                    selected_features = self.feature_selector.get_support()
                    selected_cols = [col for col, selected in zip(feature_cols, selected_features) if selected]
                    # Keep non-feature columns
                    other_cols = [col for col in events_df.columns if col not in feature_cols]
                    events_df = events_df[other_cols + selected_cols]
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            self.metrics.observe_histogram("preprocessing_duration", processing_time)
            
            logger.info(f"Preprocessed {len(events_df)} events in {processing_time:.2f} seconds")
            
            if is_training:
                self.fitted = True
            
            return events_df
            
        except Exception as e:
            logger.error(f"Error in preprocessing: {e}")
            self.metrics.increment_counter("preprocessing_errors")
            raise
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in the dataset."""
        if self.config.handle_missing_values == 'drop':
            return df.dropna()
        elif self.config.handle_missing_values == 'impute':
            # Separate numerical and categorical columns
            num_cols = df.select_dtypes(include=[np.number]).columns
            cat_cols = df.select_dtypes(include=['object']).columns
            
            # Impute numerical columns with median
            if len(num_cols) > 0:
                imputer = SimpleImputer(strategy='median')
                df[num_cols] = imputer.fit_transform(df[num_cols])
            
            # Impute categorical columns with mode
            if len(cat_cols) > 0:
                imputer = SimpleImputer(strategy='most_frequent')
                df[cat_cols] = imputer.fit_transform(df[cat_cols])
        elif self.config.handle_missing_values == 'flag':
            # Create missing value flags and fill with defaults
            for col in df.columns:
                if df[col].isnull().any():
                    df[f'{col}_is_missing'] = df[col].isnull().astype(int)
                    if df[col].dtype in [np.number]:
                        df[col] = df[col].fillna(0)
                    else:
                        df[col] = df[col].fillna('unknown')
        
        return df
    
    def _handle_outliers(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect and handle outliers in numerical features."""
        num_cols = df.select_dtypes(include=[np.number]).columns
        
        if self.config.outlier_detection_method == 'iqr':
            for col in num_cols:
                Q1 = df[col].quantile(0.25)
                Q3 = df[col].quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR
                
                # Cap outliers instead of removing them
                df[col] = np.clip(df[col], lower_bound, upper_bound)
        
        elif self.config.outlier_detection_method == 'zscore':
            for col in num_cols:
                z_scores = np.abs((df[col] - df[col].mean()) / df[col].std())
                # Cap values beyond z-score threshold
                threshold = self.config.outlier_threshold
                outlier_mask = z_scores > threshold
                if outlier_mask.any():
                    median_val = df[col].median()
                    df.loc[outlier_mask, col] = median_val
        
        return df
    
    def _encode_categorical_features(self, df: pd.DataFrame, is_training: bool) -> pd.DataFrame:
        """Encode categorical features."""
        cat_cols = df.select_dtypes(include=['object']).columns
        cat_cols = [col for col in cat_cols if col not in ['event_id', 'timestamp']]
        
        for col in cat_cols:
            if is_training:
                if self.config.categorical_encoder == 'onehot':
                    encoder = OneHotEncoder(sparse=False, handle_unknown='ignore')
                    encoded = encoder.fit_transform(df[[col]])
                    encoded_df = pd.DataFrame(
                        encoded,
                        columns=[f'{col}_{cat}' for cat in encoder.categories_[0]]
                    )
                    df = pd.concat([df.drop(col, axis=1), encoded_df], axis=1)
                    self.categorical_encoders[col] = encoder
                    
                elif self.config.categorical_encoder == 'label':
                    encoder = LabelEncoder()
                    df[col] = encoder.fit_transform(df[col].astype(str))
                    self.categorical_encoders[col] = encoder
                    
                elif self.config.categorical_encoder == 'target':
                    # For target encoding, we need target variable
                    # For now, use label encoding as fallback
                    encoder = LabelEncoder()
                    df[col] = encoder.fit_transform(df[col].astype(str))
                    self.categorical_encoders[col] = encoder
            else:
                # Apply pre-fitted encoders
                if col in self.categorical_encoders:
                    encoder = self.categorical_encoders[col]
                    if isinstance(encoder, OneHotEncoder):
                        try:
                            encoded = encoder.transform(df[[col]])
                            encoded_df = pd.DataFrame(
                                encoded,
                                columns=[f'{col}_{cat}' for cat in encoder.categories_[0]]
                            )
                            df = pd.concat([df.drop(col, axis=1), encoded_df], axis=1)
                        except ValueError:
                            # Handle unknown categories
                            df[col] = 'unknown'
                            encoded = encoder.transform(df[[col]])
                            encoded_df = pd.DataFrame(
                                encoded,
                                columns=[f'{col}_{cat}' for cat in encoder.categories_[0]]
                            )
                            df = pd.concat([df.drop(col, axis=1), encoded_df], axis=1)
                    else:
                        try:
                            df[col] = encoder.transform(df[col].astype(str))
                        except ValueError:
                            # Handle unknown labels
                            df[col] = 0  # Default value for unknown categories
        
        return df
    
    def _scale_numerical_features(self, df: pd.DataFrame, is_training: bool) -> pd.DataFrame:
        """Scale numerical features."""
        num_cols = df.select_dtypes(include=[np.number]).columns
        num_cols = [col for col in num_cols if col not in ['event_id', 'target']]
        
        if len(num_cols) > 0:
            if is_training:
                df[num_cols] = self.numerical_scaler.fit_transform(df[num_cols])
            else:
                if hasattr(self.numerical_scaler, 'scale_'):
                    df[num_cols] = self.numerical_scaler.transform(df[num_cols])
        
        return df
    
    def _select_features(self, df: pd.DataFrame, is_training: bool) -> pd.DataFrame:
        """Select most important features."""
        if not is_training:
            return df
        
        # Assume we have a target column for feature selection
        # In practice, this would be derived from labeled data
        feature_cols = [col for col in df.columns 
                       if col not in ['event_id', 'timestamp', 'target']]
        
        if len(feature_cols) == 0:
            return df
        
        # Create synthetic target for demonstration (in practice, use real labels)
        if 'target' not in df.columns:
            # Create target based on event type and severity
            df['target'] = (
                (df.get('event_type', '') == 'privilege_escalation') |
                (df.get('severity', '') == 'high')
            ).astype(int)
        
        X = df[feature_cols]
        y = df['target']
        
        k_features = min(self.config.max_features or 1000, len(feature_cols))
        
        if self.config.feature_selection_method == 'f_classif':
            self.feature_selector = SelectKBest(score_func=f_classif, k=k_features)
        elif self.config.feature_selection_method == 'mutual_info':
            self.feature_selector = SelectKBest(score_func=mutual_info_classif, k=k_features)
        
        X_selected = self.feature_selector.fit_transform(X, y)
        selected_features = self.feature_selector.get_support()
        selected_cols = [col for col, selected in zip(feature_cols, selected_features) if selected]
        
        # Keep non-feature columns and selected features
        other_cols = [col for col in df.columns if col not in feature_cols]
        result_df = df[other_cols].copy()
        
        # Add selected features
        selected_df = pd.DataFrame(X_selected, columns=selected_cols, index=df.index)
        result_df = pd.concat([result_df, selected_df], axis=1)
        
        logger.info(f"Selected {len(selected_cols)} features out of {len(feature_cols)}")
        
        return result_df
    
    def get_preprocessing_stats(self) -> Dict[str, Any]:
        """Get preprocessing statistics."""
        quality_report = self.validator.get_quality_report()
        
        stats = {
            'is_fitted': self.fitted,
            'data_quality': quality_report,
            'config': self.config.__dict__,
            'preprocessing_metrics': self.metrics.get_metrics() if hasattr(self.metrics, 'get_metrics') else {}
        }
        
        return stats
    
    def save_preprocessor_state(self, filepath: str) -> None:
        """Save the preprocessor state for later use."""
        import pickle
        
        state = {
            'config': self.config,
            'numerical_scaler': self.numerical_scaler,
            'categorical_encoders': self.categorical_encoders,
            'feature_selector': self.feature_selector,
            'fitted': self.fitted
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
        
        logger.info(f"Preprocessor state saved to {filepath}")
    
    def load_preprocessor_state(self, filepath: str) -> None:
        """Load preprocessor state from file."""
        import pickle
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        self.config = state['config']
        self.numerical_scaler = state['numerical_scaler']
        self.categorical_encoders = state['categorical_encoders']
        self.feature_selector = state['feature_selector']
        self.fitted = state['fitted']
        
        logger.info(f"Preprocessor state loaded from {filepath}")