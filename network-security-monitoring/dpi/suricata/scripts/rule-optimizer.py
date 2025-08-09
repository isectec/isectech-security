#!/usr/bin/env python3
# iSECTECH Suricata Rule Optimizer
# ML-powered rule performance optimization and tuning

import re
import json
import yaml
import sqlite3
import logging
import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter
import heapq

from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/rule-optimizer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RulePerformanceMetrics:
    """Performance metrics for individual rules"""
    sid: int
    rule_text: str
    total_matches: int
    false_positives: int
    true_positives: int
    avg_cpu_time_ms: float
    avg_memory_usage_kb: int
    packets_processed: int
    bytes_processed: int
    first_seen: datetime
    last_triggered: datetime
    performance_score: float
    optimization_suggestions: List[str]
    classification: str
    priority: int
    rule_complexity: int
    
@dataclass
class OptimizationRecommendation:
    """Rule optimization recommendation"""
    sid: int
    current_rule: str
    optimized_rule: str
    optimization_type: str
    expected_improvement: float
    confidence: float
    reasoning: str
    performance_impact: Dict[str, float]

@dataclass
class RuleCluster:
    """Cluster of similar rules for optimization"""
    cluster_id: int
    rule_sids: List[int]
    cluster_center: np.ndarray
    common_patterns: List[str]
    optimization_potential: float
    suggested_actions: List[str]

class RuleComplexityAnalyzer:
    """Analyzes rule complexity and optimization potential"""
    
    def __init__(self):
        # Pattern weights for complexity scoring
        self.complexity_weights = {
            'content': 1,
            'pcre': 5,
            'byte_test': 3,
            'byte_jump': 3,
            'isdataat': 2,
            'dsize': 1,
            'flowbits': 2,
            'threshold': 3,
            'detection_filter': 3,
            'lua': 10,
            'distance': 0.5,
            'within': 0.5,
            'offset': 0.5,
            'depth': 0.5,
            'fast_pattern': -2,  # Reduces complexity
            'nocase': 0.5,
            'reference': 0,
            'metadata': 0,
            'sid': 0,
            'rev': 0,
            'msg': 0,
            'classtype': 0
        }
        
        # Performance impact patterns
        self.performance_patterns = {
            'inefficient_pcre': r'pcre:"[^"]*\.\*[^"]*\.\*[^"]*"',  # Multiple .* in PCRE
            'missing_fast_pattern': r'content:"[^"]{8,}[^;]*;(?![^;]*fast_pattern)',
            'unanchored_content': r'content:"[^"]+";(?![^;]*(?:distance|within|offset|depth))',
            'complex_byte_operations': r'byte_test:[^;]*;[^;]*byte_test',
            'excessive_flowbits': r'(?:flowbits:[^;]*;){3,}',
            'deep_packet_inspection': r'depth:[0-9]{4,}',
            'large_content_matches': r'content:"[^"]{100,}"'
        }
    
    def analyze_rule_complexity(self, rule_text: str) -> Tuple[int, List[str]]:
        """Analyze rule complexity and return score with optimization suggestions"""
        complexity_score = 0
        suggestions = []
        
        # Parse rule components
        rule_parts = self._parse_rule(rule_text)
        
        # Calculate base complexity
        for component, count in rule_parts.items():
            weight = self.complexity_weights.get(component, 1)
            complexity_score += weight * count
        
        # Check for performance anti-patterns
        for pattern_name, pattern_regex in self.performance_patterns.items():
            if re.search(pattern_regex, rule_text, re.IGNORECASE):
                complexity_score += 5
                suggestions.append(f"Optimize {pattern_name}")
        
        # Analyze content matches
        content_matches = re.findall(r'content:"([^"]+)"', rule_text)
        if content_matches:
            longest_content = max(content_matches, key=len)
            if len(longest_content) >= 8 and 'fast_pattern' not in rule_text:
                suggestions.append("Add fast_pattern to longest content match")
            
            # Check for multiple short content matches
            short_contents = [c for c in content_matches if len(c) < 4]
            if len(short_contents) > 2:
                complexity_score += len(short_contents) * 2
                suggestions.append("Consolidate or improve short content matches")
        
        # Check PCRE patterns
        pcre_patterns = re.findall(r'pcre:"([^"]+)"', rule_text)
        for pcre in pcre_patterns:
            if pcre.count('.*') > 1:
                suggestions.append("Optimize PCRE pattern to reduce backtracking")
            if not pcre.startswith('^') and not pcre.endswith('$'):
                suggestions.append("Consider anchoring PCRE pattern")
        
        return complexity_score, suggestions
    
    def _parse_rule(self, rule_text: str) -> Dict[str, int]:
        """Parse rule and count components"""
        components = defaultdict(int)
        
        # Split rule into header and options
        parts = rule_text.split('(', 1)
        if len(parts) != 2:
            return components
        
        options_part = parts[1].rstrip(')')
        
        # Parse options
        option_pattern = r'(\w+):[^;]*;'
        matches = re.findall(option_pattern, options_part)
        
        for option in matches:
            components[option.lower()] += 1
        
        return dict(components)

class MLRuleOptimizer:
    """Machine learning-based rule optimization"""
    
    def __init__(self, db_path: str = "/var/lib/nsm/rule_performance.db"):
        self.db_path = db_path
        self.complexity_analyzer = RuleComplexityAnalyzer()
        
        # ML models
        self.performance_predictor = None
        self.anomaly_detector = None
        self.rule_clusterer = None
        self.scaler = StandardScaler()
        
        self._load_or_initialize_models()
    
    def _load_or_initialize_models(self):
        """Load existing models or initialize new ones"""
        models_dir = Path("/var/lib/nsm/optimization_models")
        models_dir.mkdir(exist_ok=True)
        
        # Performance predictor
        perf_model_path = models_dir / "performance_predictor.pkl"
        if perf_model_path.exists():
            self.performance_predictor = joblib.load(perf_model_path)
        else:
            self.performance_predictor = RandomForestRegressor(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                random_state=42
            )
        
        # Anomaly detector for identifying outlier rules
        anomaly_model_path = models_dir / "rule_anomaly_detector.pkl"
        if anomaly_model_path.exists():
            self.anomaly_detector = joblib.load(anomaly_model_path)
        else:
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
        
        # Rule clusterer
        cluster_model_path = models_dir / "rule_clusterer.pkl"
        if cluster_model_path.exists():
            self.rule_clusterer = joblib.load(cluster_model_path)
        else:
            self.rule_clusterer = KMeans(
                n_clusters=10,
                random_state=42
            )
    
    def extract_rule_features(self, rule_metrics: RulePerformanceMetrics) -> np.ndarray:
        """Extract features from rule for ML analysis"""
        # Basic performance features
        features = [
            rule_metrics.total_matches,
            rule_metrics.false_positives,
            rule_metrics.true_positives,
            rule_metrics.avg_cpu_time_ms,
            rule_metrics.avg_memory_usage_kb,
            rule_metrics.packets_processed,
            rule_metrics.bytes_processed,
            rule_metrics.rule_complexity,
            rule_metrics.priority,
        ]
        
        # Temporal features
        if rule_metrics.last_triggered and rule_metrics.first_seen:
            time_active = (rule_metrics.last_triggered - rule_metrics.first_seen).total_seconds()
            features.extend([
                time_active,
                rule_metrics.total_matches / max(1, time_active / 86400),  # matches per day
            ])
        else:
            features.extend([0, 0])
        
        # Rule content features
        rule_text = rule_metrics.rule_text.lower()
        features.extend([
            len(re.findall(r'content:', rule_text)),
            len(re.findall(r'pcre:', rule_text)),
            len(re.findall(r'byte_test:', rule_text)),
            len(re.findall(r'flowbits:', rule_text)),
            1 if 'fast_pattern' in rule_text else 0,
            1 if rule_text.startswith('drop') else 0,
            1 if rule_text.startswith('alert') else 0,
            len(rule_text),  # Rule length
        ])
        
        # Classification features
        classification_features = [0] * 10  # One-hot encode top classifications
        classification_map = {
            'trojan-activity': 0,
            'attempted-dos': 1,
            'attempted-recon': 2,
            'policy-violation': 3,
            'protocol-command-decode': 4,
            'malware-cnc': 5,
            'exploit-kit': 6,
            'suspicious-filename-detect': 7,
            'rpc-portmap-decode': 8,
            'misc-activity': 9
        }
        
        if rule_metrics.classification in classification_map:
            classification_features[classification_map[rule_metrics.classification]] = 1
        
        features.extend(classification_features)
        
        return np.array(features)
    
    def train_models(self, rule_metrics_list: List[RulePerformanceMetrics]):
        """Train ML models with rule performance data"""
        if len(rule_metrics_list) < 50:
            logger.warning("Insufficient data for model training")
            return
        
        logger.info(f"Training models with {len(rule_metrics_list)} rule samples")
        
        # Extract features and targets
        features = []
        performance_targets = []
        
        for metrics in rule_metrics_list:
            feature_vector = self.extract_rule_features(metrics)
            features.append(feature_vector)
            performance_targets.append(metrics.performance_score)
        
        features_array = np.array(features)
        targets_array = np.array(performance_targets)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features_array)
        
        # Train performance predictor
        X_train, X_test, y_train, y_test = train_test_split(
            features_scaled, targets_array, test_size=0.2, random_state=42
        )
        
        self.performance_predictor.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.performance_predictor.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)
        
        logger.info(f"Performance predictor - MSE: {mse:.3f}, R²: {r2:.3f}")
        
        # Train anomaly detector
        self.anomaly_detector.fit(features_scaled)
        
        # Train rule clusterer
        self.rule_clusterer.fit(features_scaled)
        
        # Save models
        models_dir = Path("/var/lib/nsm/optimization_models")
        joblib.dump(self.performance_predictor, models_dir / "performance_predictor.pkl")
        joblib.dump(self.anomaly_detector, models_dir / "rule_anomaly_detector.pkl")
        joblib.dump(self.rule_clusterer, models_dir / "rule_clusterer.pkl")
        joblib.dump(self.scaler, models_dir / "feature_scaler.pkl")
        
        logger.info("Models trained and saved successfully")
    
    def predict_rule_performance(self, rule_metrics: RulePerformanceMetrics) -> float:
        """Predict rule performance score"""
        try:
            features = self.extract_rule_features(rule_metrics)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            predicted_score = self.performance_predictor.predict(features_scaled)[0]
            return max(0.0, min(100.0, predicted_score))
        except Exception as e:
            logger.error(f"Error predicting rule performance: {e}")
            return rule_metrics.performance_score
    
    def identify_rule_anomalies(self, rule_metrics_list: List[RulePerformanceMetrics]) -> List[int]:
        """Identify anomalous rules that need attention"""
        try:
            features = []
            sids = []
            
            for metrics in rule_metrics_list:
                features.append(self.extract_rule_features(metrics))
                sids.append(metrics.sid)
            
            features_array = np.array(features)
            features_scaled = self.scaler.transform(features_array)
            
            # Detect anomalies
            anomaly_scores = self.anomaly_detector.decision_function(features_scaled)
            is_anomaly = self.anomaly_detector.predict(features_scaled)
            
            anomalous_sids = [sids[i] for i in range(len(sids)) if is_anomaly[i] == -1]
            
            return anomalous_sids
            
        except Exception as e:
            logger.error(f"Error identifying rule anomalies: {e}")
            return []
    
    def cluster_similar_rules(self, rule_metrics_list: List[RulePerformanceMetrics]) -> List[RuleCluster]:
        """Cluster similar rules for batch optimization"""
        try:
            features = []
            metrics_map = {}
            
            for metrics in rule_metrics_list:
                feature_vector = self.extract_rule_features(metrics)
                features.append(feature_vector)
                metrics_map[len(features) - 1] = metrics
            
            features_array = np.array(features)
            features_scaled = self.scaler.transform(features_array)
            
            # Perform clustering
            cluster_labels = self.rule_clusterer.predict(features_scaled)
            cluster_centers = self.rule_clusterer.cluster_centers_
            
            # Group rules by cluster
            clusters_dict = defaultdict(list)
            for idx, cluster_id in enumerate(cluster_labels):
                clusters_dict[cluster_id].append(metrics_map[idx])
            
            # Create RuleCluster objects
            rule_clusters = []
            for cluster_id, rule_list in clusters_dict.items():
                if len(rule_list) < 2:  # Skip singleton clusters
                    continue
                
                # Analyze common patterns
                common_patterns = self._find_common_patterns([r.rule_text for r in rule_list])
                
                # Calculate optimization potential
                avg_performance = np.mean([r.performance_score for r in rule_list])
                optimization_potential = max(0, 80 - avg_performance)  # Potential to reach 80% performance
                
                # Generate suggestions
                suggestions = self._generate_cluster_suggestions(rule_list, common_patterns)
                
                cluster = RuleCluster(
                    cluster_id=cluster_id,
                    rule_sids=[r.sid for r in rule_list],
                    cluster_center=cluster_centers[cluster_id],
                    common_patterns=common_patterns,
                    optimization_potential=optimization_potential,
                    suggested_actions=suggestions
                )
                
                rule_clusters.append(cluster)
            
            return rule_clusters
            
        except Exception as e:
            logger.error(f"Error clustering rules: {e}")
            return []
    
    def _find_common_patterns(self, rule_texts: List[str]) -> List[str]:
        """Find common patterns across rule texts"""
        patterns = []
        
        # Check for common content patterns
        all_contents = []
        for rule in rule_texts:
            contents = re.findall(r'content:"([^"]+)"', rule)
            all_contents.extend(contents)
        
        content_counts = Counter(all_contents)
        common_contents = [content for content, count in content_counts.items() if count >= len(rule_texts) * 0.5]
        
        if common_contents:
            patterns.append(f"Common content: {', '.join(common_contents[:3])}")
        
        # Check for common protocols
        protocols = []
        for rule in rule_texts:
            match = re.search(r'(tcp|udp|icmp|ip)\s', rule)
            if match:
                protocols.append(match.group(1))
        
        protocol_counts = Counter(protocols)
        if protocol_counts:
            most_common_protocol = protocol_counts.most_common(1)[0][0]
            patterns.append(f"Primary protocol: {most_common_protocol}")
        
        # Check for common classifications
        classifications = []
        for rule in rule_texts:
            match = re.search(r'classtype:([^;]+)', rule)
            if match:
                classifications.append(match.group(1))
        
        class_counts = Counter(classifications)
        if class_counts:
            most_common_class = class_counts.most_common(1)[0][0]
            patterns.append(f"Common classification: {most_common_class}")
        
        return patterns
    
    def _generate_cluster_suggestions(self, rule_list: List[RulePerformanceMetrics], 
                                    common_patterns: List[str]) -> List[str]:
        """Generate optimization suggestions for a cluster of rules"""
        suggestions = []
        
        # Check average performance
        avg_performance = np.mean([r.performance_score for r in rule_list])
        if avg_performance < 60:
            suggestions.append("Cluster has low performance - review rule efficiency")
        
        # Check false positive rates
        avg_fp_rate = np.mean([r.false_positives / max(1, r.total_matches) for r in rule_list])
        if avg_fp_rate > 0.3:
            suggestions.append("High false positive rate - consider rule refinement")
        
        # Check complexity
        avg_complexity = np.mean([r.rule_complexity for r in rule_list])
        if avg_complexity > 15:
            suggestions.append("High complexity rules - consider simplification")
        
        # Check for missing optimizations
        rules_without_fast_pattern = sum(1 for r in rule_list if 'fast_pattern' not in r.rule_text)
        if rules_without_fast_pattern > len(rule_list) * 0.5:
            suggestions.append("Many rules missing fast_pattern optimization")
        
        return suggestions

class RuleOptimizationEngine:
    """Main rule optimization engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/rule-optimizer-config.yaml"):
        self.config = self._load_config(config_path)
        self.db_path = "/var/lib/nsm/rule_performance.db"
        self.ml_optimizer = MLRuleOptimizer(self.db_path)
        self.complexity_analyzer = RuleComplexityAnalyzer()
        
        # Rule modification tracking
        self.optimization_history = []
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load optimization configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default optimization configuration"""
        return {
            'optimization': {
                'performance_threshold': 60.0,
                'false_positive_threshold': 0.2,
                'complexity_threshold': 20,
                'min_matches_for_optimization': 10
            },
            'ml_settings': {
                'retrain_frequency': 86400,  # 24 hours
                'min_training_samples': 100,
                'model_confidence_threshold': 0.7
            },
            'rule_modification': {
                'backup_enabled': True,
                'test_before_deploy': True,
                'rollback_on_failure': True,
                'max_modifications_per_batch': 50
            }
        }
    
    def load_rule_performance_data(self) -> List[RulePerformanceMetrics]:
        """Load rule performance data from database"""
        metrics_list = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT rp.sid, rm.rule_text, rp.total_matches, rp.false_positives, 
                           (rp.total_matches - rp.false_positives) as true_positives,
                           rp.cpu_time_ms, rp.memory_usage_kb, rp.last_match, rp.performance_score,
                           rm.classification, rm.priority
                    FROM rule_performance rp
                    LEFT JOIN rule_metadata rm ON rp.sid = rm.sid
                    WHERE rp.total_matches > 0
                """)
                
                for row in cursor.fetchall():
                    # Calculate complexity
                    complexity, _ = self.complexity_analyzer.analyze_rule_complexity(row[1] or "")
                    
                    metrics = RulePerformanceMetrics(
                        sid=row[0],
                        rule_text=row[1] or "",
                        total_matches=row[2],
                        false_positives=row[3],
                        true_positives=row[4],
                        avg_cpu_time_ms=row[5],
                        avg_memory_usage_kb=row[6],
                        packets_processed=row[2],  # Approximate
                        bytes_processed=row[2] * 1500,  # Approximate
                        first_seen=datetime.now() - timedelta(days=30),  # Approximate
                        last_triggered=datetime.fromisoformat(row[7]) if row[7] else datetime.now(),
                        performance_score=row[8],
                        optimization_suggestions=[],
                        classification=row[9] or "unknown",
                        priority=row[10] or 3,
                        rule_complexity=complexity
                    )
                    
                    metrics_list.append(metrics)
                    
        except Exception as e:
            logger.error(f"Error loading rule performance data: {e}")
        
        return metrics_list
    
    def identify_optimization_candidates(self, metrics_list: List[RulePerformanceMetrics]) -> List[RulePerformanceMetrics]:
        """Identify rules that need optimization"""
        candidates = []
        
        config = self.config.get('optimization', {})
        performance_threshold = config.get('performance_threshold', 60.0)
        fp_threshold = config.get('false_positive_threshold', 0.2)
        complexity_threshold = config.get('complexity_threshold', 20)
        min_matches = config.get('min_matches_for_optimization', 10)
        
        for metrics in metrics_list:
            # Skip rules with insufficient data
            if metrics.total_matches < min_matches:
                continue
            
            needs_optimization = False
            reasons = []
            
            # Check performance score
            if metrics.performance_score < performance_threshold:
                needs_optimization = True
                reasons.append(f"Low performance score: {metrics.performance_score:.1f}")
            
            # Check false positive rate
            fp_rate = metrics.false_positives / max(1, metrics.total_matches)
            if fp_rate > fp_threshold:
                needs_optimization = True
                reasons.append(f"High false positive rate: {fp_rate:.2%}")
            
            # Check complexity
            if metrics.rule_complexity > complexity_threshold:
                needs_optimization = True
                reasons.append(f"High complexity: {metrics.rule_complexity}")
            
            # Check CPU usage
            if metrics.avg_cpu_time_ms > 1000:  # More than 1ms average
                needs_optimization = True
                reasons.append(f"High CPU usage: {metrics.avg_cpu_time_ms:.1f}ms")
            
            if needs_optimization:
                metrics.optimization_suggestions = reasons
                candidates.append(metrics)
        
        # Sort by optimization priority
        candidates.sort(key=lambda x: (
            -x.performance_score,  # Lower performance first
            -x.false_positives / max(1, x.total_matches),  # Higher FP rate first
            -x.rule_complexity  # Higher complexity first
        ))
        
        return candidates
    
    def generate_optimization_recommendations(self, candidate: RulePerformanceMetrics) -> List[OptimizationRecommendation]:
        """Generate specific optimization recommendations for a rule"""
        recommendations = []
        
        # Analyze rule complexity and get suggestions
        complexity, suggestions = self.complexity_analyzer.analyze_rule_complexity(candidate.rule_text)
        
        for suggestion in suggestions:
            if "fast_pattern" in suggestion.lower():
                optimized_rule = self._add_fast_pattern(candidate.rule_text)
                if optimized_rule != candidate.rule_text:
                    rec = OptimizationRecommendation(
                        sid=candidate.sid,
                        current_rule=candidate.rule_text,
                        optimized_rule=optimized_rule,
                        optimization_type="fast_pattern_addition",
                        expected_improvement=15.0,  # Estimated 15% improvement
                        confidence=0.9,
                        reasoning="Adding fast_pattern will improve pattern matching performance",
                        performance_impact={
                            'cpu_reduction': 10.0,
                            'memory_reduction': 5.0,
                            'false_positive_reduction': 0.0
                        }
                    )
                    recommendations.append(rec)
            
            elif "pcre" in suggestion.lower() and "optimize" in suggestion.lower():
                optimized_rule = self._optimize_pcre_patterns(candidate.rule_text)
                if optimized_rule != candidate.rule_text:
                    rec = OptimizationRecommendation(
                        sid=candidate.sid,
                        current_rule=candidate.rule_text,
                        optimized_rule=optimized_rule,
                        optimization_type="pcre_optimization",
                        expected_improvement=20.0,
                        confidence=0.8,
                        reasoning="Optimizing PCRE patterns to reduce backtracking",
                        performance_impact={
                            'cpu_reduction': 25.0,
                            'memory_reduction': 10.0,
                            'false_positive_reduction': 5.0
                        }
                    )
                    recommendations.append(rec)
            
            elif "content" in suggestion.lower() and "consolidate" in suggestion.lower():
                optimized_rule = self._consolidate_content_matches(candidate.rule_text)
                if optimized_rule != candidate.rule_text:
                    rec = OptimizationRecommendation(
                        sid=candidate.sid,
                        current_rule=candidate.rule_text,
                        optimized_rule=optimized_rule,
                        optimization_type="content_consolidation",
                        expected_improvement=12.0,
                        confidence=0.7,
                        reasoning="Consolidating content matches for better performance",
                        performance_impact={
                            'cpu_reduction': 8.0,
                            'memory_reduction': 3.0,
                            'false_positive_reduction': 0.0
                        }
                    )
                    recommendations.append(rec)
        
        # High false positive rate optimization
        fp_rate = candidate.false_positives / max(1, candidate.total_matches)
        if fp_rate > 0.3:
            # Suggest adding more specific conditions
            optimized_rule = self._add_specificity(candidate.rule_text)
            if optimized_rule != candidate.rule_text:
                rec = OptimizationRecommendation(
                    sid=candidate.sid,
                    current_rule=candidate.rule_text,
                    optimized_rule=optimized_rule,
                    optimization_type="false_positive_reduction",
                    expected_improvement=25.0,
                    confidence=0.6,
                    reasoning="Adding conditions to reduce false positives",
                    performance_impact={
                        'cpu_reduction': 0.0,
                        'memory_reduction': 0.0,
                        'false_positive_reduction': 40.0
                    }
                )
                recommendations.append(rec)
        
        return recommendations
    
    def _add_fast_pattern(self, rule_text: str) -> str:
        """Add fast_pattern to the most suitable content match"""
        if 'fast_pattern' in rule_text:
            return rule_text  # Already has fast_pattern
        
        # Find all content matches
        content_matches = re.findall(r'content:"([^"]+)"', rule_text)
        if not content_matches:
            return rule_text
        
        # Find the longest content match
        longest_content = max(content_matches, key=len)
        if len(longest_content) < 4:
            return rule_text  # Too short for fast_pattern
        
        # Add fast_pattern to the longest content
        pattern = f'content:"{longest_content}"'
        replacement = f'content:"{longest_content}"; fast_pattern'
        
        return rule_text.replace(pattern, replacement, 1)
    
    def _optimize_pcre_patterns(self, rule_text: str) -> str:
        """Optimize PCRE patterns to reduce complexity"""
        # Find PCRE patterns
        pcre_patterns = re.findall(r'pcre:"([^"]+)"', rule_text)
        
        optimized_rule = rule_text
        
        for pcre in pcre_patterns:
            optimized_pcre = pcre
            
            # Replace multiple .* with more specific patterns where possible
            if pcre.count('.*') > 1:
                # Simple optimization: limit .* to not be too greedy
                optimized_pcre = pcre.replace('.*', '.{1,100}')
            
            # Add anchors if missing and appropriate
            if not pcre.startswith('^') and not pcre.endswith('$'):
                # Only add anchors if the pattern seems to match specific content
                if len(pcre) > 10 and not any(x in pcre for x in ['.*', '.+', '\\d*', '\\w*']):
                    optimized_pcre = f'^{optimized_pcre}$'
            
            if optimized_pcre != pcre:
                optimized_rule = optimized_rule.replace(f'pcre:"{pcre}"', f'pcre:"{optimized_pcre}"')
        
        return optimized_rule
    
    def _consolidate_content_matches(self, rule_text: str) -> str:
        """Consolidate multiple short content matches where possible"""
        content_matches = re.findall(r'content:"([^"]+)"[^;]*;', rule_text)
        
        # Find consecutive short content matches that could be combined
        short_contents = [c for c in content_matches if len(c) < 8]
        
        if len(short_contents) < 2:
            return rule_text
        
        # Simple consolidation: combine two short adjacent contents if they're literal
        # This is a simplified implementation - real optimization would be more sophisticated
        optimized_rule = rule_text
        
        for i in range(len(short_contents) - 1):
            current = short_contents[i]
            next_content = short_contents[i + 1]
            
            # Check if they appear consecutively in the rule
            pattern1 = f'content:"{current}"[^;]*;'
            pattern2 = f'content:"{next_content}"[^;]*;'
            
            if pattern1 in optimized_rule and pattern2 in optimized_rule:
                # Find their positions
                pos1 = optimized_rule.find(pattern1)
                pos2 = optimized_rule.find(pattern2, pos1 + len(pattern1))
                
                # If they're close together (within 100 chars), try to combine
                if 0 < pos2 - pos1 - len(pattern1) < 100:
                    combined_content = current + next_content
                    combined_pattern = f'content:"{combined_content}";'
                    
                    # Replace both patterns with the combined one
                    before_first = optimized_rule[:pos1]
                    between = optimized_rule[pos1 + len(pattern1):pos2]
                    after_second = optimized_rule[pos2 + len(pattern2):]
                    
                    if not re.search(r'\bcontent:', between):  # No other content matches between
                        optimized_rule = before_first + combined_pattern + after_second
                        break
        
        return optimized_rule
    
    def _add_specificity(self, rule_text: str) -> str:
        """Add more specific conditions to reduce false positives"""
        # This is a simplified implementation
        # Real implementation would analyze actual false positive cases
        
        optimized_rule = rule_text
        
        # Add flow direction if missing
        if 'flow:' not in rule_text and 'tcp' in rule_text:
            # Insert flow condition before the first content match
            content_pos = rule_text.find('content:')
            if content_pos > 0:
                before_content = rule_text[:content_pos]
                after_content = rule_text[content_pos:]
                optimized_rule = before_content + 'flow:established,to_server; ' + after_content
        
        # Add dsize constraint for content matches if appropriate
        if 'dsize:' not in rule_text and 'content:' in rule_text:
            content_matches = re.findall(r'content:"([^"]+)"', rule_text)
            if content_matches:
                max_content_len = max(len(c) for c in content_matches)
                if max_content_len > 10:
                    # Add minimum size requirement
                    dsize_condition = f'dsize:>{max_content_len}; '
                    content_pos = rule_text.find('content:')
                    before_content = rule_text[:content_pos]
                    after_content = rule_text[content_pos:]
                    optimized_rule = before_content + dsize_condition + after_content
        
        return optimized_rule
    
    def validate_optimized_rule(self, original: str, optimized: str) -> Tuple[bool, str]:
        """Validate that the optimized rule is syntactically correct"""
        try:
            # Basic syntax validation
            if not optimized.strip():
                return False, "Empty rule"
            
            # Check that it starts with a valid action
            if not re.match(r'^(alert|drop|pass|reject)\s', optimized):
                return False, "Invalid rule action"
            
            # Check parentheses balance
            if optimized.count('(') != optimized.count(')'):
                return False, "Unbalanced parentheses"
            
            # Check that essential components are preserved
            if 'sid:' not in optimized:
                return False, "Missing SID"
            
            if 'msg:' not in optimized:
                return False, "Missing message"
            
            # Use Suricata to validate (if available)
            try:
                # Write rule to temp file and test with suricata -T
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as f:
                    f.write(optimized + '\n')
                    temp_file = f.name
                
                result = subprocess.run([
                    'suricata', '-T', '-S', temp_file
                ], capture_output=True, text=True, timeout=10)
                
                Path(temp_file).unlink()  # Clean up
                
                if result.returncode == 0:
                    return True, "Rule validation passed"
                else:
                    return False, f"Suricata validation failed: {result.stderr}"
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Suricata not available or timeout, rely on basic checks
                return True, "Basic validation passed (Suricata not available)"
            
        except Exception as e:
            return False, f"Validation error: {e}"
    
    async def run_optimization_cycle(self):
        """Run a complete optimization cycle"""
        logger.info("Starting rule optimization cycle")
        
        try:
            # Load performance data
            metrics_list = self.load_rule_performance_data()
            if not metrics_list:
                logger.warning("No performance data available for optimization")
                return
            
            logger.info(f"Loaded {len(metrics_list)} rules with performance data")
            
            # Retrain ML models if needed
            if len(metrics_list) >= self.config.get('ml_settings', {}).get('min_training_samples', 100):
                self.ml_optimizer.train_models(metrics_list)
            
            # Identify optimization candidates
            candidates = self.identify_optimization_candidates(metrics_list)
            logger.info(f"Identified {len(candidates)} optimization candidates")
            
            if not candidates:
                logger.info("No rules require optimization")
                return
            
            # Identify anomalous rules
            anomalous_sids = self.ml_optimizer.identify_rule_anomalies(metrics_list)
            logger.info(f"Identified {len(anomalous_sids)} anomalous rules")
            
            # Cluster similar rules
            clusters = self.ml_optimizer.cluster_similar_rules(metrics_list)
            logger.info(f"Created {len(clusters)} rule clusters for batch optimization")
            
            # Generate recommendations
            all_recommendations = []
            max_modifications = self.config.get('rule_modification', {}).get('max_modifications_per_batch', 50)
            
            for candidate in candidates[:max_modifications]:
                recommendations = self.generate_optimization_recommendations(candidate)
                all_recommendations.extend(recommendations)
            
            logger.info(f"Generated {len(all_recommendations)} optimization recommendations")
            
            # Validate and apply recommendations
            if self.config.get('rule_modification', {}).get('test_before_deploy', True):
                valid_recommendations = []
                for rec in all_recommendations:
                    is_valid, reason = self.validate_optimized_rule(rec.current_rule, rec.optimized_rule)
                    if is_valid:
                        valid_recommendations.append(rec)
                    else:
                        logger.warning(f"Invalid optimization for SID {rec.sid}: {reason}")
                
                logger.info(f"{len(valid_recommendations)} recommendations passed validation")
                
                # Apply valid recommendations
                await self._apply_recommendations(valid_recommendations)
            
        except Exception as e:
            logger.error(f"Error in optimization cycle: {e}")
    
    async def _apply_recommendations(self, recommendations: List[OptimizationRecommendation]):
        """Apply optimization recommendations to rules"""
        if not recommendations:
            return
        
        logger.info(f"Applying {len(recommendations)} rule optimizations")
        
        # Create backup if enabled
        if self.config.get('rule_modification', {}).get('backup_enabled', True):
            await self._backup_current_rules()
        
        # Apply modifications
        modifications_applied = 0
        
        for rec in recommendations:
            try:
                # Update rule in rule files
                success = await self._update_rule_in_files(rec.sid, rec.optimized_rule)
                
                if success:
                    modifications_applied += 1
                    self.optimization_history.append({
                        'timestamp': datetime.now(),
                        'sid': rec.sid,
                        'optimization_type': rec.optimization_type,
                        'expected_improvement': rec.expected_improvement,
                        'confidence': rec.confidence
                    })
                    
                    logger.info(f"Applied {rec.optimization_type} optimization to SID {rec.sid}")
                else:
                    logger.warning(f"Failed to apply optimization to SID {rec.sid}")
                    
            except Exception as e:
                logger.error(f"Error applying optimization to SID {rec.sid}: {e}")
        
        logger.info(f"Successfully applied {modifications_applied} optimizations")
        
        # Reload Suricata if modifications were applied
        if modifications_applied > 0:
            await self._reload_suricata()
    
    async def _backup_current_rules(self):
        """Create backup of current rule files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = Path(f"/var/lib/nsm/rule_backups/optimization_{timestamp}")
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        rules_dir = Path("/var/lib/suricata/rules")
        for rule_file in rules_dir.glob("*.rules"):
            shutil.copy2(rule_file, backup_dir)
        
        logger.info(f"Rules backed up to {backup_dir}")
    
    async def _update_rule_in_files(self, sid: int, new_rule: str) -> bool:
        """Update a specific rule in rule files"""
        rules_dir = Path("/var/lib/suricata/rules")
        
        for rule_file in rules_dir.glob("*.rules"):
            try:
                with open(rule_file, 'r') as f:
                    content = f.read()
                
                # Find and replace the rule with matching SID
                lines = content.split('\n')
                updated = False
                
                for i, line in enumerate(lines):
                    if f'sid:{sid};' in line or f'sid:{sid} ' in line:
                        lines[i] = new_rule
                        updated = True
                        break
                
                if updated:
                    with open(rule_file, 'w') as f:
                        f.write('\n'.join(lines))
                    return True
                    
            except Exception as e:
                logger.error(f"Error updating rule file {rule_file}: {e}")
        
        return False
    
    async def _reload_suricata(self):
        """Reload Suricata configuration"""
        try:
            subprocess.run(['pkill', '-USR2', 'suricata'], check=True)
            logger.info("Suricata reloaded successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload Suricata: {e}")

async def main():
    """Main function for rule optimizer"""
    optimizer = RuleOptimizationEngine()
    
    # Run optimization cycle
    await optimizer.run_optimization_cycle()

if __name__ == "__main__":
    asyncio.run(main())