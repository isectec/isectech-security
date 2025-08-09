"""
Predictive Threat Intelligence Models for AI/ML Threat Detection

This module implements time-series models to forecast emerging threats and attack
trends based on historical and real-time data. It includes ARIMA, LSTM, Prophet
models, and ensemble forecasting approaches for predictive threat analytics.
"""

import asyncio
import logging
import json
import pickle
import joblib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum
from collections import defaultdict, deque
import warnings

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.ensemble import RandomForestRegressor
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import mlflow
import mlflow.sklearn
import mlflow.pytorch
from pydantic import BaseModel, Field

# Time series specific imports
try:
    from statsmodels.tsa.arima.model import ARIMA
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    from statsmodels.tsa.seasonal import seasonal_decompose
    from statsmodels.tsa.stattools import adfuller
    STATSMODELS_AVAILABLE = True
except ImportError:
    STATSMODELS_AVAILABLE = False
    logger.warning("Statsmodels not available. ARIMA and exponential smoothing models will be disabled.")

try:
    from fbprophet import Prophet
    PROPHET_AVAILABLE = True
except ImportError:
    try:
        from prophet import Prophet
        PROPHET_AVAILABLE = True
    except ImportError:
        PROPHET_AVAILABLE = False
        logger.warning("Prophet not available. Prophet forecasting models will be disabled.")

from .behavioral_analytics import BehaviorType, AnomalyType
from .supervised_threat_classification import ThreatCategory
from .zero_day_detection import NoveltyType
from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector
from ...shared.mlflow.integration import MLFlowManager

logger = logging.getLogger(__name__)
warnings.filterwarnings('ignore', category=UserWarning)


class ThreatForecastMethod(Enum):
    """Methods for threat forecasting."""
    ARIMA = "arima"
    LSTM = "lstm"
    PROPHET = "prophet"
    EXPONENTIAL_SMOOTHING = "exponential_smoothing"
    ENSEMBLE = "ensemble"
    RANDOM_FOREST = "random_forest"
    TRANSFORMER = "transformer"


class ThreatTrendType(Enum):
    """Types of threat trends to forecast."""
    ATTACK_VOLUME = "attack_volume"
    THREAT_DIVERSITY = "threat_diversity"
    GEOGRAPHIC_SPREAD = "geographic_spread"
    TARGET_SECTORS = "target_sectors"
    ATTACK_SOPHISTICATION = "attack_sophistication"
    ZERO_DAY_EMERGENCE = "zero_day_emergence"
    CAMPAIGN_DURATION = "campaign_duration"


@dataclass
class PredictiveThreatConfig:
    """Configuration for predictive threat intelligence models."""
    # General settings
    forecast_horizon_days: int = 30
    min_history_days: int = 90
    confidence_levels: List[float] = field(default_factory=lambda: [0.8, 0.9, 0.95])
    seasonality_detection: bool = True
    trend_detection: bool = True
    
    # ARIMA settings
    arima_max_p: int = 5
    arima_max_d: int = 2
    arima_max_q: int = 5
    arima_seasonal: bool = True
    arima_seasonal_periods: int = 7  # Weekly seasonality
    
    # LSTM settings
    lstm_sequence_length: int = 30
    lstm_hidden_size: int = 64
    lstm_num_layers: int = 2
    lstm_dropout: float = 0.2
    lstm_learning_rate: float = 0.001
    lstm_epochs: int = 100
    lstm_batch_size: int = 32
    
    # Prophet settings
    prophet_seasonality_mode: str = "additive"  # "additive" or "multiplicative"
    prophet_weekly_seasonality: bool = True
    prophet_daily_seasonality: bool = False
    prophet_yearly_seasonality: bool = False
    prophet_changepoint_prior_scale: float = 0.05
    
    # Ensemble settings
    ensemble_weights: Dict[str, float] = field(default_factory=dict)
    ensemble_method: str = "weighted_average"  # "weighted_average", "stacking", "voting"
    
    # Feature engineering
    enable_feature_engineering: bool = True
    lag_features: List[int] = field(default_factory=lambda: [1, 3, 7, 14, 30])
    rolling_windows: List[int] = field(default_factory=lambda: [3, 7, 14, 30])
    
    # Performance settings
    enable_gpu: bool = False
    parallel_forecasting: bool = True
    max_memory_gb: float = 4.0


class ThreatForecast(BaseModel):
    """Represents a threat intelligence forecast."""
    forecast_id: str
    method: ThreatForecastMethod
    trend_type: ThreatTrendType
    forecast_date: datetime
    forecast_horizon_days: int
    
    # Forecast values
    predicted_values: List[float] = Field(default_factory=list)
    confidence_intervals: Dict[str, List[Tuple[float, float]]] = Field(default_factory=dict)
    trend_direction: str = ""  # "increasing", "decreasing", "stable", "volatile"
    trend_strength: float = 0.0  # 0-1 scale
    
    # Model performance
    model_accuracy: float = 0.0
    validation_mae: float = 0.0
    validation_rmse: float = 0.0
    
    # Threat context
    threat_categories: List[str] = Field(default_factory=list)
    geographic_regions: List[str] = Field(default_factory=list)
    attack_vectors: List[str] = Field(default_factory=list)
    risk_assessment: str = ""  # "low", "medium", "high", "critical"
    
    # Actionable insights
    key_insights: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    alert_triggers: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            ThreatForecastMethod: lambda v: v.value,
            ThreatTrendType: lambda v: v.value
        }


class LSTMThreatForecaster(nn.Module):
    """LSTM neural network for threat forecasting."""
    
    def __init__(self, input_size: int, hidden_size: int, num_layers: int, 
                 output_size: int = 1, dropout: float = 0.2):
        super(LSTMThreatForecaster, self).__init__()
        
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            dropout=dropout if num_layers > 1 else 0,
            batch_first=True
        )
        
        self.dropout = nn.Dropout(dropout)
        self.linear = nn.Linear(hidden_size, output_size)
        
    def forward(self, x):
        batch_size = x.size(0)
        
        # Initialize hidden state
        h0 = torch.zeros(self.num_layers, batch_size, self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, batch_size, self.hidden_size).to(x.device)
        
        # LSTM forward pass
        lstm_out, _ = self.lstm(x, (h0, c0))
        
        # Take the last time step output
        last_output = lstm_out[:, -1, :]
        
        # Apply dropout and linear layer
        output = self.dropout(last_output)
        output = self.linear(output)
        
        return output


class TransformerThreatForecaster(nn.Module):
    """Transformer-based model for threat forecasting."""
    
    def __init__(self, input_size: int, d_model: int = 64, nhead: int = 8, 
                 num_layers: int = 3, dropout: float = 0.1):
        super(TransformerThreatForecaster, self).__init__()
        
        self.d_model = d_model
        self.input_projection = nn.Linear(input_size, d_model)
        
        # Positional encoding
        self.pos_encoding = nn.Parameter(torch.randn(1000, d_model))
        
        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dropout=dropout,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Output layers
        self.dropout = nn.Dropout(dropout)
        self.output_projection = nn.Linear(d_model, 1)
        
    def forward(self, x):
        seq_len = x.size(1)
        
        # Project input to model dimension
        x = self.input_projection(x)
        
        # Add positional encoding
        x = x + self.pos_encoding[:seq_len, :].unsqueeze(0)
        
        # Transformer forward pass
        transformer_out = self.transformer(x)
        
        # Take the last time step
        last_output = transformer_out[:, -1, :]
        
        # Apply dropout and output projection
        output = self.dropout(last_output)
        output = self.output_projection(output)
        
        return output


class BaseThreatForecaster(ABC):
    """Abstract base class for threat forecasting models."""
    
    def __init__(self, config: PredictiveThreatConfig, method: ThreatForecastMethod):
        self.config = config
        self.method = method
        self.model = None
        self.scaler = None
        self.is_fitted = False
        self.feature_names = []
        self.forecast_cache = {}
        
    @abstractmethod
    def fit(self, data: pd.DataFrame, target_column: str) -> None:
        """Fit the forecasting model."""
        pass
    
    @abstractmethod
    def forecast(self, steps: int) -> ThreatForecast:
        """Generate forecasts for specified number of steps."""
        pass
    
    def _prepare_time_series_features(self, data: pd.DataFrame, target_column: str) -> pd.DataFrame:
        """Prepare time-series features for modeling."""
        df = data.copy()
        
        if not self.config.enable_feature_engineering:
            return df
        
        # Create lag features
        for lag in self.config.lag_features:
            df[f'{target_column}_lag_{lag}'] = df[target_column].shift(lag)
        
        # Create rolling statistics
        for window in self.config.rolling_windows:
            df[f'{target_column}_rolling_mean_{window}'] = df[target_column].rolling(window=window).mean()
            df[f'{target_column}_rolling_std_{window}'] = df[target_column].rolling(window=window).std()
            df[f'{target_column}_rolling_min_{window}'] = df[target_column].rolling(window=window).min()
            df[f'{target_column}_rolling_max_{window}'] = df[target_column].rolling(window=window).max()
        
        # Create time-based features
        if 'timestamp' in df.columns or isinstance(df.index, pd.DatetimeIndex):
            date_col = df.index if isinstance(df.index, pd.DatetimeIndex) else df['timestamp']
            
            df['hour'] = date_col.hour
            df['day_of_week'] = date_col.dayofweek
            df['day_of_month'] = date_col.day
            df['month'] = date_col.month
            df['quarter'] = date_col.quarter
            df['is_weekend'] = (date_col.dayofweek >= 5).astype(int)
            df['is_business_hour'] = ((date_col.hour >= 9) & (date_col.hour <= 17)).astype(int)
        
        # Create difference features
        df[f'{target_column}_diff_1'] = df[target_column].diff(1)
        df[f'{target_column}_diff_7'] = df[target_column].diff(7)
        
        return df
    
    def _detect_seasonality(self, data: pd.Series) -> Dict[str, Any]:
        """Detect seasonality patterns in the data."""
        seasonality_info = {
            'has_seasonality': False,
            'dominant_period': None,
            'seasonal_strength': 0.0,
            'trend_strength': 0.0
        }
        
        if len(data) < 14:  # Need minimum data for seasonality detection
            return seasonality_info
        
        try:
            # Simple seasonal decomposition
            decomposition = seasonal_decompose(data.dropna(), model='additive', period=7)
            
            # Calculate seasonal strength
            seasonal_var = np.var(decomposition.seasonal.dropna())
            residual_var = np.var(decomposition.resid.dropna())
            
            if residual_var > 0:
                seasonal_strength = seasonal_var / (seasonal_var + residual_var)
                trend_strength = np.var(decomposition.trend.dropna()) / (np.var(data.dropna()) + 1e-10)
                
                seasonality_info.update({
                    'has_seasonality': seasonal_strength > 0.1,
                    'seasonal_strength': seasonal_strength,
                    'trend_strength': trend_strength,
                    'dominant_period': 7  # Weekly
                })
        
        except Exception as e:
            logger.warning(f"Seasonality detection failed: {e}")
        
        return seasonality_info
    
    def _calculate_forecast_accuracy(self, actual: np.ndarray, predicted: np.ndarray) -> Dict[str, float]:
        """Calculate forecast accuracy metrics."""
        metrics = {}
        
        try:
            metrics['mae'] = mean_absolute_error(actual, predicted)
            metrics['rmse'] = np.sqrt(mean_squared_error(actual, predicted))
            metrics['mape'] = np.mean(np.abs((actual - predicted) / (actual + 1e-10))) * 100
            
            # R-squared
            if len(actual) > 1:
                metrics['r2'] = r2_score(actual, predicted)
            
            # Directional accuracy (fraction of correct trend predictions)
            if len(actual) > 1:
                actual_diff = np.diff(actual)
                predicted_diff = np.diff(predicted)
                directional_accuracy = np.mean(np.sign(actual_diff) == np.sign(predicted_diff))
                metrics['directional_accuracy'] = directional_accuracy
            
        except Exception as e:
            logger.warning(f"Accuracy calculation failed: {e}")
            metrics = {'mae': float('inf'), 'rmse': float('inf'), 'mape': float('inf'), 'r2': 0.0}
        
        return metrics


class ARIMAThreatForecaster(BaseThreatForecaster):
    """ARIMA-based threat forecasting model."""
    
    def __init__(self, config: PredictiveThreatConfig):
        super().__init__(config, ThreatForecastMethod.ARIMA)
        self.best_params = None
        self.seasonal_info = None
        
    def fit(self, data: pd.DataFrame, target_column: str) -> None:
        """Fit ARIMA model with automatic parameter selection."""
        
        if not STATSMODELS_AVAILABLE:
            raise ImportError("Statsmodels is required for ARIMA forecasting")
        
        # Prepare data
        df = self._prepare_time_series_features(data, target_column)
        ts_data = df[target_column].dropna()
        
        if len(ts_data) < self.config.min_history_days:
            raise ValueError(f"Insufficient data: need at least {self.config.min_history_days} points")
        
        # Detect seasonality
        self.seasonal_info = self._detect_seasonality(ts_data)
        
        # Check for stationarity
        adf_result = adfuller(ts_data)
        is_stationary = adf_result[1] <= 0.05
        
        # Auto-select ARIMA parameters
        self.best_params = self._auto_arima(ts_data)
        
        # Fit final model
        try:
            if self.config.arima_seasonal and self.seasonal_info['has_seasonality']:
                self.model = ARIMA(
                    ts_data, 
                    order=self.best_params['order'],
                    seasonal_order=self.best_params['seasonal_order']
                ).fit()
            else:
                self.model = ARIMA(ts_data, order=self.best_params['order']).fit()
                
            self.is_fitted = True
            logger.info(f"ARIMA model fitted with parameters: {self.best_params}")
            
        except Exception as e:
            logger.error(f"ARIMA model fitting failed: {e}")
            raise
    
    def _auto_arima(self, data: pd.Series) -> Dict[str, Any]:
        """Automatic ARIMA parameter selection using AIC."""
        
        best_aic = float('inf')
        best_params = {'order': (1, 1, 1), 'seasonal_order': None}
        
        # Grid search for best parameters
        for p in range(self.config.arima_max_p + 1):
            for d in range(self.config.arima_max_d + 1):
                for q in range(self.config.arima_max_q + 1):
                    try:
                        # Non-seasonal ARIMA
                        model = ARIMA(data, order=(p, d, q)).fit()
                        aic = model.aic
                        
                        if aic < best_aic:
                            best_aic = aic
                            best_params['order'] = (p, d, q)
                            best_params['seasonal_order'] = None
                        
                        # Seasonal ARIMA if seasonality detected
                        if (self.config.arima_seasonal and 
                            self.seasonal_info and self.seasonal_info['has_seasonality']):
                            
                            seasonal_order = (1, 1, 1, self.config.arima_seasonal_periods)
                            model_seasonal = ARIMA(
                                data, 
                                order=(p, d, q),
                                seasonal_order=seasonal_order
                            ).fit()
                            
                            if model_seasonal.aic < best_aic:
                                best_aic = model_seasonal.aic
                                best_params['order'] = (p, d, q)
                                best_params['seasonal_order'] = seasonal_order
                        
                    except Exception:
                        continue
        
        best_params['aic'] = best_aic
        return best_params
    
    def forecast(self, steps: int) -> ThreatForecast:
        """Generate ARIMA forecasts."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before forecasting")
        
        # Generate forecasts
        forecast_result = self.model.forecast(steps=steps, alpha=0.05)  # 95% confidence
        predictions = forecast_result.tolist()
        
        # Get confidence intervals
        conf_int = self.model.get_forecast(steps=steps).conf_int()
        confidence_intervals = {
            "0.95": [(float(conf_int.iloc[i, 0]), float(conf_int.iloc[i, 1])) 
                    for i in range(steps)]
        }
        
        # Calculate trend metrics
        trend_direction = "stable"
        trend_strength = 0.0
        
        if len(predictions) > 1:
            trend_slope = np.polyfit(range(len(predictions)), predictions, 1)[0]
            if abs(trend_slope) > 0.1:
                trend_direction = "increasing" if trend_slope > 0 else "decreasing"
                trend_strength = min(abs(trend_slope), 1.0)
        
        # Create forecast object
        forecast = ThreatForecast(
            forecast_id=f"arima_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            method=self.method,
            trend_type=ThreatTrendType.ATTACK_VOLUME,  # Default, should be specified
            forecast_date=datetime.utcnow(),
            forecast_horizon_days=steps,
            predicted_values=predictions,
            confidence_intervals=confidence_intervals,
            trend_direction=trend_direction,
            trend_strength=trend_strength,
            model_accuracy=getattr(self.model, 'aic', 0.0)
        )
        
        return forecast


class LSTMThreatForecastModel(BaseThreatForecaster):
    """LSTM-based threat forecasting model."""
    
    def __init__(self, config: PredictiveThreatConfig):
        super().__init__(config, ThreatForecastMethod.LSTM)
        self.device = torch.device('cuda' if config.enable_gpu and torch.cuda.is_available() else 'cpu')
        self.sequence_length = config.lstm_sequence_length
        
    def fit(self, data: pd.DataFrame, target_column: str) -> None:
        """Fit LSTM model."""
        
        # Prepare features
        df = self._prepare_time_series_features(data, target_column)
        df = df.dropna()
        
        if len(df) < self.config.min_history_days:
            raise ValueError(f"Insufficient data: need at least {self.config.min_history_days} points")
        
        # Prepare sequences
        X, y = self._create_sequences(df, target_column)
        
        # Scale data
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
        
        # Split data
        train_size = int(len(X_scaled) * 0.8)
        X_train, X_val = X_scaled[:train_size], X_scaled[train_size:]
        y_train, y_val = y[:train_size], y[train_size:]
        
        # Create PyTorch datasets
        train_dataset = TensorDataset(
            torch.FloatTensor(X_train).to(self.device),
            torch.FloatTensor(y_train).to(self.device)
        )
        val_dataset = TensorDataset(
            torch.FloatTensor(X_val).to(self.device),
            torch.FloatTensor(y_val).to(self.device)
        )
        
        train_loader = DataLoader(train_dataset, batch_size=self.config.lstm_batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=self.config.lstm_batch_size)
        
        # Create model
        input_size = X.shape[-1]
        self.model = LSTMThreatForecaster(
            input_size=input_size,
            hidden_size=self.config.lstm_hidden_size,
            num_layers=self.config.lstm_num_layers,
            dropout=self.config.lstm_dropout
        ).to(self.device)
        
        # Training setup
        optimizer = optim.Adam(self.model.parameters(), lr=self.config.lstm_learning_rate)
        criterion = nn.MSELoss()
        
        # Training loop
        self.model.train()
        best_val_loss = float('inf')
        patience_counter = 0
        patience = 10
        
        for epoch in range(self.config.lstm_epochs):
            train_loss = 0.0
            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs.squeeze(), batch_y)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()
            
            # Validation
            self.model.eval()
            val_loss = 0.0
            with torch.no_grad():
                for batch_X, batch_y in val_loader:
                    outputs = self.model(batch_X)
                    val_loss += criterion(outputs.squeeze(), batch_y).item()
            
            val_loss /= len(val_loader)
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    logger.info(f"Early stopping at epoch {epoch}")
                    break
            
            self.model.train()
            
            if epoch % 20 == 0:
                logger.info(f"Epoch {epoch}: Train Loss = {train_loss/len(train_loader):.4f}, "
                           f"Val Loss = {val_loss:.4f}")
        
        self.is_fitted = True
        logger.info(f"LSTM model fitted with validation loss: {best_val_loss:.4f}")
    
    def _create_sequences(self, data: pd.DataFrame, target_column: str) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM training."""
        
        # Get feature columns (excluding target)
        feature_cols = [col for col in data.columns if col != target_column]
        
        sequences = []
        targets = []
        
        for i in range(self.sequence_length, len(data)):
            # Sequence features (including lagged target)
            seq_features = data[feature_cols].iloc[i-self.sequence_length:i].values
            sequences.append(seq_features)
            
            # Target value
            targets.append(data[target_column].iloc[i])
        
        return np.array(sequences), np.array(targets)
    
    def forecast(self, steps: int) -> ThreatForecast:
        """Generate LSTM forecasts."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before forecasting")
        
        self.model.eval()
        predictions = []
        
        # Use last sequence as initial input
        # This would need the last sequence from training data
        # For demonstration, creating dummy input
        dummy_input = torch.randn(1, self.sequence_length, self.scaler.n_features_in_).to(self.device)
        
        with torch.no_grad():
            current_seq = dummy_input
            
            for _ in range(steps):
                pred = self.model(current_seq)
                predictions.append(float(pred.cpu().numpy()[0, 0]))
                
                # Update sequence (simplified - would need proper feature updating)
                new_timestep = torch.cat([
                    pred.unsqueeze(1), 
                    torch.zeros(1, 1, self.scaler.n_features_in_ - 1).to(self.device)
                ], dim=2)
                
                current_seq = torch.cat([current_seq[:, 1:, :], new_timestep], dim=1)
        
        # Determine trend
        trend_direction = "stable"
        trend_strength = 0.0
        
        if len(predictions) > 1:
            trend_slope = np.polyfit(range(len(predictions)), predictions, 1)[0]
            if abs(trend_slope) > 0.1:
                trend_direction = "increasing" if trend_slope > 0 else "decreasing"
                trend_strength = min(abs(trend_slope), 1.0)
        
        # Create forecast
        forecast = ThreatForecast(
            forecast_id=f"lstm_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            method=self.method,
            trend_type=ThreatTrendType.ATTACK_VOLUME,
            forecast_date=datetime.utcnow(),
            forecast_horizon_days=steps,
            predicted_values=predictions,
            trend_direction=trend_direction,
            trend_strength=trend_strength
        )
        
        return forecast


class ProphetThreatForecaster(BaseThreatForecaster):
    """Prophet-based threat forecasting model."""
    
    def __init__(self, config: PredictiveThreatConfig):
        super().__init__(config, ThreatForecastMethod.PROPHET)
        
    def fit(self, data: pd.DataFrame, target_column: str) -> None:
        """Fit Prophet model."""
        
        if not PROPHET_AVAILABLE:
            raise ImportError("Prophet is required for Prophet forecasting")
        
        # Prepare data for Prophet (needs 'ds' and 'y' columns)
        prophet_data = data.copy()
        
        if 'timestamp' in prophet_data.columns:
            prophet_data = prophet_data.rename(columns={'timestamp': 'ds', target_column: 'y'})
        elif isinstance(prophet_data.index, pd.DatetimeIndex):
            prophet_data = prophet_data.reset_index()
            prophet_data = prophet_data.rename(columns={prophet_data.columns[0]: 'ds', target_column: 'y'})
        else:
            raise ValueError("Data must have a timestamp column or DatetimeIndex")
        
        # Remove rows with missing target values
        prophet_data = prophet_data.dropna(subset=['y'])
        
        if len(prophet_data) < self.config.min_history_days:
            raise ValueError(f"Insufficient data: need at least {self.config.min_history_days} points")
        
        # Initialize Prophet model
        self.model = Prophet(
            seasonality_mode=self.config.prophet_seasonality_mode,
            weekly_seasonality=self.config.prophet_weekly_seasonality,
            daily_seasonality=self.config.prophet_daily_seasonality,
            yearly_seasonality=self.config.prophet_yearly_seasonality,
            changepoint_prior_scale=self.config.prophet_changepoint_prior_scale
        )
        
        # Add custom seasonalities if needed
        if len(prophet_data) >= 14:  # Minimum for weekly seasonality
            self.model.add_seasonality(name='business_day', period=7, fourier_order=3)
        
        # Fit model
        try:
            self.model.fit(prophet_data[['ds', 'y']])
            self.is_fitted = True
            logger.info("Prophet model fitted successfully")
            
        except Exception as e:
            logger.error(f"Prophet model fitting failed: {e}")
            raise
    
    def forecast(self, steps: int) -> ThreatForecast:
        """Generate Prophet forecasts."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before forecasting")
        
        # Create future dataframe
        future = self.model.make_future_dataframe(periods=steps, freq='D')
        
        # Generate forecast
        forecast_result = self.model.predict(future)
        
        # Extract predictions (last 'steps' values)
        predictions = forecast_result['yhat'].tail(steps).tolist()
        
        # Extract confidence intervals
        confidence_intervals = {
            "0.95": [(float(forecast_result['yhat_lower'].iloc[-steps + i]), 
                     float(forecast_result['yhat_upper'].iloc[-steps + i]))
                    for i in range(steps)]
        }
        
        # Calculate trend
        trend_direction = "stable"
        trend_strength = 0.0
        
        if len(predictions) > 1:
            trend_slope = np.polyfit(range(len(predictions)), predictions, 1)[0]
            if abs(trend_slope) > 0.1:
                trend_direction = "increasing" if trend_slope > 0 else "decreasing"
                trend_strength = min(abs(trend_slope), 1.0)
        
        # Create forecast object
        forecast = ThreatForecast(
            forecast_id=f"prophet_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            method=self.method,
            trend_type=ThreatTrendType.ATTACK_VOLUME,
            forecast_date=datetime.utcnow(),
            forecast_horizon_days=steps,
            predicted_values=predictions,
            confidence_intervals=confidence_intervals,
            trend_direction=trend_direction,
            trend_strength=trend_strength
        )
        
        return forecast


class EnsembleThreatForecaster:
    """Ensemble forecasting combining multiple models."""
    
    def __init__(self, config: PredictiveThreatConfig, methods: List[ThreatForecastMethod]):
        self.config = config
        self.methods = methods
        self.forecasters: Dict[ThreatForecastMethod, BaseThreatForecaster] = {}
        self.is_fitted = False
        
        # Initialize individual forecasters
        for method in methods:
            if method == ThreatForecastMethod.ARIMA:
                self.forecasters[method] = ARIMAThreatForecaster(config)
            elif method == ThreatForecastMethod.LSTM:
                self.forecasters[method] = LSTMThreatForecastModel(config)
            elif method == ThreatForecastMethod.PROPHET:
                self.forecasters[method] = ProphetThreatForecaster(config)
    
    def fit(self, data: pd.DataFrame, target_column: str) -> None:
        """Fit all ensemble forecasters."""
        logger.info(f"Fitting ensemble with {len(self.forecasters)} forecasters")
        
        successful_forecasters = {}
        
        for method, forecaster in self.forecasters.items():
            try:
                logger.info(f"Training {method.value} forecaster...")
                forecaster.fit(data, target_column)
                successful_forecasters[method] = forecaster
            except Exception as e:
                logger.error(f"Failed to train {method.value} forecaster: {e}")
                continue
        
        self.forecasters = successful_forecasters
        self.is_fitted = True
        
        logger.info(f"Ensemble fitted with {len(self.forecasters)} successful forecasters")
    
    def forecast(self, steps: int) -> ThreatForecast:
        """Generate ensemble forecasts."""
        if not self.is_fitted:
            raise ValueError("Ensemble must be fitted before forecasting")
        
        # Collect individual forecasts
        individual_forecasts = {}
        
        for method, forecaster in self.forecasters.items():
            try:
                forecast = forecaster.forecast(steps)
                individual_forecasts[method] = forecast
            except Exception as e:
                logger.error(f"Failed to get forecast from {method.value}: {e}")
                continue
        
        if not individual_forecasts:
            raise ValueError("No successful forecasts from individual models")
        
        # Combine forecasts
        ensemble_predictions = self._combine_forecasts(individual_forecasts, steps)
        
        # Calculate ensemble trend
        trend_direction = "stable"
        trend_strength = 0.0
        
        if len(ensemble_predictions) > 1:
            trend_slope = np.polyfit(range(len(ensemble_predictions)), ensemble_predictions, 1)[0]
            if abs(trend_slope) > 0.1:
                trend_direction = "increasing" if trend_slope > 0 else "decreasing"
                trend_strength = min(abs(trend_slope), 1.0)
        
        # Create ensemble forecast
        ensemble_forecast = ThreatForecast(
            forecast_id=f"ensemble_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            method=ThreatForecastMethod.ENSEMBLE,
            trend_type=ThreatTrendType.ATTACK_VOLUME,
            forecast_date=datetime.utcnow(),
            forecast_horizon_days=steps,
            predicted_values=ensemble_predictions,
            trend_direction=trend_direction,
            trend_strength=trend_strength
        )
        
        return ensemble_forecast
    
    def _combine_forecasts(self, forecasts: Dict[ThreatForecastMethod, ThreatForecast], steps: int) -> List[float]:
        """Combine individual forecasts using ensemble method."""
        
        if self.config.ensemble_method == "weighted_average":
            # Use weights if specified, otherwise equal weighting
            weights = {}
            for method in forecasts.keys():
                weights[method] = self.config.ensemble_weights.get(method.value, 1.0 / len(forecasts))
            
            # Normalize weights
            total_weight = sum(weights.values())
            weights = {k: v / total_weight for k, v in weights.items()}
            
            # Weighted average
            ensemble_predictions = []
            for step in range(steps):
                weighted_sum = 0.0
                for method, forecast in forecasts.items():
                    if step < len(forecast.predicted_values):
                        weighted_sum += forecast.predicted_values[step] * weights[method]
                ensemble_predictions.append(weighted_sum)
            
            return ensemble_predictions
        
        elif self.config.ensemble_method == "median":
            # Median ensemble
            ensemble_predictions = []
            for step in range(steps):
                step_predictions = []
                for forecast in forecasts.values():
                    if step < len(forecast.predicted_values):
                        step_predictions.append(forecast.predicted_values[step])
                
                if step_predictions:
                    ensemble_predictions.append(np.median(step_predictions))
                else:
                    ensemble_predictions.append(0.0)
            
            return ensemble_predictions
        
        else:
            # Default: simple average
            ensemble_predictions = []
            for step in range(steps):
                step_predictions = []
                for forecast in forecasts.values():
                    if step < len(forecast.predicted_values):
                        step_predictions.append(forecast.predicted_values[step])
                
                if step_predictions:
                    ensemble_predictions.append(np.mean(step_predictions))
                else:
                    ensemble_predictions.append(0.0)
            
            return ensemble_predictions


class PredictiveThreatIntelligenceManager:
    """Main manager for predictive threat intelligence."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("predictive_threat_intelligence")
        self.mlflow_manager = MLFlowManager(settings)
        
        # Default configuration
        self.config = PredictiveThreatConfig()
        
        # Storage for trained models
        self.trained_models: Dict[str, Union[BaseThreatForecaster, EnsembleThreatForecaster]] = {}
        
        # Forecast cache
        self.forecast_cache: Dict[str, ThreatForecast] = {}
        
        # Threat intelligence data
        self.threat_timeseries: Dict[ThreatTrendType, pd.DataFrame] = {}
    
    async def build_threat_timeseries(
        self,
        events: List[SecurityEvent],
        trend_types: List[ThreatTrendType]
    ) -> Dict[ThreatTrendType, pd.DataFrame]:
        """Build time-series data from security events."""
        
        logger.info(f"Building time-series data for {len(trend_types)} trend types from {len(events)} events")
        
        # Convert events to DataFrame
        event_data = []
        for event in events:
            event_data.append({
                'timestamp': event.timestamp,
                'event_id': event.event_id,
                'event_type': event.event_type,
                'severity': event.severity,
                'source_ip': event.source_ip,
                'dest_ip': event.dest_ip,
                'port': event.port,
                'username': event.username,
                'hostname': event.hostname,
                'threat_category': getattr(event, 'threat_category', 'unknown')
            })
        
        df = pd.DataFrame(event_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        timeseries_data = {}
        
        for trend_type in trend_types:
            try:
                if trend_type == ThreatTrendType.ATTACK_VOLUME:
                    # Daily attack volume
                    daily_counts = df.groupby(df['timestamp'].dt.date).size()
                    ts_data = pd.DataFrame({
                        'timestamp': pd.to_datetime(daily_counts.index),
                        'value': daily_counts.values
                    })
                
                elif trend_type == ThreatTrendType.THREAT_DIVERSITY:
                    # Daily unique threat types
                    daily_diversity = df.groupby(df['timestamp'].dt.date)['event_type'].nunique()
                    ts_data = pd.DataFrame({
                        'timestamp': pd.to_datetime(daily_diversity.index),
                        'value': daily_diversity.values
                    })
                
                elif trend_type == ThreatTrendType.ATTACK_SOPHISTICATION:
                    # Sophistication based on severity scores
                    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                    df['severity_score'] = df['severity'].map(severity_map).fillna(0)
                    daily_sophistication = df.groupby(df['timestamp'].dt.date)['severity_score'].mean()
                    ts_data = pd.DataFrame({
                        'timestamp': pd.to_datetime(daily_sophistication.index),
                        'value': daily_sophistication.values
                    })
                
                elif trend_type == ThreatTrendType.GEOGRAPHIC_SPREAD:
                    # Daily unique source IP countries (simplified)
                    df['source_country'] = df['source_ip'].apply(self._ip_to_country)
                    daily_geo_spread = df.groupby(df['timestamp'].dt.date)['source_country'].nunique()
                    ts_data = pd.DataFrame({
                        'timestamp': pd.to_datetime(daily_geo_spread.index),
                        'value': daily_geo_spread.values
                    })
                
                else:
                    # Default: attack volume
                    daily_counts = df.groupby(df['timestamp'].dt.date).size()
                    ts_data = pd.DataFrame({
                        'timestamp': pd.to_datetime(daily_counts.index),
                        'value': daily_counts.values
                    })
                
                ts_data = ts_data.set_index('timestamp').sort_index()
                timeseries_data[trend_type] = ts_data
                
            except Exception as e:
                logger.error(f"Failed to build timeseries for {trend_type}: {e}")
                continue
        
        self.threat_timeseries = timeseries_data
        return timeseries_data
    
    def _ip_to_country(self, ip: str) -> str:
        """Simple IP to country mapping (would use GeoIP in production)."""
        if not ip:
            return "unknown"
        
        # Simple heuristic based on IP ranges
        octets = ip.split('.')
        if len(octets) != 4:
            return "unknown"
        
        try:
            first_octet = int(octets[0])
            if first_octet in [10, 172, 192]:  # Private IPs
                return "internal"
            elif first_octet < 50:
                return "us"
            elif first_octet < 100:
                return "eu"
            elif first_octet < 150:
                return "asia"
            else:
                return "other"
        except:
            return "unknown"
    
    async def train_forecasting_models(
        self,
        trend_type: ThreatTrendType,
        model_name: str = "default",
        methods: Optional[List[ThreatForecastMethod]] = None,
        config: Optional[PredictiveThreatConfig] = None
    ) -> Dict[str, Any]:
        """Train forecasting models for a specific trend type."""
        
        if config:
            self.config = config
        
        if methods is None:
            methods = [ThreatForecastMethod.ARIMA, ThreatForecastMethod.PROPHET]
            if STATSMODELS_AVAILABLE:
                methods.append(ThreatForecastMethod.ARIMA)
            if PROPHET_AVAILABLE:
                methods.append(ThreatForecastMethod.PROPHET)
        
        if trend_type not in self.threat_timeseries:
            raise ValueError(f"No timeseries data available for {trend_type}")
        
        data = self.threat_timeseries[trend_type]
        
        logger.info(f"Training forecasting models for {trend_type.value} with methods: {[m.value for m in methods]}")
        
        training_results = {}
        
        with mlflow.start_run(run_name=f"threat_forecasting_{model_name}_{trend_type.value}"):
            if len(methods) > 1:
                # Train ensemble
                ensemble = EnsembleThreatForecaster(self.config, methods)
                start_time = datetime.utcnow()
                
                ensemble.fit(data.reset_index(), 'value')
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                model_key = f"{model_name}_{trend_type.value}"
                self.trained_models[model_key] = ensemble
                
                # Log metrics
                mlflow.log_param("model_type", "ensemble")
                mlflow.log_param("methods", [m.value for m in methods])
                mlflow.log_param("trend_type", trend_type.value)
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("data_points", len(data))
                
                training_results = {
                    'model_name': model_key,
                    'model_type': 'ensemble',
                    'methods': [m.value for m in methods],
                    'trend_type': trend_type.value,
                    'training_time': training_time,
                    'data_points': len(data)
                }
                
            else:
                # Train single model
                method = methods[0]
                start_time = datetime.utcnow()
                
                if method == ThreatForecastMethod.ARIMA:
                    forecaster = ARIMAThreatForecaster(self.config)
                elif method == ThreatForecastMethod.PROPHET:
                    forecaster = ProphetThreatForecaster(self.config)
                elif method == ThreatForecastMethod.LSTM:
                    forecaster = LSTMThreatForecastModel(self.config)
                else:
                    raise ValueError(f"Unsupported forecasting method: {method}")
                
                forecaster.fit(data.reset_index(), 'value')
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                model_key = f"{model_name}_{trend_type.value}"
                self.trained_models[model_key] = forecaster
                
                # Log metrics
                mlflow.log_param("model_type", method.value)
                mlflow.log_param("trend_type", trend_type.value)
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("data_points", len(data))
                
                training_results = {
                    'model_name': model_key,
                    'model_type': method.value,
                    'trend_type': trend_type.value,
                    'training_time': training_time,
                    'data_points': len(data)
                }
        
        logger.info(f"Completed training forecasting models for {trend_type.value}")
        return training_results
    
    async def generate_threat_forecasts(
        self,
        trend_type: ThreatTrendType,
        forecast_horizon_days: int = 30,
        model_name: str = "default"
    ) -> ThreatForecast:
        """Generate threat forecasts for specified trend type."""
        
        model_key = f"{model_name}_{trend_type.value}"
        
        if model_key not in self.trained_models:
            raise ValueError(f"No trained model found for {model_key}")
        
        forecaster = self.trained_models[model_key]
        
        # Generate forecast
        forecast = forecaster.forecast(forecast_horizon_days)
        forecast.trend_type = trend_type
        
        # Add threat-specific insights and recommendations
        forecast = await self._enrich_forecast_with_intelligence(forecast, trend_type)
        
        # Cache forecast
        cache_key = f"{model_key}_{forecast_horizon_days}_{datetime.utcnow().strftime('%Y%m%d')}"
        self.forecast_cache[cache_key] = forecast
        
        # Log forecast metrics
        self.metrics.increment_counter(
            "forecasts_generated",
            tags={
                "trend_type": trend_type.value,
                "model": model_name,
                "horizon_days": str(forecast_horizon_days),
                "trend_direction": forecast.trend_direction
            }
        )
        
        logger.info(f"Generated forecast for {trend_type.value}: {forecast.trend_direction} trend")
        return forecast
    
    async def _enrich_forecast_with_intelligence(
        self,
        forecast: ThreatForecast,
        trend_type: ThreatTrendType
    ) -> ThreatForecast:
        """Enrich forecast with threat intelligence insights."""
        
        # Generate insights based on trend type and forecast characteristics
        insights = []
        recommendations = []
        alert_triggers = []
        
        if trend_type == ThreatTrendType.ATTACK_VOLUME:
            if forecast.trend_direction == "increasing":
                if forecast.trend_strength > 0.7:
                    insights.append("Significant increase in attack volume expected")
                    recommendations.append("Scale up security monitoring resources")
                    recommendations.append("Prepare incident response teams for higher workload")
                    alert_triggers.append("Attack volume exceeds baseline by >50%")
                
                avg_predicted = np.mean(forecast.predicted_values)
                if avg_predicted > 100:  # Threshold
                    insights.append(f"High attack volume forecasted (avg: {avg_predicted:.0f} attacks/day)")
                    recommendations.append("Consider implementing rate limiting")
            
            elif forecast.trend_direction == "decreasing":
                insights.append("Attack volume showing declining trend")
                recommendations.append("Monitor for potential attack pattern shifts")
        
        elif trend_type == ThreatTrendType.THREAT_DIVERSITY:
            if forecast.trend_direction == "increasing":
                insights.append("Increasing diversity in attack types expected")
                recommendations.append("Review and update threat detection signatures")
                recommendations.append("Enhance threat hunting capabilities")
                alert_triggers.append("New attack types detected")
        
        elif trend_type == ThreatTrendType.ATTACK_SOPHISTICATION:
            if forecast.trend_direction == "increasing":
                insights.append("Attack sophistication levels rising")
                recommendations.append("Strengthen advanced threat detection capabilities")
                recommendations.append("Consider threat intelligence subscriptions")
                alert_triggers.append("Advanced persistent threat indicators detected")
        
        # Risk assessment
        risk_level = "medium"
        if forecast.trend_direction == "increasing" and forecast.trend_strength > 0.6:
            risk_level = "high"
        elif forecast.trend_direction == "increasing" and forecast.trend_strength > 0.8:
            risk_level = "critical"
        elif forecast.trend_direction == "stable" or forecast.trend_direction == "decreasing":
            risk_level = "low"
        
        # Update forecast
        forecast.key_insights = insights
        forecast.recommendations = recommendations
        forecast.alert_triggers = alert_triggers
        forecast.risk_assessment = risk_level
        
        return forecast
    
    async def get_forecast_summary(self) -> Dict[str, Any]:
        """Get summary of all active forecasts."""
        
        summary = {
            'total_models': len(self.trained_models),
            'active_forecasts': len(self.forecast_cache),
            'trend_types': list(self.threat_timeseries.keys()),
            'forecast_performance': {},
            'risk_overview': defaultdict(int)
        }
        
        # Analyze cached forecasts
        for forecast in self.forecast_cache.values():
            summary['risk_overview'][forecast.risk_assessment] += 1
        
        return summary
    
    async def validate_forecasting_performance(
        self,
        trend_type: ThreatTrendType,
        model_name: str = "default",
        validation_days: int = 7
    ) -> Dict[str, Any]:
        """Validate forecasting model performance."""
        
        model_key = f"{model_name}_{trend_type.value}"
        
        if model_key not in self.trained_models:
            raise ValueError(f"No trained model found for {model_key}")
        
        if trend_type not in self.threat_timeseries:
            raise ValueError(f"No timeseries data for {trend_type}")
        
        # Get recent data for validation
        data = self.threat_timeseries[trend_type]
        if len(data) < validation_days * 2:
            raise ValueError(f"Insufficient data for validation: need at least {validation_days * 2} points")
        
        # Split data: use all but last validation_days for training, last validation_days for testing
        train_data = data.iloc[:-validation_days]
        test_data = data.iloc[-validation_days:]
        
        # Retrain model on training data
        forecaster = self.trained_models[model_key]
        temp_forecaster = type(forecaster)(self.config)
        temp_forecaster.fit(train_data.reset_index(), 'value')
        
        # Generate forecasts
        forecast = temp_forecaster.forecast(validation_days)
        
        # Calculate accuracy metrics
        actual_values = test_data['value'].values
        predicted_values = np.array(forecast.predicted_values[:len(actual_values)])
        
        accuracy_metrics = temp_forecaster._calculate_forecast_accuracy(actual_values, predicted_values)
        
        validation_results = {
            'model_name': model_key,
            'trend_type': trend_type.value,
            'validation_period': validation_days,
            'actual_values': actual_values.tolist(),
            'predicted_values': predicted_values.tolist(),
            **accuracy_metrics
        }
        
        # Log validation results
        with mlflow.start_run(run_name=f"forecast_validation_{model_key}"):
            mlflow.log_metrics(accuracy_metrics)
        
        return validation_results