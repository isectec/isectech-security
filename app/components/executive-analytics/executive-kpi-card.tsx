'use client';

import React, { useMemo, memo, useCallback } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  IconButton,
  LinearProgress,
  Tooltip,
  useTheme,
  alpha
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon,
  Info as InfoIcon,
  Launch as LaunchIcon
} from '@mui/icons-material';
import { motion } from 'framer-motion';

interface ExecutiveKPICardProps {
  title: string;
  value: string | number;
  format: 'number' | 'percentage' | 'currency' | 'time' | 'status';
  trend?: 'up' | 'down' | 'stable';
  trendValue?: number;
  icon?: React.ReactNode;
  color?: 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'info';
  subtitle?: string;
  target?: number;
  confidenceScore?: number;
  lastUpdated?: Date;
  suffix?: string;
  prefix?: string;
  clickable?: boolean;
  onClick?: () => void;
  loading?: boolean;
  size?: 'small' | 'medium' | 'large';
  showProgress?: boolean;
  progressValue?: number;
  executiveMode?: boolean;
}

const ExecutiveKPICard: React.FC<ExecutiveKPICardProps> = memo(({
  title,
  value,
  format,
  trend,
  trendValue,
  icon,
  color = 'primary',
  subtitle,
  target,
  confidenceScore,
  lastUpdated,
  suffix,
  prefix,
  clickable = false,
  onClick,
  loading = false,
  size = 'medium',
  showProgress = false,
  progressValue,
  executiveMode = true
}) => {
  // Memoized click handler to prevent unnecessary re-renders
  const handleClick = useCallback(() => {
    if (clickable && onClick) {
      onClick();
    }
  }, [clickable, onClick]);
  const theme = useTheme();

  // Format value based on type and executive preferences
  const formattedValue = useMemo(() => {
    if (loading) return '--';
    
    switch (format) {
      case 'percentage':
        return `${typeof value === 'number' ? Math.round(value) : value}%`;
      case 'currency':
        return new Intl.NumberFormat('en-US', {
          style: 'currency',
          currency: 'USD',
          notation: 'compact',
          maximumFractionDigits: 1
        }).format(Number(value));
      case 'time':
        if (suffix) return `${value}${suffix}`;
        return `${value}min`;
      case 'status':
        return String(value).toUpperCase();
      case 'number':
        if (typeof value === 'number' && value >= 1000) {
          return new Intl.NumberFormat('en-US', {
            notation: 'compact',
            maximumFractionDigits: 1
          }).format(value);
        }
        return String(value);
      default:
        return `${prefix || ''}${value}${suffix || ''}`;
    }
  }, [value, format, loading, suffix, prefix]);

  // Calculate progress percentage for targets
  const progressPercentage = useMemo(() => {
    if (progressValue !== undefined) return progressValue;
    if (!target || typeof value !== 'number') return undefined;
    
    if (format === 'time') {
      // For time metrics, lower is better (inverse progress)
      return Math.max(0, Math.min(100, ((target - value) / target) * 100));
    }
    
    return Math.max(0, Math.min(100, (value / target) * 100));
  }, [value, target, format, progressValue]);

  // Determine card colors based on performance and executive branding
  const cardColors = useMemo(() => {
    const baseColor = theme.palette[color];
    
    return {
      background: executiveMode 
        ? alpha(baseColor.main, 0.05)
        : theme.palette.background.paper,
      border: alpha(baseColor.main, 0.2),
      accent: baseColor.main,
      text: baseColor.main,
      contrastText: baseColor.contrastText
    };
  }, [theme, color, executiveMode]);

  // Trend icon and color
  const trendIcon = useMemo(() => {
    if (!trend) return null;
    
    const iconProps = { 
      fontSize: 'small' as const, 
      sx: { 
        color: trend === 'up' ? 'success.main' : trend === 'down' ? 'error.main' : 'text.secondary' 
      } 
    };
    
    switch (trend) {
      case 'up': return <TrendingUpIcon {...iconProps} />;
      case 'down': return <TrendingDownIcon {...iconProps} />;
      case 'stable': return <TrendingFlatIcon {...iconProps} />;
      default: return null;
    }
  }, [trend]);

  // Card size configurations
  const sizeConfig = useMemo(() => {
    switch (size) {
      case 'small':
        return {
          padding: 2,
          titleVariant: 'body2' as const,
          valueVariant: 'h6' as const,
          subtitleVariant: 'caption' as const,
          minHeight: 120
        };
      case 'large':
        return {
          padding: 4,
          titleVariant: 'h6' as const,
          valueVariant: 'h3' as const,
          subtitleVariant: 'body2' as const,
          minHeight: 200
        };
      default: // medium
        return {
          padding: 3,
          titleVariant: 'subtitle1' as const,
          valueVariant: 'h4' as const,
          subtitleVariant: 'body2' as const,
          minHeight: 150
        };
    }
  }, [size]);

  const cardContent = (
    <CardContent sx={{ 
      p: sizeConfig.padding,
      '&:last-child': { pb: sizeConfig.padding },
      minHeight: sizeConfig.minHeight,
      display: 'flex',
      flexDirection: 'column',
      position: 'relative'
    }}>
      {/* Header with title and trend */}
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'flex-start',
        mb: 1
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
          {icon && (
            <Box sx={{ 
              color: cardColors.accent,
              display: 'flex',
              alignItems: 'center'
            }}>
              {icon}
            </Box>
          )}
          <Typography 
            variant={sizeConfig.titleVariant}
            sx={{ 
              fontWeight: executiveMode ? 600 : 500,
              color: 'text.primary',
              lineHeight: 1.2
            }}
          >
            {title}
          </Typography>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          {trendIcon}
          {confidenceScore && (
            <Tooltip title={`Confidence: ${Math.round(confidenceScore * 100)}%`}>
              <IconButton size="small" sx={{ p: 0.5 }}>
                <InfoIcon fontSize="inherit" />
              </IconButton>
            </Tooltip>
          )}
          {clickable && (
            <Tooltip title="View details">
              <IconButton size="small" sx={{ p: 0.5 }}>
                <LaunchIcon fontSize="inherit" />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </Box>

      {/* Main Value Display */}
      <Box sx={{ 
        flex: 1, 
        display: 'flex', 
        flexDirection: 'column', 
        justifyContent: 'center',
        textAlign: executiveMode ? 'left' : 'center'
      }}>
        <Typography 
          variant={sizeConfig.valueVariant}
          sx={{ 
            fontWeight: 700,
            color: cardColors.text,
            lineHeight: 1,
            mb: 0.5,
            wordBreak: 'break-word'
          }}
        >
          {formattedValue}
        </Typography>
        
        {subtitle && (
          <Typography 
            variant={sizeConfig.subtitleVariant}
            color="text.secondary"
            sx={{ mb: 1 }}
          >
            {subtitle}
          </Typography>
        )}

        {/* Trend value display */}
        {trendValue && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
            <Chip
              size="small"
              label={`${trendValue > 0 ? '+' : ''}${trendValue.toFixed(1)}%`}
              color={trendValue > 0 ? 'success' : trendValue < 0 ? 'error' : 'default'}
              variant="outlined"
              sx={{ fontSize: '0.75rem', height: 20 }}
            />
            <Typography variant="caption" color="text.secondary">
              vs last period
            </Typography>
          </Box>
        )}
      </Box>

      {/* Progress bar for targets */}
      {(showProgress || (target && progressPercentage !== undefined)) && (
        <Box sx={{ mt: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress to target
            </Typography>
            {target && (
              <Typography variant="caption" color="text.secondary">
                Target: {format === 'percentage' ? `${target}%` : target}
              </Typography>
            )}
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercentage || 0}
            sx={{
              height: 6,
              borderRadius: 3,
              backgroundColor: alpha(cardColors.accent, 0.1),
              '& .MuiLinearProgress-bar': {
                borderRadius: 3,
                backgroundColor: cardColors.accent
              }
            }}
          />
        </Box>
      )}

      {/* Data freshness indicator */}
      {lastUpdated && executiveMode && (
        <Typography 
          variant="caption" 
          color="text.secondary"
          sx={{ mt: 1, fontSize: '0.7rem' }}
        >
          Updated: {lastUpdated.toLocaleTimeString()}
        </Typography>
      )}
    </CardContent>
  );

  const cardProps = {
    sx: {
      height: '100%',
      background: cardColors.background,
      border: `1px solid ${cardColors.border}`,
      boxShadow: executiveMode 
        ? `0 4px 12px ${alpha(cardColors.accent, 0.1)}` 
        : theme.shadows[1],
      transition: 'all 0.3s ease-in-out',
      cursor: clickable ? 'pointer' : 'default',
      '&:hover': clickable ? {
        transform: 'translateY(-2px)',
        boxShadow: `0 8px 24px ${alpha(cardColors.accent, 0.2)}`,
        borderColor: cardColors.accent
      } : {},
      position: 'relative' as const,
      overflow: 'hidden'
    },
    onClick: clickable ? handleClick : undefined
  };

  // Wrap in motion component for smooth animations
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      whileHover={clickable ? { scale: 1.02 } : {}}
      whileTap={clickable ? { scale: 0.98 } : {}}
    >
      <Card {...cardProps}>
        {/* Accent bar for executive branding */}
        {executiveMode && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 4,
              background: `linear-gradient(90deg, ${cardColors.accent}, ${alpha(cardColors.accent, 0.6)})`
            }}
          />
        )}
        
        {/* Loading overlay */}
        {loading && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              backgroundColor: alpha(theme.palette.background.paper, 0.8),
              zIndex: 1
            }}
          >
            <LinearProgress sx={{ width: '50%' }} />
          </Box>
        )}
        
        {cardContent}
      </Card>
    </motion.div>
  );
});

// Add display name for debugging
ExecutiveKPICard.displayName = 'ExecutiveKPICard';

export { ExecutiveKPICard };
export default ExecutiveKPICard;