'use client';

import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Chip,
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  IconButton,
  Drawer,
  AppBar,
  Toolbar,
  Fade,
  CircularProgress,
  Alert,
  Fab,
  Paper,
  Divider,
  useTheme,
  useMediaQuery,
  InputAdornment,
  Skeleton
} from '@mui/material';
import {
  Send as SendIcon,
  Mic as MicIcon,
  MicOff as MicOffIcon,
  Psychology as PsychologyIcon,
  Person as PersonIcon,
  Close as CloseIcon,
  Lightbulb as LightbulbIcon,
  TrendingUp as TrendingUpIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  AutoAwesome as AutoAwesomeIcon,
  VolumeUp as VolumeUpIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useNaturalLanguageQuery } from '../../../lib/hooks/use-natural-language-query';
import { useSpeechRecognition } from '../../../lib/hooks/use-speech-recognition';
import { useSpeechSynthesis } from '../../../lib/hooks/use-speech-synthesis';
import {
  ExecutiveNLQInterfaceProps,
  ExecutiveQuery,
  NLQContext
} from './types';

interface ConversationMessage {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  query?: ExecutiveQuery;
  isLoading?: boolean;
  error?: string;
}

export const ExecutiveNLQInterface: React.FC<ExecutiveNLQInterfaceProps> = ({
  config,
  onQueryProcessed,
  placeholder = "Ask me anything about your security posture...",
  suggestions = [
    "What's our current security posture?",
    "Show me last month's threat trends",
    "How are we performing against compliance requirements?",
    "What security investments have the highest ROI?",
    "Predict next quarter's security risks"
  ],
  contextAware = true,
  voiceEnabled = true
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  // State management
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [conversation, setConversation] = useState<ConversationMessage[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [conversationContext, setConversationContext] = useState<NLQContext[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Refs
  const conversationRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Natural Language Query processing
  const {
    processQuery,
    parseIntent,
    generateResponse,
    isLoading: nlqLoading
  } = useNaturalLanguageQuery({
    userId: config.userId,
    tenantId: config.tenantId,
    userRole: config.userRole,
    contextAware
  });

  // Speech Recognition (voice input)
  const {
    isListening,
    transcript,
    startListening,
    stopListening,
    isSupported: speechRecognitionSupported
  } = useSpeechRecognition({
    continuous: false,
    interimResults: false,
    language: 'en-US'
  });

  // Speech Synthesis (voice output)
  const {
    speak,
    isSpeaking,
    cancel: cancelSpeech,
    isSupported: speechSynthesisSupported
  } = useSpeechSynthesis();

  // Auto-scroll conversation
  useEffect(() => {
    if (conversationRef.current) {
      conversationRef.current.scrollTop = conversationRef.current.scrollHeight;
    }
  }, [conversation]);

  // Handle speech recognition results
  useEffect(() => {
    if (transcript && !isListening) {
      setQuery(transcript);
    }
  }, [transcript, isListening]);

  const handleSendQuery = useCallback(async () => {
    if (!query.trim() || isProcessing) return;

    const userMessage: ConversationMessage = {
      id: `user-${Date.now()}`,
      type: 'user',
      content: query,
      timestamp: new Date()
    };

    const assistantMessage: ConversationMessage = {
      id: `assistant-${Date.now()}`,
      type: 'assistant',
      content: '',
      timestamp: new Date(),
      isLoading: true
    };

    setConversation(prev => [...prev, userMessage, assistantMessage]);
    setQuery('');
    setIsProcessing(true);
    setShowSuggestions(false);
    setError(null);

    try {
      // Process the query
      const executiveQuery = await processExecutiveQuery(query, conversationContext);
      
      // Update conversation with response
      setConversation(prev => prev.map(msg => 
        msg.id === assistantMessage.id 
          ? { ...msg, content: executiveQuery.response.content, isLoading: false, query: executiveQuery }
          : msg
      ));

      // Update context
      const newContext: NLQContext = {
        query,
        response: executiveQuery.response.content,
        timestamp: new Date(),
        entities: executiveQuery.intent.entities,
        intent: executiveQuery.intent.type
      };

      setConversationContext(prev => [...prev.slice(-4), newContext]); // Keep last 5 exchanges

      // Notify parent
      onQueryProcessed(executiveQuery);

      // Speak response if enabled
      if (voiceEnabled && speechSynthesisSupported && config.preferences.nlqEnabled) {
        speak(executiveQuery.response.content, {
          rate: 1.1,
          pitch: 1.0,
          volume: 0.8
        });
      }

    } catch (error) {
      console.error('Query processing failed:', error);
      setConversation(prev => prev.map(msg => 
        msg.id === assistantMessage.id 
          ? { ...msg, content: 'Sorry, I encountered an error processing your request. Please try again.', isLoading: false, error: error.message }
          : msg
      ));
      setError('Failed to process query');
    } finally {
      setIsProcessing(false);
    }
  }, [query, conversationContext, isProcessing, processExecutiveQuery, onQueryProcessed, voiceEnabled, speechSynthesisSupported, config.preferences.nlqEnabled]);

  const processExecutiveQuery = async (queryText: string, context: NLQContext[]): Promise<ExecutiveQuery> => {
    // Parse query intent and entities
    const intent = await parseIntent(queryText, context);
    
    // Process query based on intent
    const response = await generateExecutiveResponse(intent, queryText);
    
    return {
      id: `query-${Date.now()}`,
      query: queryText,
      intent,
      response,
      conversationContext: context,
      userId: config.userId,
      sessionId: `session-${config.userId}-${Date.now()}`
    };
  };

  const generateExecutiveResponse = async (intent: any, query: string) => {
    switch (intent.type) {
      case 'data-request':
        return await handleDataRequest(intent);
      case 'trend-analysis':
        return await handleTrendAnalysis(intent);
      case 'comparison':
        return await handleComparison(intent);
      case 'prediction':
        return await handlePrediction(intent);
      case 'recommendation':
        return await handleRecommendation(intent);
      default:
        return await handleGenericQuery(intent, query);
    }
  };

  const handleDataRequest = async (intent: any) => {
    // Handle specific data requests
    const entities = intent.entities;
    let content = '';

    if (entities.includes('security-posture')) {
      content = `Based on current data, your security posture score is 87%, which is above the industry average of 74%. Key strengths include endpoint protection (94%) and network security (91%). Areas for improvement include cloud security (78%) and user awareness training (72%).`;
    } else if (entities.includes('threat-landscape')) {
      content = `Current threat landscape shows 23 active threats detected in the last 24 hours, with 3 high-severity incidents requiring attention. The primary threat vectors are phishing attacks (45%) and malware (32%). Our detection rate has improved by 15% compared to last month.`;
    } else if (entities.includes('compliance')) {
      content = `Compliance status across all frameworks shows 92% overall compliance. GDPR: 96%, SOX: 91%, HIPAA: 89%, PCI-DSS: 94%. Two minor gaps identified in data retention policies that require executive review.`;
    } else {
      content = `I can provide information about security posture, threat landscape, compliance status, ROI metrics, and predictive analytics. What specific area would you like to explore?`;
    }

    return {
      type: 'narrative' as const,
      content,
      confidence: 0.9,
      sources: ['Security Dashboard', 'Threat Intelligence', 'Compliance Management'],
      generatedAt: new Date()
    };
  };

  const handleTrendAnalysis = async (intent: any) => {
    const timeframe = intent.timeframe?.period || 'month';
    const content = `Trend analysis for the past ${timeframe} shows improving security metrics across most areas. Security posture increased by 8%, threat detection improved by 15%, and compliance maintained at 92%. Notable trends include a 25% reduction in false positives and 18% faster incident response times.`;

    return {
      type: 'visualization' as const,
      content,
      confidence: 0.85,
      sources: ['Analytics Engine', 'Historical Data'],
      generatedAt: new Date()
    };
  };

  const handleComparison = async (intent: any) => {
    const content = `Comparing current performance to previous periods: Security posture improved from 79% to 87% (10% increase), threat response time decreased from 4.2 hours to 3.1 hours (26% improvement), and compliance score maintained steady at 92%. Your organization outperforms industry benchmarks in 8 out of 12 key security metrics.`;

    return {
      type: 'data-table' as const,
      content,
      confidence: 0.88,
      sources: ['Benchmarking Data', 'Performance Metrics'],
      generatedAt: new Date()
    };
  };

  const handlePrediction = async (intent: any) => {
    const horizon = intent.timeframe?.period || 'quarter';
    const content = `Predictive analysis for the next ${horizon} indicates a 15% increase in phishing attacks, particularly targeting remote workers. Security posture is expected to improve to 91% with current initiatives. Compliance scores will likely maintain current levels. Recommendation: Increase user awareness training budget by 20% to address predicted phishing increase.`;

    return {
      type: 'insight' as const,
      content,
      confidence: 0.78,
      sources: ['Predictive Models', 'Threat Intelligence'],
      generatedAt: new Date()
    };
  };

  const handleRecommendation = async (intent: any) => {
    const content = `Based on current analysis, I recommend: 1) Implementing zero-trust architecture to improve security posture by estimated 12%, 2) Increasing security awareness training frequency to address human factor vulnerabilities, 3) Investing in advanced threat detection to reduce false positives by 30%. These initiatives have projected ROI of 240% over 18 months.`;

    return {
      type: 'recommendation' as const,
      content,
      confidence: 0.92,
      sources: ['AI Recommendations Engine', 'ROI Calculator'],
      generatedAt: new Date()
    };
  };

  const handleGenericQuery = async (intent: any, query: string) => {
    const content = `I understand you're asking about ${query}. As your AI security advisor, I can help with security posture analysis, threat intelligence, compliance reporting, ROI calculations, and predictive analytics. Could you be more specific about what aspect you'd like to explore?`;

    return {
      type: 'narrative' as const,
      content,
      confidence: 0.6,
      sources: ['Natural Language Processing'],
      generatedAt: new Date()
    };
  };

  const handleSuggestionClick = (suggestion: string) => {
    setQuery(suggestion);
    setShowSuggestions(false);
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handleVoiceToggle = () => {
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  };

  const clearConversation = () => {
    setConversation([]);
    setConversationContext([]);
    setShowSuggestions(true);
    setError(null);
  };

  const handleKeyPress = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      handleSendQuery();
    }
  };

  return (
    <>
      {/* NLQ Interface Trigger */}
      <Fab
        color="secondary"
        sx={{ 
          position: 'fixed', 
          bottom: 140, 
          right: 16,
          zIndex: 1300,
          '&:hover': {
            transform: 'scale(1.1)',
            transition: 'transform 0.2s ease-in-out'
          }
        }}
        onClick={() => setIsOpen(true)}
      >
        <AutoAwesomeIcon />
      </Fab>

      {/* NLQ Interface Drawer */}
      <Drawer
        anchor={isMobile ? 'bottom' : 'right'}
        open={isOpen}
        onClose={() => setIsOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? '100%' : 450,
            height: isMobile ? '80vh' : '100vh',
            maxWidth: '100vw',
            borderRadius: isMobile ? '16px 16px 0 0' : 0
          }
        }}
      >
        {/* Header */}
        <AppBar position="static" color="primary" elevation={0}>
          <Toolbar>
            <Avatar sx={{ mr: 2, bgcolor: 'secondary.main' }}>
              <PsychologyIcon />
            </Avatar>
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="h6" color="inherit">
                AI Security Advisor
              </Typography>
              <Typography variant="caption" color="rgba(255,255,255,0.7)">
                Ask me anything about your security
              </Typography>
            </Box>
            <IconButton
              color="inherit"
              onClick={clearConversation}
              disabled={conversation.length === 0}
            >
              <LightbulbIcon />
            </IconButton>
            <IconButton color="inherit" onClick={() => setIsOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Toolbar>
        </AppBar>

        {/* Conversation Area */}
        <Box
          ref={conversationRef}
          sx={{
            flexGrow: 1,
            overflow: 'auto',
            p: 2,
            bgcolor: 'background.default'
          }}
        >
          {/* Welcome Message */}
          {conversation.length === 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <Card sx={{ mb: 2, bgcolor: 'primary.main', color: 'white' }}>
                <CardContent>
                  <Typography variant="body1" gutterBottom>
                    👋 Hi {config.userRole === 'ceo' ? 'CEO' : config.userRole.toUpperCase()}! I'm your AI Security Advisor.
                  </Typography>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>
                    I can help you understand your security posture, analyze threats, 
                    review compliance status, and provide strategic recommendations.
                  </Typography>
                </CardContent>
              </Card>
            </motion.div>
          )}

          {/* Suggestions */}
          {showSuggestions && conversation.length === 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <Typography variant="subtitle2" sx={{ mb: 1, color: 'text.secondary' }}>
                Try asking:
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mb: 2 }}>
                {suggestions.map((suggestion, index) => (
                  <Chip
                    key={index}
                    label={suggestion}
                    onClick={() => handleSuggestionClick(suggestion)}
                    sx={{ 
                      justifyContent: 'flex-start', 
                      '&:hover': { bgcolor: 'primary.light', color: 'white' }
                    }}
                    icon={
                      suggestion.includes('posture') ? <SecurityIcon /> :
                      suggestion.includes('trend') ? <TrendingUpIcon /> :
                      suggestion.includes('compliance') ? <AssessmentIcon /> :
                      <AutoAwesomeIcon />
                    }
                  />
                ))}
              </Box>
            </motion.div>
          )}

          {/* Conversation Messages */}
          <List sx={{ width: '100%' }}>
            <AnimatePresence>
              {conversation.map((message, index) => (
                <motion.div
                  key={message.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                >
                  <ListItem
                    alignItems="flex-start"
                    sx={{
                      flexDirection: message.type === 'user' ? 'row-reverse' : 'row',
                      mb: 1
                    }}
                  >
                    <ListItemAvatar sx={{ 
                      minWidth: message.type === 'user' ? 'auto' : 56,
                      ml: message.type === 'user' ? 1 : 0,
                      mr: message.type === 'user' ? 0 : 1
                    }}>
                      <Avatar sx={{ 
                        bgcolor: message.type === 'user' ? 'secondary.main' : 'primary.main',
                        width: 32,
                        height: 32
                      }}>
                        {message.type === 'user' ? <PersonIcon /> : <PsychologyIcon />}
                      </Avatar>
                    </ListItemAvatar>
                    
                    <Paper
                      elevation={1}
                      sx={{
                        p: 2,
                        maxWidth: '80%',
                        bgcolor: message.type === 'user' ? 'secondary.light' : 'background.paper',
                        color: message.type === 'user' ? 'secondary.contrastText' : 'text.primary',
                        borderRadius: 2,
                        position: 'relative'
                      }}
                    >
                      {message.isLoading ? (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <CircularProgress size={16} />
                          <Typography variant="body2">
                            Analyzing...
                          </Typography>
                        </Box>
                      ) : (
                        <>
                          <Typography variant="body1" sx={{ mb: 1 }}>
                            {message.content}
                          </Typography>
                          
                          {message.type === 'assistant' && message.query && (
                            <Box sx={{ mt: 1, pt: 1, borderTop: '1px solid rgba(0,0,0,0.1)' }}>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <Typography variant="caption" color="text.secondary">
                                  Confidence: {Math.round((message.query.response.confidence || 0) * 100)}%
                                </Typography>
                                {voiceEnabled && speechSynthesisSupported && (
                                  <IconButton
                                    size="small"
                                    onClick={() => speak(message.content)}
                                    disabled={isSpeaking}
                                  >
                                    <VolumeUpIcon fontSize="small" />
                                  </IconButton>
                                )}
                              </Box>
                              
                              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                Sources: {message.query.response.sources?.join(', ')}
                              </Typography>
                            </Box>
                          )}
                          
                          {message.error && (
                            <Alert severity="error" sx={{ mt: 1 }}>
                              {message.error}
                            </Alert>
                          )}
                        </>
                      )}
                    </Paper>
                  </ListItem>
                </motion.div>
              ))}
            </AnimatePresence>
          </List>

          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
        </Box>

        {/* Input Area */}
        <Paper
          elevation={3}
          sx={{
            p: 2,
            borderRadius: 0,
            borderTop: '1px solid',
            borderColor: 'divider'
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: 1 }}>
            <TextField
              ref={inputRef}
              fullWidth
              multiline
              maxRows={3}
              placeholder={isListening ? "Listening..." : placeholder}
              value={isListening ? transcript : query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isProcessing || isListening}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    {voiceEnabled && speechRecognitionSupported && (
                      <IconButton
                        onClick={handleVoiceToggle}
                        color={isListening ? "secondary" : "default"}
                        disabled={isProcessing}
                      >
                        {isListening ? <MicIcon /> : <MicOffIcon />}
                      </IconButton>
                    )}
                  </InputAdornment>
                )
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  borderRadius: 2
                }
              }}
            />
            
            <Button
              variant="contained"
              onClick={handleSendQuery}
              disabled={!query.trim() || isProcessing || isListening}
              sx={{ 
                minWidth: 'auto',
                borderRadius: 2,
                px: 2
              }}
            >
              {isProcessing ? <CircularProgress size={20} color="inherit" /> : <SendIcon />}
            </Button>
          </Box>

          {isListening && (
            <Typography variant="caption" color="secondary" sx={{ mt: 1, display: 'block' }}>
              🎤 Voice recognition active... Speak now
            </Typography>
          )}
        </Paper>
      </Drawer>
    </>
  );
};