export interface BotDetectionResult {
    isBot: boolean;
    confidence: number; // 0-1
    indicators: string[];
    riskScore: number;
    recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
    analysis: {
      userAgent: boolean;
      timing: boolean;
      navigation: boolean;
      requestPattern: boolean;
      sessionBehavior: boolean;
    };
  }
  
  export interface BotDetectionConfig {
    id: string;
    tenantId: string;
    name: string;
    thresholds: {
      low: number;
      medium: number;
      high: number;
      critical: number;
    };
    enabled: boolean;
    customPatterns: string[];
    createdAt: Date;
    updatedAt: Date;
  }