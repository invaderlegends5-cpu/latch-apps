//src/device-fingerprinting/types/device.types.ts
export interface DeviceFingerprint {
    userAgent: string | null;
    ipAddress: string | null;
    deviceId?: string; // if available from client
    os?: string;
    browser?: string;
    deviceType?: 'mobile' | 'desktop' | 'tablet' | 'unknown';
    screenResolution?: string;
  timezone?: string;
  language?: string;
  canvasFingerprint?: string;
  webglFingerprint?: string;
  fonts?: string[];
  plugins?: string[];
  hardwareConcurrency?: number;
  deviceMemory?: number;
  }
  
  export interface DeviceSessionPattern {
    userId: string;
    fingerprint: DeviceFingerprint;
    sessionIds: string[];
    tokenFamilyIds: string[];
    firstSeen: Date;
    lastSeen: Date;
    active: boolean;
  }
  
  export interface DeviceReuseAlert {
    id: string;
    userId: string;
    primaryFingerprint: DeviceFingerprint;
    secondaryFingerprint: DeviceFingerprint;
    primarySessionId: string;
    secondarySessionId: string;
    timestamp: Date;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    reason: string;
  }

  export interface DeviceAnalysisResult {
    deviceId: string;
    isBot: boolean;
    confidence: number;
    riskScore: number;
    isSuspicious: boolean;
    indicators: string[];
    recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
    similarityScore: number;
    matchedDevices: string[];
    isNewDevice: boolean;
    analysis: {
      userAgent: boolean;
      deviceType: boolean;
      browser: boolean;
      os: boolean;
      timing: boolean;
      pattern: boolean;
    };
    firstSeen: Date;
    lastSeen: Date;
  }
  