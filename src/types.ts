export interface DeviceFingerprintData {
  fingerprintHash: string;
  platform: 'web';
  osName: string;
  osVersion: string;
  browserName?: string;
  browserVersion?: string;
  userAgent?: string;
  screenWidth?: number;
  screenHeight?: number;
  colorDepth?: number;
  timezone?: string;
  language?: string;
  languages?: string[];
  hardwareConcurrency?: number;
  deviceMemory?: number;
  maxTouchPoints?: number;
  canvasHash?: string;
  webglHash?: string;
  audioHash?: string;
  raspSignals?: RASPSignalsData;
}

export interface RASPSignalsData {
  isEmulator: boolean;
  isRooted: boolean;
  isDebugMode: boolean;
  isVirtualMachine: boolean;
  isHooked: boolean;
  isTampered: boolean;
  isScreenRecording: boolean;
  isDevToolsOpen: boolean;
  isAutomated: boolean;
  isHeadless: boolean;
  hasConsoleTampering: boolean;
}

export interface SessionResponse {
  sessionId: string;
  status: string;
  expiresAt: string;
}

export interface DeviceProfileResponse {
  deviceId: string;
  deviceHash: string;
  trustLevel: 'unknown' | 'low' | 'medium' | 'high';
  trustScore: number;
  isNewDevice: boolean;
  isBlocked: boolean;
  sessionCount: number;
  riskSignals: RiskSignal[];
}

export interface RiskSignal {
  code: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export interface ApiError {
  error: string;
  message: string;
}
