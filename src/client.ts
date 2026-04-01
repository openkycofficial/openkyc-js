import { DeviceFingerprint } from './device/fingerprint';
import { RASPDetector } from './rasp/detector';
import type { DeviceFingerprintData, DeviceProfileResponse, SessionResponse, ApiError } from './types';

export interface TrustClientConfig {
  apiKey: string;
  apiSecret: string;
  baseUrl?: string;
  apiVersion?: '1' | '2'; // API version for signature scheme (default: '2')
}

export class TrustClient {
  private apiKey: string;
  private apiSecret: string;
  private baseUrl: string;
  private apiVersion: '1' | '2';
  private fingerprint: DeviceFingerprint;
  private rasp: RASPDetector;

  constructor(config: TrustClientConfig) {
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.baseUrl = config.baseUrl || 'https://api.openkyc.cloud';
    this.apiVersion = config.apiVersion || '2'; // Default to v2 (secure, includes body)
    this.fingerprint = new DeviceFingerprint();
    this.rasp = new RASPDetector();
  }

  /**
   * Generate a complete device fingerprint with RASP signals
   */
  async getFingerprint(): Promise<DeviceFingerprintData> {
    const [fpResult, raspSignals] = await Promise.all([
      this.fingerprint.collect(),
      this.rasp.detect(),
    ]);

    return {
      fingerprintHash: fpResult.hash,
      platform: 'web',
      osName: fpResult.os.name,
      osVersion: fpResult.os.version,
      browserName: fpResult.browser.name,
      browserVersion: fpResult.browser.version,
      userAgent: navigator.userAgent,
      screenWidth: fpResult.screen.width,
      screenHeight: fpResult.screen.height,
      colorDepth: fpResult.screen.colorDepth,
      timezone: fpResult.timezone,
      language: fpResult.language,
      languages: fpResult.languages,
      hardwareConcurrency: fpResult.hardware.concurrency,
      deviceMemory: fpResult.hardware.memory,
      maxTouchPoints: fpResult.hardware.touchPoints,
      canvasHash: fpResult.canvas,
      webglHash: fpResult.webgl,
      audioHash: fpResult.audio,
      raspSignals: {
        isEmulator: raspSignals.isEmulator,
        isRooted: false, // Not applicable for web
        isDebugMode: raspSignals.isDebugMode,
        isVirtualMachine: raspSignals.isVirtualMachine,
        isHooked: false, // Not applicable for web
        isTampered: false, // Not applicable for web
        isScreenRecording: false, // Limited detection on web
        isDevToolsOpen: raspSignals.isDevToolsOpen,
        isAutomated: raspSignals.isAutomated,
        isHeadless: raspSignals.isHeadless,
        hasConsoleTampering: raspSignals.hasConsoleTampering,
      },
    };
  }

  /**
   * Submit device fingerprint to a session
   */
  async submitFingerprint(sessionId: string): Promise<DeviceProfileResponse> {
    const fingerprint = await this.getFingerprint();

    const response = await this.request<DeviceProfileResponse>(
      'POST',
      `/v1/sessions/${sessionId}/device`,
      { fingerprint }
    );

    return response;
  }

  /**
   * Create a new verification session
   */
  async createSession(externalUserId?: string, metadata?: Record<string, unknown>): Promise<SessionResponse> {
    return this.request<SessionResponse>('POST', '/v1/sessions', {
      external_user_id: externalUserId,
      metadata,
    });
  }

  /**
   * Get session status
   */
  async getSession(sessionId: string): Promise<SessionResponse> {
    return this.request<SessionResponse>('GET', `/v1/sessions/${sessionId}`);
  }

  /**
   * Make an authenticated API request
   */
  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyString = body ? JSON.stringify(body) : '';
    const signature = await this.computeSignature(timestamp, method, path, bodyString);

    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'X-API-Key': this.apiKey,
      'X-Signature': signature,
      'X-Timestamp': timestamp,
      'X-API-Version': this.apiVersion,
    };

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: bodyString || undefined,
    });

    if (!response.ok) {
      const error: ApiError = await response.json();
      throw new Error(error.message || 'API request failed');
    }

    return response.json();
  }

  /**
   * Compute HMAC signature for request authentication
   * V1: message = apiKey + timestamp + method + path
   * V2: message = apiKey + timestamp + method + path + body (secure, prevents body tampering)
   */
  private async computeSignature(timestamp: string, method: string, path: string, body: string = ''): Promise<string> {
    // V2 includes body in signature to prevent tampering
    const message = this.apiVersion === '2'
      ? this.apiKey + timestamp + method + path + body
      : this.apiKey + timestamp + method + path;

    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.apiSecret);
    const messageData = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}
