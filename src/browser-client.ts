/**
 * TrustBrowserClient - Browser-safe client for OpenKYC SDK
 *
 * IMPORTANT: This client does NOT handle HMAC authentication.
 * It requires a backend proxy that handles authentication with the OpenKYC API.
 *
 * Usage:
 *   const client = new TrustBrowserClient({
 *     proxyUrl: 'https://your-backend.com/api/openkyc-proxy'
 *   });
 *
 * Your backend proxy should:
 * 1. Receive requests from this client
 * 2. Add HMAC authentication headers using your API secret
 * 3. Forward requests to Trust Platform API
 * 4. Return responses to the browser
 */

import { DeviceFingerprint } from './device/fingerprint';
import { RASPDetector } from './rasp/detector';
import type { DeviceFingerprintData, DeviceProfileResponse, ApiError } from './types';

export interface TrustBrowserClientConfig {
  proxyUrl: string; // URL of your backend proxy endpoint
}

export class TrustBrowserClient {
  private proxyUrl: string;
  private fingerprint: DeviceFingerprint;
  private rasp: RASPDetector;

  constructor(config: TrustBrowserClientConfig) {
    if (!config.proxyUrl) {
      throw new Error('proxyUrl is required for TrustBrowserClient');
    }
    this.proxyUrl = config.proxyUrl.replace(/\/$/, ''); // Remove trailing slash
    this.fingerprint = new DeviceFingerprint();
    this.rasp = new RASPDetector();
  }

  /**
   * Generate a complete device fingerprint with RASP signals
   * This runs entirely in the browser - no network call
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
   * Submit device fingerprint to a session via your backend proxy
   * The proxy should forward to POST /v1/sessions/{sessionId}/device
   */
  async submitFingerprint(sessionId: string): Promise<DeviceProfileResponse> {
    const fingerprint = await this.getFingerprint();

    const response = await fetch(`${this.proxyUrl}/submit-fingerprint`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sessionId,
        fingerprint,
      }),
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({ message: 'Request failed' }));
      throw new Error(error.message || 'Failed to submit fingerprint');
    }

    return response.json();
  }

  /**
   * Get device trust assessment via your backend proxy
   * The proxy should forward to GET /v1/sessions/{sessionId}/device/trust
   */
  async getDeviceTrust(sessionId: string): Promise<{
    trustScore: number;
    riskLevel: string;
    riskSignals: string[];
  }> {
    const response = await fetch(`${this.proxyUrl}/device-trust?sessionId=${encodeURIComponent(sessionId)}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({ message: 'Request failed' }));
      throw new Error(error.message || 'Failed to get device trust');
    }

    return response.json();
  }
}

/**
 * Example backend proxy implementation (Node.js/Express):
 *
 * const { TrustClient } = require('@openkyc/sdk');
 *
 * // Server-side client with API secret
 * const trustClient = new TrustClient({
 *   apiKey: process.env.OPENKYC_API_KEY,
 *   apiSecret: process.env.OPENKYC_API_SECRET,
 * });
 *
 * app.post('/api/openkyc-proxy/submit-fingerprint', async (req, res) => {
 *   const { sessionId, fingerprint } = req.body;
 *
 *   // Validate sessionId belongs to authenticated user
 *   // ...
 *
 *   // Forward to OpenKYC API with HMAC auth
 *   const result = await trustClient.request('POST', `/v1/sessions/${sessionId}/device`, { fingerprint });
 *   res.json(result);
 * });
 */
