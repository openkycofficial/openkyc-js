// Server-side client (Node.js, Deno, Bun) - uses API secret for HMAC auth
export { TrustClient, type TrustClientConfig } from './client';

// Browser-safe client - requires backend proxy, no API secret exposed
export { TrustBrowserClient, type TrustBrowserClientConfig } from './browser-client';

// Fingerprint and RASP detection (works in both browser and server)
export { DeviceFingerprint, type FingerprintResult } from './device/fingerprint';
export { RASPDetector, type RASPSignals } from './rasp/detector';
export * from './types';
