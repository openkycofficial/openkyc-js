# @openkyc/sdk

JavaScript/TypeScript SDK for [OpenKYC](https://openkyc.cloud) — device fingerprinting, RASP detection, and identity verification.

## Install

```bash
npm install @openkyc/sdk
```

## Quick Start

### Server-side (Node.js)

```typescript
import { TrustClient } from '@openkyc/sdk';

const client = new TrustClient({
  apiKey: process.env.OPENKYC_API_KEY!,
  apiSecret: process.env.OPENKYC_API_SECRET!,
});

// Create a verification session
const session = await client.createSession('user_123');

// Get session status
const status = await client.getSession(session.sessionId);
```

### Browser (with backend proxy)

```typescript
import { TrustBrowserClient } from '@openkyc/sdk';

const client = new TrustBrowserClient({
  proxyUrl: 'https://your-backend.com/api/openkyc-proxy',
});

// Collect device fingerprint + RASP signals (runs locally, no network call)
const fingerprint = await client.getFingerprint();

// Submit to a verification session via your proxy
const result = await client.submitFingerprint(sessionId);
```

### Fingerprint & RASP Only

```typescript
import { DeviceFingerprint, RASPDetector } from '@openkyc/sdk';

const fp = new DeviceFingerprint();
const rasp = new RASPDetector();

const fingerprint = await fp.collect();
// { hash, os, browser, screen, canvas, webgl, audio, ... }

const signals = await rasp.detect();
// { isAutomated, isHeadless, isDevToolsOpen, isVirtualMachine, ... }
```

## What it detects

### Device Fingerprinting
- Canvas, WebGL, and audio fingerprints
- OS, browser, screen, timezone, language
- Hardware: CPU cores, memory, touch points

### RASP Signals
- Automation tools (Selenium, Puppeteer, Playwright)
- Headless browsers
- DevTools open
- Virtual machines (VMware, VirtualBox, QEMU, etc.)
- Console tampering

## Documentation

Full API docs at [openkyc.cloud/docs](https://openkyc.cloud/docs)

## License

MIT
