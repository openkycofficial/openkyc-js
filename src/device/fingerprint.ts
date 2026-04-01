export interface FingerprintResult {
  hash: string;
  os: {
    name: string;
    version: string;
  };
  browser: {
    name: string;
    version: string;
  };
  screen: {
    width: number;
    height: number;
    colorDepth: number;
  };
  timezone: string;
  language: string;
  languages: string[];
  hardware: {
    concurrency: number;
    memory?: number;
    touchPoints: number;
  };
  canvas?: string;
  webgl?: string;
  audio?: string;
}

export class DeviceFingerprint {
  /**
   * Collect all fingerprint signals
   */
  async collect(): Promise<FingerprintResult> {
    const [canvas, webgl, audio] = await Promise.all([
      this.getCanvasFingerprint(),
      this.getWebGLFingerprint(),
      this.getAudioFingerprint(),
    ]);

    const os = this.getOS();
    const browser = this.getBrowser();

    const components = {
      os,
      browser,
      screen: this.getScreen(),
      timezone: this.getTimezone(),
      language: navigator.language,
      languages: Array.from(navigator.languages || [navigator.language]),
      hardware: this.getHardware(),
      canvas,
      webgl,
      audio,
    };

    // Generate hash from all components
    const hash = await this.hashComponents(components);

    return {
      hash,
      ...components,
    };
  }

  /**
   * Get OS information from user agent
   */
  private getOS(): { name: string; version: string } {
    const ua = navigator.userAgent;
    let name = 'Unknown';
    let version = '';

    if (ua.includes('Windows NT 10')) {
      name = 'Windows';
      version = '10';
    } else if (ua.includes('Windows NT 6.3')) {
      name = 'Windows';
      version = '8.1';
    } else if (ua.includes('Mac OS X')) {
      name = 'macOS';
      const match = ua.match(/Mac OS X (\d+[._]\d+)/);
      version = match ? match[1].replace('_', '.') : '';
    } else if (ua.includes('Linux')) {
      name = 'Linux';
    } else if (ua.includes('Android')) {
      name = 'Android';
      const match = ua.match(/Android (\d+(\.\d+)?)/);
      version = match ? match[1] : '';
    } else if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) {
      name = 'iOS';
      const match = ua.match(/OS (\d+[._]\d+)/);
      version = match ? match[1].replace('_', '.') : '';
    }

    return { name, version };
  }

  /**
   * Get browser information from user agent
   */
  private getBrowser(): { name: string; version: string } {
    const ua = navigator.userAgent;
    let name = 'Unknown';
    let version = '';

    if (ua.includes('Firefox/')) {
      name = 'Firefox';
      const match = ua.match(/Firefox\/(\d+(\.\d+)?)/);
      version = match ? match[1] : '';
    } else if (ua.includes('Edg/')) {
      name = 'Edge';
      const match = ua.match(/Edg\/(\d+(\.\d+)?)/);
      version = match ? match[1] : '';
    } else if (ua.includes('Chrome/')) {
      name = 'Chrome';
      const match = ua.match(/Chrome\/(\d+(\.\d+)?)/);
      version = match ? match[1] : '';
    } else if (ua.includes('Safari/') && !ua.includes('Chrome')) {
      name = 'Safari';
      const match = ua.match(/Version\/(\d+(\.\d+)?)/);
      version = match ? match[1] : '';
    }

    return { name, version };
  }

  /**
   * Get screen information
   */
  private getScreen(): { width: number; height: number; colorDepth: number } {
    return {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth,
    };
  }

  /**
   * Get timezone
   */
  private getTimezone(): string {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      return new Date().getTimezoneOffset().toString();
    }
  }

  /**
   * Get hardware information
   */
  private getHardware(): { concurrency: number; memory?: number; touchPoints: number } {
    return {
      concurrency: navigator.hardwareConcurrency || 0,
      memory: (navigator as Navigator & { deviceMemory?: number }).deviceMemory,
      touchPoints: navigator.maxTouchPoints || 0,
    };
  }

  /**
   * Get canvas fingerprint
   */
  private async getCanvasFingerprint(): Promise<string | undefined> {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d');
      if (!ctx) return undefined;

      // Draw text with specific styling
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 100, 50);
      ctx.fillStyle = '#069';
      ctx.fillText('Trust Platform', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Canvas FP', 4, 30);

      const dataUrl = canvas.toDataURL();
      return await this.sha256(dataUrl);
    } catch {
      return undefined;
    }
  }

  /**
   * Get WebGL fingerprint
   */
  private async getWebGLFingerprint(): Promise<string | undefined> {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return undefined;

      const webgl = gl as WebGLRenderingContext;
      const debugInfo = webgl.getExtension('WEBGL_debug_renderer_info');

      const info = {
        vendor: webgl.getParameter(webgl.VENDOR),
        renderer: webgl.getParameter(webgl.RENDERER),
        unmaskedVendor: debugInfo ? webgl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : undefined,
        unmaskedRenderer: debugInfo ? webgl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : undefined,
      };

      return await this.sha256(JSON.stringify(info));
    } catch {
      return undefined;
    }
  }

  /**
   * Get audio fingerprint
   */
  private async getAudioFingerprint(): Promise<string | undefined> {
    try {
      const AudioContext = window.AudioContext || (window as Window & { webkitAudioContext?: typeof window.AudioContext }).webkitAudioContext;
      if (!AudioContext) return undefined;

      const context = new AudioContext();
      const oscillator = context.createOscillator();
      const analyser = context.createAnalyser();
      const gain = context.createGain();
      const processor = context.createScriptProcessor(4096, 1, 1);

      gain.gain.value = 0; // Mute
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;

      oscillator.connect(analyser);
      analyser.connect(processor);
      processor.connect(gain);
      gain.connect(context.destination);

      return new Promise((resolve) => {
        oscillator.start(0);

        const dataArray = new Float32Array(analyser.frequencyBinCount);
        analyser.getFloatFrequencyData(dataArray);

        oscillator.stop();
        context.close();

        const hash = this.sha256(dataArray.slice(0, 100).toString());
        resolve(hash);
      });
    } catch {
      return undefined;
    }
  }

  /**
   * Hash components to create fingerprint
   */
  private async hashComponents(components: Record<string, unknown>): Promise<string> {
    const str = JSON.stringify(components, Object.keys(components).sort());
    return this.sha256(str);
  }

  /**
   * SHA-256 hash function
   */
  private async sha256(message: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}
