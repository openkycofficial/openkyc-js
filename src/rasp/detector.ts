export interface RASPSignals {
  isDevToolsOpen: boolean;
  isAutomated: boolean;
  isHeadless: boolean;
  isVirtualMachine: boolean;
  isEmulator: boolean;
  isDebugMode: boolean;
  hasConsoleTampering: boolean;
}

export class RASPDetector {
  /**
   * Detect all RASP signals
   */
  async detect(): Promise<RASPSignals> {
    const [
      isDevToolsOpen,
      isAutomated,
      isHeadless,
      isVirtualMachine,
      hasConsoleTampering,
    ] = await Promise.all([
      this.detectDevTools(),
      this.detectAutomation(),
      this.detectHeadless(),
      this.detectVirtualMachine(),
      this.detectConsoleTampering(),
    ]);

    return {
      isDevToolsOpen,
      isAutomated,
      isHeadless,
      isVirtualMachine,
      isEmulator: isVirtualMachine, // For web, VM detection is equivalent
      isDebugMode: isDevToolsOpen,
      hasConsoleTampering,
    };
  }

  /**
   * Detect if DevTools is open
   */
  private async detectDevTools(): Promise<boolean> {
    // Method 1: Check window size difference
    const widthThreshold = window.outerWidth - window.innerWidth > 160;
    const heightThreshold = window.outerHeight - window.innerHeight > 160;

    if (widthThreshold || heightThreshold) {
      return true;
    }

    // Method 2: Debugger detection via timing
    const start = performance.now();
    // This will be slow if debugger is attached
    (() => {
      const a = new Error();
      return a.stack;
    })();
    const end = performance.now();

    if (end - start > 100) {
      return true;
    }

    // Method 3: Check for Firebug
    if ((window as Window & { Firebug?: unknown }).Firebug?.chrome?.isInitialized) {
      return true;
    }

    return false;
  }

  /**
   * Detect automation tools (Selenium, Puppeteer, Playwright)
   */
  private async detectAutomation(): Promise<boolean> {
    const windowAny = window as Window & Record<string, unknown>;
    const navigatorAny = navigator as Navigator & Record<string, unknown>;
    const documentAny = document as Document & Record<string, unknown>;

    // Check for WebDriver
    if (navigatorAny.webdriver) {
      return true;
    }

    // Check for automation-specific properties
    const automationSigns = [
      '__webdriver_script_fn',
      '__driver_evaluate',
      '__webdriver_evaluate',
      '__selenium_evaluate',
      '__fxdriver_evaluate',
      '__driver_unwrapped',
      '__webdriver_unwrapped',
      '__selenium_unwrapped',
      '__fxdriver_unwrapped',
      '_Selenium_IDE_Recorder',
      '_selenium',
      'calledSelenium',
      '$cdc_asdjflasutopfhvcZLmcfl_',
      '$chrome_asyncScriptInfo',
      '__$webdriverAsyncExecutor',
      '__lastWatirAlert',
      '__lastWatirConfirm',
      '__lastWatirPrompt',
      '_WEBDRIVER_ELEM_CACHE',
      'ChromeDriverw',
    ];

    for (const sign of automationSigns) {
      if (windowAny[sign] !== undefined || documentAny[sign] !== undefined) {
        return true;
      }
    }

    // Check for Puppeteer/Playwright
    if (navigatorAny.plugins?.length === 0) {
      return true;
    }

    // Check for phantom
    if (windowAny.callPhantom || windowAny._phantom) {
      return true;
    }

    // Check for nightmare
    if (windowAny.__nightmare) {
      return true;
    }

    return false;
  }

  /**
   * Detect headless browsers
   */
  private async detectHeadless(): Promise<boolean> {
    const navigatorAny = navigator as Navigator & Record<string, unknown>;

    // Check user agent for headless indicators
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('headless')) {
      return true;
    }

    // Check for missing plugins (headless typically has none)
    if (!navigator.plugins || navigator.plugins.length === 0) {
      // Could be headless, but also could be a strict privacy setting
      // Combine with other signals
    }

    // Check for missing languages
    if (!navigator.languages || navigator.languages.length === 0) {
      return true;
    }

    // Chrome headless detection
    if (navigatorAny.webdriver === true) {
      return true;
    }

    // Check for permissions API behavior
    try {
      const permissionStatus = await navigator.permissions.query({ name: 'notifications' as PermissionName });
      if (permissionStatus.state === 'denied' && Notification.permission === 'default') {
        return true;
      }
    } catch {
      // Permissions API not available
    }

    // Check for Chrome-specific properties
    const windowAny = window as Window & { chrome?: unknown };
    if (!windowAny.chrome && ua.includes('chrome')) {
      return true;
    }

    return false;
  }

  /**
   * Detect virtual machines
   */
  private async detectVirtualMachine(): Promise<boolean> {
    // Check WebGL renderer for VM indicators
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const webgl = gl as WebGLRenderingContext;
        const debugInfo = webgl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          const renderer = webgl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)?.toLowerCase() || '';
          const vmIndicators = [
            'vmware',
            'virtualbox',
            'hyper-v',
            'parallels',
            'virtual',
            'qemu',
            'xen',
            'bochs',
          ];

          for (const indicator of vmIndicators) {
            if (renderer.includes(indicator)) {
              return true;
            }
          }
        }
      }
    } catch {
      // WebGL not available
    }

    // Check for low hardware specs (common in VMs)
    if (navigator.hardwareConcurrency === 1) {
      // Single core is suspicious
      return true;
    }

    const deviceMemory = (navigator as Navigator & { deviceMemory?: number }).deviceMemory;
    if (deviceMemory && deviceMemory < 2) {
      // Very low memory is suspicious
      return true;
    }

    return false;
  }

  /**
   * Detect console tampering
   */
  private async detectConsoleTampering(): Promise<boolean> {
    try {
      // Check if console methods have been overridden
      const nativeLog = console.log.toString();
      if (!nativeLog.includes('[native code]') && !nativeLog.includes('native code')) {
        return true;
      }

      // Check for common debugging tools
      const windowAny = window as Window & Record<string, unknown>;
      if (windowAny.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
        // React DevTools is installed (not necessarily malicious, but worth noting)
      }

      return false;
    } catch {
      // If we can't check, assume tampering
      return true;
    }
  }
}
