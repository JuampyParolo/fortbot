/**
 * FORTBOT — Browser Module (Playwright)
 *
 * Gives the agent READ-ONLY web browsing capabilities:
 *   - Navigate to URLs (rendered with JavaScript)
 *   - Extract text/data from pages
 *   - Take screenshots
 *   - Wait for dynamic content
 *
 * SECURITY MODEL:
 *   - READ-ONLY by design. Form filling and clicking are technically
 *     possible in the API but BLOCKED at the Executor level by
 *     src/policy/network.ts (checkFormFields, checkClickTarget).
 *   - Private IPs/internal networks blocked (Executor.checkUrl + network.ts)
 *   - Content sanitized for prompt injection before reaching any LLM
 *   - Each request gets a fresh browser context (no shared cookies/state)
 *   - Downloads are disabled (acceptDownloads: false)
 *   - Popup windows are auto-closed
 *   - No permissions granted (camera, mic, geolocation all denied)
 *   - Dangerous URI schemes blocked (javascript:, data:, file:, blob:)
 *   - CSP respected (bypassCSP: false)
 *
 * Playwright is an OPTIONAL dependency.
 * If not installed, browse actions fail gracefully.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface BrowseResult {
  url: string;
  title: string;
  text: string;
  screenshot?: Buffer;
  links: { text: string; href: string }[];
  error?: string;
}

export interface BrowseOptions {
  /** Take a screenshot */
  screenshot?: boolean;
  /** Wait for selector before extracting */
  waitFor?: string;
  /** Timeout in ms (default 15000) */
  timeout?: number;
  /** Max text length to extract (default 8000) */
  maxTextLength?: number;
  /** Extract specific CSS selector content only */
  selector?: string;
  // NOTE: fill and click were removed in v0.4 security hardening.
  // The browser is READ-ONLY by design. Form interaction is blocked
  // at multiple levels (BrowseOptions, Executor, network.ts).
}

let _browser: any = null;

async function getBrowser(): Promise<any> {
  if (_browser?.isConnected()) return _browser;

  // Dynamic import — playwright is optional
  const pw = await import('playwright');
  _browser = await pw.chromium.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--single-process',
    ],
  });

  return _browser;
}

export async function closeBrowser(): Promise<void> {
  if (_browser) {
    await _browser.close();
    _browser = null;
  }
}

/**
 * Browse a URL and extract content.
 *
 * This is the main entry point used by the Executor.
 * Each call creates a fresh context (no shared cookies/state).
 */
export async function browse(url: string, opts: BrowseOptions = {}): Promise<BrowseResult> {
  const timeout = opts.timeout ?? 15_000;
  const maxText = opts.maxTextLength ?? 8_000;

  let context: any = null;

  try {
    const browser = await getBrowser();

    // Fresh context per request — no cookie/session leakage
    context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 720 },
      javaScriptEnabled: true,
      ignoreHTTPSErrors: false,
      // SECURITY: disable features that could be exploited
      acceptDownloads: false,  // Block all file downloads
      bypassCSP: false,       // Respect Content Security Policy
      hasTouch: false,
      isMobile: false,
      permissions: [],         // Grant no permissions (no camera, mic, geolocation)
    });

    // SECURITY: Block popup windows
    context.on('page', (page: any) => {
      page.close().catch(() => {});
    });

    const page = await context.newPage();

    // SECURITY: Block navigation to dangerous schemes
    page.on('framenavigated', (frame: any) => {
      try {
        const frameUrl = frame.url();
        if (frameUrl && (
          frameUrl.startsWith('javascript:') ||
          frameUrl.startsWith('data:') ||
          frameUrl.startsWith('file:') ||
          frameUrl.startsWith('blob:')
        )) {
          frame.goto('about:blank').catch(() => {});
        }
      } catch { /* ignore */ }
    });

    // Block unnecessary resources for speed
    await page.route('**/*.{png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico}', (route: any) => {
      if (!opts.screenshot) {
        route.abort();
      } else {
        route.continue();
      }
    });

    // Navigate
    await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout,
    });

    // Optional: wait for specific element
    if (opts.waitFor) {
      await page.waitForSelector(opts.waitFor, { timeout: timeout / 2 }).catch(() => {});
    }

    // NOTE: fill/click intentionally removed — browser is READ-ONLY

    // Extract content
    let text: string;
    if (opts.selector) {
      text = await page.locator(opts.selector).innerText({ timeout: 5000 }).catch(() => '');
    } else {
      text = await extractMainContent(page);
    }

    // Truncate
    if (text.length > maxText) {
      text = text.substring(0, maxText) + '\n\n[... truncado]';
    }

    // Extract links
    const links = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('a[href]'))
        .slice(0, 20)
        .map((a) => ({
          text: (a as HTMLAnchorElement).innerText.trim().substring(0, 100),
          href: (a as HTMLAnchorElement).href,
        }))
        .filter((l) => l.text && l.href.startsWith('http'));
    });

    // Screenshot
    let screenshot: Buffer | undefined;
    if (opts.screenshot) {
      screenshot = await page.screenshot({
        type: 'jpeg',
        quality: 70,
        fullPage: false,
      });
    }

    const title = await page.title();

    return { url: page.url(), title, text, screenshot, links };
  } catch (err) {
    return {
      url,
      title: '',
      text: '',
      links: [],
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    if (context) {
      await context.close().catch(() => {});
    }
  }
}

/**
 * Extract the main readable content from a page.
 * Tries to find article/main content, falls back to body text.
 */
async function extractMainContent(page: any): Promise<string> {
  return page.evaluate(() => {
    // Try common content selectors
    const selectors = [
      'article', 'main', '[role="main"]',
      '.post-content', '.article-content', '.entry-content',
      '.content', '#content', '#main',
    ];

    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.textContent && el.textContent.trim().length > 100) {
        return el.textContent.trim().replace(/\s+/g, ' ');
      }
    }

    // Fallback: body text minus noise
    const noise = document.querySelectorAll(
      'nav, header, footer, aside, .sidebar, .menu, .nav, .footer, .header, script, style, noscript'
    );
    noise.forEach((el) => el.remove());

    return (document.body?.textContent ?? '').trim().replace(/\s+/g, ' ');
  });
}

/**
 * Take a screenshot of a URL without extracting content.
 * Useful for "show me what X looks like".
 */
export async function screenshot(url: string): Promise<Buffer | null> {
  const result = await browse(url, { screenshot: true, maxTextLength: 0 });
  return result.screenshot ?? null;
}

/**
 * Check if Playwright is available.
 * Returns false if not installed — browser actions degrade gracefully.
 */
export async function isPlaywrightAvailable(): Promise<boolean> {
  try {
    await import('playwright');
    return true;
  } catch {
    return false;
  }
}
