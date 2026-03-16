/**
 * urlscan-poller.js
 * ThreatAnalyzer — URLScan.io Async Polling Module
 *
 * Handles the full lifecycle of a URLScan submission:
 *   1. POST /scan        → get UUID
 *   2. Poll GET /result/{uuid}  every N seconds until 200 or timeout
 *   3. Parse + return the full result JSON to the UI layer
 */

const URLScanPoller = (() => {

  // ─── Configuration ──────────────────────────────────────────────────────────

  const BASE_URL   = 'https://urlscan.io/api/v1';
  const SCAN_EP    = `${BASE_URL}/scan/`;
  const RESULT_EP  = (uuid) => `${BASE_URL}/result/${uuid}/`;

  const DEFAULTS = {
    visibility:      'public',   // 'public' | 'unlisted' | 'private'
    pollIntervalMs:  5000,       // how long to wait between retries (ms)
    maxAttempts:     24,         // 24 × 5 s = 2 min max wait
    initialDelayMs:  8000,       // urlscan usually needs ~8 s before first result
    onProgress:      null,       // optional (message: string) => void callback
  };

  // ─── Internal helpers ────────────────────────────────────────────────────────

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const notify = (fn, msg) => {
    try { fn && fn(msg); } catch (_) {}
  };

  async function submitScan(url, apiKey, visibility) {
    const response = await fetch(SCAN_EP, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key':      apiKey,
      },
      body: JSON.stringify({ url, visibility }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const msg  = body?.message || body?.description || response.statusText;
      throw new URLScanError(`Scan submission failed (HTTP ${response.status}): ${msg}`, response.status);
    }

    const data = await response.json();

    if (!data?.uuid) {
      throw new URLScanError('Scan submission returned no UUID.', 0);
    }

    return {
      uuid:      data.uuid,
      resultUrl: data.result,
      apiUrl:    data.api,
    };
  }

  async function pollForResult(uuid, opts) {
    const { pollIntervalMs, maxAttempts, onProgress } = opts;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      notify(onProgress, `Waiting for scan to complete… (attempt ${attempt}/${maxAttempts})`);

      const response = await fetch(RESULT_EP(uuid), {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.status === 200) {
        const result = await response.json();
        notify(onProgress, 'Scan complete. Parsing results…');
        return result;
      }

      if (response.status === 404) {
        if (attempt < maxAttempts) {
          await sleep(pollIntervalMs);
          continue;
        }
        throw new URLScanError(
          `Scan did not complete after ${maxAttempts} attempts (~${Math.round((maxAttempts * pollIntervalMs) / 1000)}s). ` +
          `View result manually: https://urlscan.io/result/${uuid}/`,
          404,
          uuid
        );
      }

      const body = await response.json().catch(() => ({}));
      throw new URLScanError(
        `Unexpected response (HTTP ${response.status}) while polling: ${body?.message || response.statusText}`,
        response.status,
        uuid
      );
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  async function scan(url, apiKey, options = {}) {
    const opts = { ...DEFAULTS, ...options };

    notify(opts.onProgress, 'Submitting URL to URLScan.io…');
    const { uuid, resultUrl } = await submitScan(url, apiKey, opts.visibility);
    notify(opts.onProgress, `Scan queued. UUID: ${uuid}`);

    notify(opts.onProgress, `Waiting ${opts.initialDelayMs / 1000}s for scan to initialize…`);
    await sleep(opts.initialDelayMs);

    const rawResult = await pollForResult(uuid, opts);

    return parseResult(rawResult, uuid, resultUrl);
  }

  function parseResult(raw, uuid, resultUrl) {
    const page     = raw?.page     || {};
    const stats    = raw?.stats    || {};
    const verdicts = raw?.verdicts || {};
    const lists    = raw?.lists    || {};
    const meta     = raw?.meta     || {};
    const data     = raw?.data     || {};

    const overallVerdict  = verdicts?.overall   || {};
    const urlscanVerdict  = verdicts?.urlscan   || {};
    const communityScore  = verdicts?.community || {};

    return {
      uuid,
      resultUrl,
      submittedUrl: page.url       || '',
      finalUrl:     page.url       || '',
      domain:       page.domain    || '',
      ip:           page.ip        || '',
      country:      page.country   || '',
      server:       page.server    || '',
      title:        page.title     || '',

      scannedAt:    raw?.task?.time || null,
      visibility:   raw?.task?.visibility || 'public',

      malicious:    overallVerdict.malicious  ?? false,
      score:        overallVerdict.score      ?? 0,
      tags:         overallVerdict.tags       || [],
      categories:   urlscanVerdict.categories || [],
      brands:       urlscanVerdict.brands     || [],

      stats: {
        requests:        stats.requests        ?? 0,
        domains:         stats.domains         ?? 0,
        countries:       stats.countries       ?? 0,
        ips:             stats.ips             ?? 0,
        dataLength:      stats.dataLength      ?? 0,
        uniqIPs:         stats.uniqIPs         ?? 0,
        consoleMsgs:     stats.consoleMsgs     ?? 0,
        tlsSizes:        stats.tlsSizes        || {},
        tlsInfo:         stats.tlsInfo         || {},
        malicious:       stats.malicious       ?? 0,
        adBlocked:       stats.adBlocked       ?? 0,
        securePercent:   stats.securePercentage ?? null,
      },

      ips:       lists.ips       || [],
      domains:   lists.domains   || [],
      urls:      lists.urls      || [],
      countries: lists.countries || [],
      hashes:    lists.hashes    || [],
      asns:      lists.asns      || [],
      servers:   lists.servers   || [],
      certificates: lists.certificates || [],

      requests: (data.requests || []).map((r) => ({
        url:      r?.request?.request?.url      || '',
        method:   r?.request?.request?.method   || '',
        status:   r?.response?.response?.status  ?? null,
        mimeType: r?.response?.response?.mimeType || '',
        size:     r?.response?.dataLength        ?? 0,
      })),

      screenshotUrl: `https://urlscan.io/screenshots/${uuid}.png`,

      tlsIssuer:     page.tlsIssuer     || '',
      tlsValidFrom:  page.tlsValidFrom  || '',
      tlsValidTo:    page.tlsValidDays  || '',
      tlsAgeDays:    page.tlsAgeDays    ?? null,

      _fullResult: raw,
      _meta: meta,
      _community: communityScore,
    };
  }

  class URLScanError extends Error {
    constructor(message, httpStatus = 0, uuid = null) {
      super(message);
      this.name       = 'URLScanError';
      this.httpStatus = httpStatus;
      this.uuid       = uuid;
    }
  }

  return { scan, URLScanError };

})();

// ─── Integration glue — wire this into ThreatAnalyzer UI ─────────────────────
//
// runURLScan is called from startSingleScanLegacy() in scripts.js.
// It delegates to scanURLScan() which lives inside scripts.js and contains
// the full submit → poll → render pipeline.
// URLScanPoller.scan() is available for any other callers that need the
// low-level poller directly (e.g. bulk scans, Quick Query, etc.).

async function runURLScan(ioc) {
  // Delegate entirely to the patched scanURLScan() in scripts.js
  // which now correctly submits, polls, and renders.
  if (typeof scanURLScan === 'function') {
    return scanURLScan(ioc);
  }

  // Fallback: use URLScanPoller directly if scanURLScan is not available
  const apiKey = getURLScanKey();
  if (!apiKey) {
    if (typeof showError === 'function') showError('urlscan', 'URLScan API key not configured');
    return;
  }

  if (typeof showLoading === 'function') showLoading('urlscan');

  try {
    const result = await URLScanPoller.scan(ioc, apiKey, {
      visibility:     'public',
      pollIntervalMs: 5000,
      maxAttempts:    24,
      initialDelayMs: 8000,
      onProgress:     (msg) => updateURLScanStatus(msg),
    });

    if (typeof currentResults !== 'undefined') currentResults.urlscan = result._fullResult || result;
    if (typeof renderURLScan  === 'function')  renderURLScan(result._fullResult || result);
    if (typeof updateReputationGrid === 'function') {
      updateReputationGrid(currentResults.vt, currentResults.abuseipdb, currentResults.whois, currentResults.urlscan);
    }
    return result;

  } catch (err) {
    const msg = err instanceof URLScanPoller.URLScanError && err.uuid
      ? `${err.message} <a href="https://urlscan.io/result/${err.uuid}/" target="_blank" style="color:var(--accent-blue)">View ↗</a>`
      : `URLScan error: ${err.message}`;
    if (typeof showError === 'function') showError('urlscan', msg);
  }
}

function getURLScanKey() {
  const stored = localStorage.getItem('urlscan_api_key');
  if (stored) {
    try { return atob(stored); } catch (_) { return stored; }
  }
  return localStorage.getItem('urlscanApiKey') || '';
}

function updateURLScanStatus(msg) {
  const container = document.getElementById('urlscanResults');
  if (!container) return;
  const label = container.querySelector('.loading span');
  if (label) label.textContent = msg;
}
