/**
 * urlscan-poller.js
 * ThreatAnalyzer — URLScan.io Async Polling Module
 *
 * Handles the full lifecycle of a URLScan submission:
 *   1. POST /scan        → get UUID
 *   2. Poll GET /result/{uuid}  every N seconds until 200 or timeout
 *   3. Parse + return the full result JSON to the UI layer
 *
 * Usage (drop-in replacement for your existing URLScan fetch):
 *
 *   const result = await URLScanPoller.scan(url, apiKey, {
 *     onProgress: (msg) => updateStatusUI(msg)
 *   });
 *   displayURLScanResults(result);
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

  /**
   * Sleep for `ms` milliseconds.
   */
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  /**
   * Fire optional progress callback without throwing.
   */
  const notify = (fn, msg) => {
    try { fn && fn(msg); } catch (_) {}
  };

  /**
   * Step 1 — Submit the URL to urlscan.io.
   * Returns { uuid, resultUrl, apiUrl } or throws on error.
   */
  async function submitScan(url, apiKey, visibility) {
    const response = await fetch(SCAN_EP, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key':      apiKey,
      },
      body: JSON.stringify({ url, visibility }),
    });

    // 400 = bad request (invalid URL, quota exceeded, etc.)
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

  /**
   * Step 2 — Poll the result endpoint until the scan is ready.
   *
   * urlscan returns:
   *   404  → scan still processing (normal; keep polling)
   *   200  → scan complete; full JSON in body
   *   400  → malformed UUID
   *   404 after timeout → scan may have been blocked/skipped by urlscan
   *
   * Returns the full result JSON object.
   */
  async function pollForResult(uuid, opts) {
    const { pollIntervalMs, maxAttempts, onProgress } = opts;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      notify(onProgress, `Waiting for scan to complete… (attempt ${attempt}/${maxAttempts})`);

      const response = await fetch(RESULT_EP(uuid), {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.status === 200) {
        // ✅ Scan complete — parse and return
        const result = await response.json();
        notify(onProgress, 'Scan complete. Parsing results…');
        return result;
      }

      if (response.status === 404) {
        // ⏳ Still processing — wait and retry
        if (attempt < maxAttempts) {
          await sleep(pollIntervalMs);
          continue;
        }
        // Ran out of attempts
        throw new URLScanError(
          `Scan did not complete after ${maxAttempts} attempts (~${Math.round((maxAttempts * pollIntervalMs) / 1000)}s). ` +
          `View result manually: https://urlscan.io/result/${uuid}/`,
          404,
          uuid
        );
      }

      // Any other HTTP error is fatal
      const body = await response.json().catch(() => ({}));
      throw new URLScanError(
        `Unexpected response (HTTP ${response.status}) while polling: ${body?.message || response.statusText}`,
        response.status,
        uuid
      );
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Main entry point.
   *
   * @param {string}   url          - The URL/domain to scan
   * @param {string}   apiKey       - Your urlscan.io API key
   * @param {object}   [options]    - Overrides for DEFAULTS
   * @returns {Promise<URLScanResult>}
   */
  async function scan(url, apiKey, options = {}) {
    const opts = { ...DEFAULTS, ...options };

    // ── 1. Submit ──────────────────────────────────────────────────────────
    notify(opts.onProgress, 'Submitting URL to URLScan.io…');
    const { uuid, resultUrl } = await submitScan(url, apiKey, opts.visibility);
    notify(opts.onProgress, `Scan queued. UUID: ${uuid}`);

    // ── 2. Initial delay (scan needs time to start) ────────────────────────
    notify(opts.onProgress, `Waiting ${opts.initialDelayMs / 1000}s for scan to initialize…`);
    await sleep(opts.initialDelayMs);

    // ── 3. Poll until ready ────────────────────────────────────────────────
    const rawResult = await pollForResult(uuid, opts);

    // ── 4. Parse into a normalized shape for the UI ────────────────────────
    return parseResult(rawResult, uuid, resultUrl);
  }

  /**
   * Normalize the raw urlscan JSON into the shape your UI expects.
   * Extend this function as you add more fields to the display.
   */
  function parseResult(raw, uuid, resultUrl) {
    const page     = raw?.page     || {};
    const stats    = raw?.stats    || {};
    const verdicts = raw?.verdicts || {};
    const lists    = raw?.lists    || {};
    const meta     = raw?.meta     || {};
    const data     = raw?.data     || {};

    // Malicious verdict from urlscan's own engine + community
    const overallVerdict  = verdicts?.overall   || {};
    const urlscanVerdict  = verdicts?.urlscan   || {};
    const communityScore  = verdicts?.community || {};

    return {
      // ── Identity ────────────────────────────────────────────────────────
      uuid,
      resultUrl,
      submittedUrl: page.url       || '',
      finalUrl:     page.url       || '',
      domain:       page.domain    || '',
      ip:           page.ip        || '',
      country:      page.country   || '',
      server:       page.server    || '',
      title:        page.title     || '',

      // ── Scan metadata ────────────────────────────────────────────────────
      scannedAt:    raw?.task?.time || null,
      visibility:   raw?.task?.visibility || 'public',

      // ── Verdict ──────────────────────────────────────────────────────────
      malicious:    overallVerdict.malicious  ?? false,
      score:        overallVerdict.score      ?? 0,
      tags:         overallVerdict.tags       || [],
      categories:   urlscanVerdict.categories || [],
      brands:       urlscanVerdict.brands     || [],

      // ── Stats ─────────────────────────────────────────────────────────────
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

      // ── Network ───────────────────────────────────────────────────────────
      ips:       lists.ips       || [],
      domains:   lists.domains   || [],
      urls:      lists.urls      || [],
      countries: lists.countries || [],
      hashes:    lists.hashes    || [],
      asns:      lists.asns      || [],
      servers:   lists.servers   || [],
      certificates: lists.certificates || [],

      // ── HTTP requests summary ─────────────────────────────────────────────
      requests: (data.requests || []).map((r) => ({
        url:      r?.request?.request?.url      || '',
        method:   r?.request?.request?.method   || '',
        status:   r?.response?.response?.status  ?? null,
        mimeType: r?.response?.response?.mimeType || '',
        size:     r?.response?.dataLength        ?? 0,
      })),

      // ── Screenshots ───────────────────────────────────────────────────────
      screenshotUrl: `https://urlscan.io/screenshots/${uuid}.png`,

      // ── SSL / TLS ─────────────────────────────────────────────────────────
      tlsIssuer:     page.tlsIssuer     || '',
      tlsValidFrom:  page.tlsValidFrom  || '',
      tlsValidTo:    page.tlsValidDays  || '',
      tlsAgeDays:    page.tlsAgeDays    ?? null,

      // ── Raw (for the JSON viewer) ─────────────────────────────────────────
      _fullResult: raw,
    };
  }

  // ─── Custom error class ──────────────────────────────────────────────────────

  class URLScanError extends Error {
    constructor(message, httpStatus = 0, uuid = null) {
      super(message);
      this.name       = 'URLScanError';
      this.httpStatus = httpStatus;
      this.uuid       = uuid;
    }
  }

  // ─── Exports ─────────────────────────────────────────────────────────────────

  return { scan, URLScanError };

})();


// ═══════════════════════════════════════════════════════════════════════════════
//  Integration glue — wire this into your existing ThreatAnalyzer UI
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Call this from your existing `startScan()` / `queryURLScan()` function
 * whenever the IOC type is 'url' or 'domain'.
 *
 * Replace the content of your current urlscan block with this function.
 */
async function runURLScan(ioc) {
  const apiKey = getURLScanKey(); // your existing key-retrieval helper
  if (!apiKey) {
    showURLScanError('URLScan API key not configured. Add it in Settings.');
    return;
  }

  // Show loading state in the URLScan tab
  showURLScanLoading(true, 'Submitting to URLScan.io…');

  try {
    const result = await URLScanPoller.scan(ioc, apiKey, {
      visibility:   'public',
      pollIntervalMs: 5000,
      maxAttempts:    24,       // ~2 minutes total
      initialDelayMs: 8000,
      onProgress: (msg) => {
        // Update the loading message in the URLScan panel
        updateURLScanStatus(msg);
      },
    });

    // Hand off to your existing display function
    displayURLScanResults(result);

  } catch (err) {
    if (err instanceof URLScanPoller.URLScanError) {
      // If the scan timed out, we can still give the user the direct link
      if (err.httpStatus === 404 && err.uuid) {
        showURLScanError(
          `${err.message}`,
          `https://urlscan.io/result/${err.uuid}/`
        );
      } else {
        showURLScanError(err.message);
      }
    } else {
      // Generic network/CORS error
      showURLScanError(`Network error: ${err.message}`);
    }
  } finally {
    showURLScanLoading(false);
  }
}


// ─── Stub UI helpers — replace these with your real implementations ───────────
// These match the pattern used elsewhere in ThreatAnalyzer (ui-panels.js style).

function getURLScanKey() {
  // Replace with however you retrieve the saved API key in scripts.js
  return localStorage.getItem('urlscanApiKey') || '';
}

function showURLScanLoading(isLoading, initialMessage = 'Scanning…') {
  const emptyEl   = document.getElementById('urlscanEmpty');
  const resultsEl = document.getElementById('urlscanResults');

  if (isLoading) {
    if (emptyEl)   emptyEl.style.display   = 'none';
    if (resultsEl) resultsEl.innerHTML = `
      <div class="loading-state" style="text-align:center; padding: 32px; color: var(--text-muted);">
        <div class="spinner" style="
          width:32px; height:32px; border:3px solid var(--border);
          border-top-color:var(--accent-blue); border-radius:50%;
          animation:spin 0.8s linear infinite; margin:0 auto 16px;">
        </div>
        <div id="urlscanStatusMsg" style="font-size:13px;">${initialMessage}</div>
      </div>`;
  } else {
    if (emptyEl) emptyEl.style.display = 'none';
  }
}

function updateURLScanStatus(msg) {
  const el = document.getElementById('urlscanStatusMsg');
  if (el) el.textContent = msg;
}

function showURLScanError(message, fallbackLink = null) {
  const resultsEl = document.getElementById('urlscanResults');
  if (!resultsEl) return;

  const linkHTML = fallbackLink
    ? `<br><a href="${fallbackLink}" target="_blank" rel="noopener noreferrer"
              style="color:var(--accent-blue); font-size:12px;">
         View result on urlscan.io ↗
       </a>`
    : '';

  resultsEl.innerHTML = `
    <div class="error-state" style="
      padding:24px; background:var(--bg-secondary);
      border:1px solid var(--danger); border-radius:8px;
      color:var(--danger); font-size:13px;">
      ⚠️ ${message}${linkHTML}
    </div>`;
}

/**
 * displayURLScanResults — render the parsed URLScan result into the UI.
 *
 * This replaces (or extends) your existing URLScan display code.
 * It uses the normalized shape returned by URLScanPoller.scan().
 */
function displayURLScanResults(r) {
  const resultsEl = document.getElementById('urlscanResults');
  if (!resultsEl) return;

  // Verdict badge colour
  const verdictClass = r.malicious ? 'danger' : (r.score > 0 ? 'warning' : 'success');
  const verdictLabel = r.malicious ? '🔴 MALICIOUS' : (r.score > 0 ? '🟡 SUSPICIOUS' : '🟢 CLEAN');

  // Helper: key-value row
  const row = (label, value) =>
    value ? `<tr><td style="color:var(--text-muted);padding:4px 8px;white-space:nowrap">${label}</td>
                 <td style="padding:4px 8px;word-break:break-all">${value}</td></tr>` : '';

  // Helper: pill list
  const pills = (items, colour) =>
    items.length
      ? items.map(t =>
          `<span style="background:var(--${colour});color:#fff;border-radius:4px;
                        padding:2px 7px;font-size:11px;margin:2px;">${t}</span>`
        ).join('')
      : '<span style="color:var(--text-muted)">—</span>';

  resultsEl.innerHTML = `
    <!-- ── Summary card ──────────────────────────────────────────────────── -->
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">

      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
        <h3 style="margin:0; font-size:15px;">🔍 URLScan.io Result</h3>
        <span style="
          background:var(--${verdictClass},#444); color:#fff;
          border-radius:6px; padding:4px 12px; font-size:13px; font-weight:600;">
          ${verdictLabel}
        </span>
      </div>

      <table style="width:100%; border-collapse:collapse; font-size:13px;">
        <tbody>
          ${row('Submitted URL', `<a href="${r.submittedUrl}" target="_blank" rel="noopener noreferrer"
                                      style="color:var(--accent-blue)">${r.submittedUrl}</a>`)}
          ${row('Final URL',    r.finalUrl !== r.submittedUrl
                                  ? `<a href="${r.finalUrl}" target="_blank" rel="noopener noreferrer"
                                         style="color:var(--accent-blue)">${r.finalUrl}</a>`
                                  : '')}
          ${row('Page Title',   r.title)}
          ${row('Domain',       r.domain)}
          ${row('Server IP',    r.ip)}
          ${row('Country',      r.country)}
          ${row('Server',       r.server)}
          ${row('Scanned At',   r.scannedAt ? new Date(r.scannedAt).toLocaleString() : '')}
          ${row('UUID',         `<a href="${r.resultUrl}" target="_blank" rel="noopener noreferrer"
                                     style="color:var(--accent-blue)">${r.uuid}</a>`)}
        </tbody>
      </table>
    </div>

    <!-- ── Screenshot ───────────────────────────────────────────────────── -->
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">
      <h4 style="margin:0 0 10px; font-size:13px; color:var(--text-muted);">📸 Page Screenshot</h4>
      <img src="${r.screenshotUrl}"
           alt="Page screenshot"
           onerror="this.style.display='none'; this.nextElementSibling.style.display='block'"
           style="width:100%; border-radius:4px; border:1px solid var(--border);">
      <span style="display:none; color:var(--text-muted); font-size:12px;">Screenshot not available yet.</span>
    </div>

    <!-- ── Verdict tags ──────────────────────────────────────────────────── -->
    ${(r.tags.length || r.categories.length || r.brands.length) ? `
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">
      <h4 style="margin:0 0 10px; font-size:13px; color:var(--text-muted);">🏷️ Tags & Categories</h4>
      <div style="margin-bottom:6px;">${pills(r.tags,       'danger')}</div>
      <div style="margin-bottom:6px;">${pills(r.categories, 'warning')}</div>
      <div>${pills(r.brands, 'accent-blue')}</div>
    </div>` : ''}

    <!-- ── Network stats ─────────────────────────────────────────────────── -->
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">
      <h4 style="margin:0 0 10px; font-size:13px; color:var(--text-muted);">📡 Network Stats</h4>
      <div style="display:flex; flex-wrap:wrap; gap:12px;">
        ${[
          ['Requests',  r.stats.requests],
          ['Domains',   r.stats.domains],
          ['IPs',       r.stats.ips],
          ['Countries', r.stats.countries],
          ['Malicious', r.stats.malicious],
          ['Ad-blocked',r.stats.adBlocked],
        ].map(([label, val]) => `
          <div style="
            background:var(--bg-tertiary,#0d1117); border:1px solid var(--border);
            border-radius:6px; padding:8px 14px; text-align:center; min-width:70px;">
            <div style="font-size:18px; font-weight:700;
                        color:${label==='Malicious'&&val>0 ? 'var(--danger)' : 'var(--text-primary)'}">
              ${val ?? '—'}
            </div>
            <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">${label}</div>
          </div>`).join('')}
      </div>
    </div>

    <!-- ── Domains / IPs ─────────────────────────────────────────────────── -->
    ${r.domains.length ? `
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">
      <h4 style="margin:0 0 10px; font-size:13px; color:var(--text-muted);">🌐 Contacted Domains (${r.domains.length})</h4>
      <div style="max-height:160px; overflow-y:auto; font-size:12px; font-family:monospace;">
        ${r.domains.map(d => `<div style="padding:2px 0; border-bottom:1px solid var(--border)">${d}</div>`).join('')}
      </div>
    </div>` : ''}

    ${r.ips.length ? `
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">
      <h4 style="margin:0 0 10px; font-size:13px; color:var(--text-muted);">🖥️ Contacted IPs (${r.ips.length})</h4>
      <div style="max-height:120px; overflow-y:auto; font-size:12px; font-family:monospace;">
        ${r.ips.map(ip => `<div style="padding:2px 0; border-bottom:1px solid var(--border)">${ip}</div>`).join('')}
      </div>
    </div>` : ''}

    <!-- ── HTTP requests table ───────────────────────────────────────────── -->
    ${r.requests.length ? `
    <div class="result-card" style="
      background:var(--bg-secondary); border:1px solid var(--border);
      border-radius:8px; padding:16px; margin-bottom:12px;">
      <h4 style="margin:0 0 10px; font-size:13px; color:var(--text-muted);">
        📋 HTTP Requests (${r.requests.length})
      </h4>
      <div style="overflow-x:auto; max-height:220px; overflow-y:auto;">
        <table style="width:100%; border-collapse:collapse; font-size:11px; font-family:monospace;">
          <thead>
            <tr style="background:var(--bg-tertiary,#0d1117); color:var(--text-muted);">
              <th style="padding:4px 8px; text-align:left;">Status</th>
              <th style="padding:4px 8px; text-align:left;">Method</th>
              <th style="padding:4px 8px; text-align:left;">Type</th>
              <th style="padding:4px 8px; text-align:left;">URL</th>
            </tr>
          </thead>
          <tbody>
            ${r.requests.slice(0, 100).map(req => {
              const statusColour = !req.status          ? '#888'
                                  : req.status < 300    ? 'var(--success,#3fb950)'
                                  : req.status < 400    ? 'var(--warning,#d29922)'
                                  :                        'var(--danger,#f85149)';
              return `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:3px 8px; color:${statusColour}">${req.status ?? '—'}</td>
                  <td style="padding:3px 8px; color:var(--text-muted)">${req.method}</td>
                  <td style="padding:3px 8px; color:var(--text-muted); white-space:nowrap">
                    ${(req.mimeType || '').replace('application/', '').replace('text/', '')}
                  </td>
                  <td style="padding:3px 8px; word-break:break-all; max-width:340px;">
                    ${req.url.length > 90 ? req.url.slice(0, 90) + '…' : req.url}
                  </td>
                </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- ── View full report link ─────────────────────────────────────────── -->
    <div style="text-align:center; padding:8px 0 16px;">
      <a href="${r.resultUrl}" target="_blank" rel="noopener noreferrer"
         style="color:var(--accent-blue); font-size:13px;">
        View full report on urlscan.io ↗
      </a>
    </div>`;
}

// ── CSS keyframe for spinner (inject once) ────────────────────────────────────
(function injectSpinnerCSS() {
  if (document.getElementById('urlscan-spinner-style')) return;
  const style = document.createElement('style');
  style.id = 'urlscan-spinner-style';
  style.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
  document.head.appendChild(style);
})();
