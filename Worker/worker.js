/**
 * ThreatAnalyzer — Cloudflare Worker API Proxy
 *
 * Routes:
 *   GET /scan?value=<ioc>          — main aggregator (VT + AbuseIPDB + WHOIS + URLScan)
 *   GET /urlscan/result?uuid=<id>  — poll a pending URLScan result
 *
 * All API keys are passed from the browser via custom request headers:
 *   X-VT-API-Key       → VirusTotal
 *   X-AbuseIPDB-Key    → AbuseIPDB
 *   X-Whois-Key        → APILayer WHOIS
 *   X-URLScan-Key      → URLScan.io
 *   X-AbuseCH-Key      → Abuse.ch (ThreatFox / URLhaus / MalwareBazaar)
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers':
    'Accept, Content-Type, X-VT-API-Key, X-AbuseIPDB-Key, X-Whois-Key, X-URLScan-Key, X-AbuseCH-Key',
};

// ─── Entry point ─────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    // Handle CORS pre-flight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/scan') {
        return await handleScan(request, url);
      }

      if (url.pathname === '/urlscan/result') {
        return await handleURLScanResult(request, url);
      }

      return jsonResponse({ error: 'Not found' }, 404);
    } catch (err) {
      console.error('Worker unhandled error:', err);
      return jsonResponse({ error: err.message || 'Internal server error' }, 500);
    }
  },
};

// ─── /scan ────────────────────────────────────────────────────────────────────

async function handleScan(request, url) {
  const value = url.searchParams.get('value');
  if (!value) {
    return jsonResponse({ error: 'Missing required parameter: value' }, 400);
  }

  const vtKey       = request.headers.get('X-VT-API-Key')    || '';
  const abuseKey    = request.headers.get('X-AbuseIPDB-Key') || '';
  const whoisKey    = request.headers.get('X-Whois-Key')     || '';
  const urlscanKey  = request.headers.get('X-URLScan-Key')   || '';
  const abusechKey  = request.headers.get('X-AbuseCH-Key')   || '';

  const iocType = detectIOCType(value);

  // Fan-out all lookups in parallel — each returns null / error obj on failure
  const [virustotal, abuseipdb, whois, urlscan, threatfox, urlhaus, malwarebazaar] =
    await Promise.all([
      vtKey      ? fetchVirusTotal(value, iocType, vtKey)        : Promise.resolve(null),
      abuseKey   ? fetchAbuseIPDB(value, iocType, abuseKey)      : Promise.resolve(null),
      whoisKey   ? fetchWhois(value, iocType, whoisKey)          : Promise.resolve(null),
      urlscanKey ? fetchURLScan(value, iocType, urlscanKey)      : Promise.resolve(null),
      abusechKey ? fetchThreatFox(value, iocType, abusechKey)    : Promise.resolve(null),
      abusechKey ? fetchURLhaus(value, iocType, abusechKey)      : Promise.resolve(null),
      abusechKey ? fetchMalwareBazaar(value, iocType, abusechKey): Promise.resolve(null),
    ]);

  return jsonResponse({
    ioc:   value,
    type:  iocType,
    virustotal,
    abuseipdb,
    whois,
    urlscan,
    threatfox,
    urlhaus,
    malwarebazaar,
  });
}

// ─── /urlscan/result ──────────────────────────────────────────────────────────

async function handleURLScanResult(request, url) {
  const uuid = url.searchParams.get('uuid');
  if (!uuid) return jsonResponse({ error: 'Missing uuid parameter' }, 400);

  const apiKey = request.headers.get('X-URLScan-Key') || '';

  const resp = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
    headers: apiKey ? { 'API-Key': apiKey } : {},
  });

  if (resp.status === 404) {
    // Still processing
    return jsonResponse({ status: 'pending', uuid });
  }

  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    return jsonResponse({ error: body.message || `URLScan error: ${resp.status}` }, resp.status);
  }

  const data = await resp.json();
  return jsonResponse(data);
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────

async function fetchVirusTotal(value, type, apiKey) {
  try {
    let endpoint;
    let method = 'GET';
    let body;
    let urlEncoded;

    switch (type) {
      case 'ip':
        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
        break;
      case 'domain':
        endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
        break;
      case 'hash':
        endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
        break;
      case 'url': {
        // VT requires url_id = base64url(url) with no padding
        const urlId = btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        break;
      }
      default:
        return { error: `Unsupported IOC type for VirusTotal: ${type}` };
    }

    const resp = await fetch(endpoint, {
      method,
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json',
      },
    });

    if (resp.status === 404) return { error: 'Not found in VirusTotal' };
    if (resp.status === 401) return { error: 'Invalid VirusTotal API key' };
    if (resp.status === 429) return { error: 'VirusTotal rate limit exceeded' };

    const data = await resp.json();

    // VT wraps errors inside JSON even on non-2xx
    if (data.error) {
      return { error: data.error.message || JSON.stringify(data.error) };
    }

    return data;
  } catch (err) {
    return { error: `VirusTotal fetch failed: ${err.message}` };
  }
}

// ─── AbuseIPDB ────────────────────────────────────────────────────────────────

async function fetchAbuseIPDB(value, type, apiKey) {
  if (type !== 'ip') return null; // AbuseIPDB is IP-only

  try {
    const params = new URLSearchParams({
      ipAddress: value,
      maxAgeInDays: '90',
      verbose: '1',
    });

    const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?${params}`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      },
    });

    if (resp.status === 401) return { error: 'Invalid AbuseIPDB API key' };
    if (resp.status === 429) return { error: 'AbuseIPDB rate limit exceeded' };

    const data = await resp.json();

    if (data.errors) {
      return { error: data.errors.map(e => e.detail || e.title).join('; ') };
    }

    // Return unwrapped so frontend can use data.abuseipdb directly
    return data.data || data;
  } catch (err) {
    return { error: `AbuseIPDB fetch failed: ${err.message}` };
  }
}

// ─── WHOIS (APILayer) ──────────────────────────────────────────────────────────

async function fetchWhois(value, type, apiKey) {
  // Only meaningful for domains and URLs
  if (type !== 'domain' && type !== 'url') return null;

  try {
    // Extract domain from URL if needed
    let domain = value;
    if (type === 'url') {
      try {
        domain = new URL(value.startsWith('http') ? value : `https://${value}`).hostname;
      } catch (_) {
        domain = value;
      }
    }

    // Strip leading www.
    domain = domain.replace(/^www\./, '');

    const resp = await fetch(
      `https://api.apilayer.com/whois/query?domain=${encodeURIComponent(domain)}`,
      {
        headers: {
          'apikey': apiKey,
          'Accept': 'application/json',
        },
      }
    );

    if (resp.status === 401) return { error: 'Invalid WHOIS API key' };
    if (resp.status === 429) return { error: 'WHOIS API rate limit exceeded' };
    if (resp.status === 404) return { error: `No WHOIS data found for ${domain}` };

    const data = await resp.json();

    if (data.message && !data.result) {
      return { error: data.message };
    }

    return data;
  } catch (err) {
    return { error: `WHOIS fetch failed: ${err.message}` };
  }
}

// ─── URLScan.io ───────────────────────────────────────────────────────────────

async function fetchURLScan(value, type, apiKey) {
  // URLScan is primarily for URLs and domains
  if (type !== 'url' && type !== 'domain') return null;

  try {
    // Submit scan
    const submitResp = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': apiKey,
      },
      body: JSON.stringify({
        url: type === 'url' ? value : `https://${value}`,
        visibility: 'public',
      }),
    });

    if (submitResp.status === 401) return { error: 'Invalid URLScan API key' };
    if (submitResp.status === 429) return { error: 'URLScan rate limit exceeded' };

    if (!submitResp.ok) {
      const body = await submitResp.json().catch(() => ({}));
      return { error: body.message || `URLScan submit failed: ${submitResp.status}` };
    }

    const submitData = await submitResp.json();
    const uuid = submitData.uuid;

    if (!uuid) return { error: 'URLScan did not return a scan UUID' };

    // Return pending status — the browser will poll /urlscan/result?uuid=...
    // via the Worker's second route. This avoids holding the Worker open for 2+ minutes.
    return {
      status: 'pending',
      uuid,
      resultUrl: submitData.result,
      message: 'Scan submitted successfully. Polling for result…',
    };
  } catch (err) {
    return { error: `URLScan fetch failed: ${err.message}` };
  }
}

// ─── ThreatFox (Abuse.ch) ─────────────────────────────────────────────────────

async function fetchThreatFox(value, type, apiKey) {
  try {
    const resp = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Auth-Key': apiKey,
      },
      body: JSON.stringify({ query: 'search_ioc', search_term: value }),
    });

    if (!resp.ok) return { found: false, error: `ThreatFox error: ${resp.status}` };

    const data = await resp.json();

    if (data.query_status === 'no_result') return { found: false };
    if (data.query_status !== 'ok') return { found: false, error: data.query_status };

    return {
      found: true,
      iocs: data.data || [],
    };
  } catch (err) {
    return { found: false, error: `ThreatFox fetch failed: ${err.message}` };
  }
}

// ─── URLhaus (Abuse.ch) ───────────────────────────────────────────────────────

async function fetchURLhaus(value, type, apiKey) {
  if (type !== 'url' && type !== 'domain' && type !== 'hash') return null;

  try {
    let endpoint, bodyParams;

    if (type === 'hash') {
      endpoint = 'https://urlhaus-api.abuse.ch/v1/payload/';
      bodyParams = `md5_hash=${encodeURIComponent(value)}`;
      if (value.length === 64) {
        bodyParams = `sha256_hash=${encodeURIComponent(value)}`;
      }
    } else {
      endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
      bodyParams = `url=${encodeURIComponent(value)}`;
    }

    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: bodyParams,
    });

    if (!resp.ok) return { found: false, error: `URLhaus error: ${resp.status}` };

    const data = await resp.json();

    if (data.query_status === 'no_results' || data.query_status === 'not_found') {
      return { found: false };
    }

    return { found: true, ...data };
  } catch (err) {
    return { found: false, error: `URLhaus fetch failed: ${err.message}` };
  }
}

// ─── MalwareBazaar (Abuse.ch) ─────────────────────────────────────────────────

async function fetchMalwareBazaar(value, type, apiKey) {
  if (type !== 'hash') return null;

  try {
    const resp = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `query=get_info&hash=${encodeURIComponent(value)}`,
    });

    if (!resp.ok) return { found: false, error: `MalwareBazaar error: ${resp.status}` };

    const data = await resp.json();

    if (data.query_status === 'hash_not_found') return { found: false };

    return {
      found: true,
      malware_family: data.data?.[0]?.signature || null,
      ...data,
    };
  } catch (err) {
    return { found: false, error: `MalwareBazaar fetch failed: ${err.message}` };
  }
}

// ─── IOC Type Detection ───────────────────────────────────────────────────────

function detectIOCType(value) {
  const v = value.trim();

  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip';

  // IPv6 — simplified check
  if (/^[0-9a-fA-F:]{2,39}$/.test(v) && v.includes(':')) return 'ip';

  // MD5
  if (/^[a-fA-F0-9]{32}$/.test(v)) return 'hash';
  // SHA1
  if (/^[a-fA-F0-9]{40}$/.test(v)) return 'hash';
  // SHA256
  if (/^[a-fA-F0-9]{64}$/.test(v)) return 'hash';

  // URL (has scheme)
  if (/^https?:\/\//i.test(v)) return 'url';

  // Domain-like (contains dot, no spaces)
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(v)) return 'domain';

  // Default: treat as URL
  return 'url';
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': 'application/json',
    },
  });
}
