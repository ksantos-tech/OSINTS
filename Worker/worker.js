export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-VT-API-Key, X-AbuseIPDB-Key, X-Whois-Key, X-URLScan-Key, X-AbuseCH-Key"
        }
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const value = url.searchParams.get("value");

    // Get API keys from request headers (sent by frontend) or fall back to env
    const vtApiKey = request.headers.get("X-VT-API-Key") || env.VT_API_KEY;
    const abuseipdbKey = request.headers.get("X-AbuseIPDB-Key") || env.ABUSEIPDB_KEY;
    const whoisApiKey = request.headers.get("X-Whois-Key") || env.WHOIS_API_KEY;
    const urlscanKey = request.headers.get("X-URLScan-Key") || env.URLSCAN_KEY;
    // Single Auth-Key covers ThreatFox, URLhaus, and MalwareBazaar (all abuse.ch platforms)
    const abusechKey = request.headers.get("X-AbuseCH-Key") || env.ABUSECH_KEY;

    console.log("API Keys - VT:", !!vtApiKey, "AbuseIPDB:", !!abuseipdbKey, "WHOIS:", !!whoisApiKey, "URLScan:", !!urlscanKey, "AbuseCH:", !!abusechKey);

    // Route: /urlscan/result?uuid=<scanId>
    // Polled by frontend when Worker returned status:"pending".
    // GET /result requires API-Key per urlscan docs.
    if (path === "/urlscan/result") {
      const scanId = url.searchParams.get("uuid");
      if (!scanId) return json({ error: "Missing uuid parameter" }, 400);
      const key = request.headers.get("X-URLScan-Key") || env.URLSCAN_KEY;
      if (!key) return json({ error: "URLScan API key not configured" }, 400);
      try {
        const r = await fetch(
          `https://urlscan.io/api/v1/result/${scanId}/`,
          {
            headers: {
              "API-Key": key,
              "Accept": "application/json"
            }
          }
        );
        if (r.status === 200) return json(await r.json());
        if (r.status === 404) return json({ status: "pending", uuid: scanId });
        return json({ error: `URLScan returned HTTP ${r.status}` }, r.status);
      } catch (err) {
        return json({ error: err.message }, 500);
      }
    }

    // Route: /scan?value=<ioc>
    if (path !== "/scan" || !value) {
      return json({ error: "Use /scan?value=<ioc>" }, 400);
    }

    // Auto-detect IOC type from value
    const type = detectIOCType(value);

    if (type === "unknown") {
      return json({ error: "Unable to detect IOC type. Provide a valid IP, URL, or domain." }, 400);
    }

    try {
      let results = {};

      // Resolve domain to IP for services that only support IPs
      let resolvedIp = null;
      let domainToResolve = null;
      
      // Extract domain from URL if needed
      if (type === "url") {
        try {
          domainToResolve = new URL(value).hostname;
        } catch (e) {
          // Invalid URL, ignore
        }
      } else if (type === "domain") {
        domainToResolve = value;
      }
      
      // Perform DNS resolution for domains and URLs (quick - needed for AbuseIPDB)
      if ((type === "domain" || type === "url") && domainToResolve) {
        try {
          const dnsResponse = await fetch(`https://dns.google/resolve?name=${domainToResolve}&type=A`);
          const dnsData = await dnsResponse.json();
          if (dnsData.Answer && dnsData.Answer.length > 0) {
            const aRecord = dnsData.Answer.find(r => r.type === 1);
            if (aRecord) {
              resolvedIp = aRecord.data;
            }
          }
        } catch (err) {
          // DNS resolution failed
        }
      }

      // Make VirusTotal, AbuseIPDB, WHOIS calls in PARALLEL (no polling - fast)
      const fastPromises = [];

      // VIRUSTOTAL - supports IP, domain, URL, and hash
      if (type === "ip" || type === "domain" || type === "url" || type === "hash") {
        let vtEndpoint = "";
        if (type === "ip") {
          vtEndpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
        } else if (type === "domain") {
          vtEndpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
        } else if (type === "url") {
          // VT requires base64url encoding (RFC 4648): strip padding, + → -, / → _
          const encoded = btoa(value)
            .replace(/=+$/, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
          vtEndpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`;
        } else if (type === "hash") {
          // MD5 (32), SHA1 (40), SHA256 (64) all work directly
          vtEndpoint = `https://www.virustotal.com/api/v3/files/${value}`;
        }

        if (vtApiKey) {
          fastPromises.push(
            (async () => {
              try {
                const vtHeaders = { "x-apikey": vtApiKey };
                let vt = await fetch(vtEndpoint, { headers: vtHeaders });

                // For URLs: VT returns 404 when it has never seen the URL before.
                // Fix: POST to /urls to submit it for scanning, then GET the result.
                if (vt.status === 404 && type === "url") {
                  // Submit URL for analysis
                  const submitResp = await fetch("https://www.virustotal.com/api/v3/urls", {
                    method: "POST",
                    headers: { ...vtHeaders, "Content-Type": "application/x-www-form-urlencoded" },
                    body: `url=${encodeURIComponent(value)}`
                  });
                  if (!submitResp.ok) {
                    const e = await submitResp.json().catch(() => ({}));
                    results.virustotal = { error: e?.error?.message || `VT submit failed: ${submitResp.status}` };
                    return;
                  }
                  // Wait briefly then re-fetch the analysis result
                  await new Promise(r => setTimeout(r, 5000));
                  vt = await fetch(vtEndpoint, { headers: vtHeaders });
                }

                const vtData = await vt.json();
                // VT returns { error: { code, message } } on failure — flatten to a string
                if (vtData.error && typeof vtData.error === "object") {
                  results.virustotal = { error: vtData.error.message || vtData.error.code || "VirusTotal error" };
                } else {
                  results.virustotal = vtData;
                }
              } catch (err) {
                results.virustotal = { error: err.message };
              }
            })()
          );
        } else {
          results.virustotal = { error: "VT_API_KEY not configured" };
        }
      }

      // ABUSEIPDB - supports IP addresses (and domains/URLs via DNS resolution)
      if (type === "ip" || (type === "domain" && resolvedIp) || (type === "url" && resolvedIp)) {
        const ipToCheck = type === "ip" ? value : resolvedIp;
        if (abuseipdbKey) {
          fastPromises.push(
            (async () => {
              try {
                console.log('AbuseIPDB: Checking IP', ipToCheck);
                
                const abuse = await fetch(
                  `https://api.abuseipdb.com/api/v2/check?ipAddress=${ipToCheck}&maxAgeInDays=90&verbose=`,
                  { headers: { Key: abuseipdbKey, Accept: "application/json" } }
                );
                
                console.log('AbuseIPDB response status:', abuse.status);
                
                if (!abuse.ok) {
                  const errorData = await abuse.json().catch(() => ({}));
                  console.log('AbuseIPDB error:', errorData);
                  results.abuseipdb = { error: errorData.errors?.[0]?.detail || `API error: ${abuse.status}` };
                  return;
                }
                
                const abuseData = await abuse.json();
                console.log('AbuseIPDB raw response:', JSON.stringify(abuseData).substring(0, 200));
                
                // Extract the data from the API response (AbuseIPDB returns { data: {...} })
                let ipData = abuseData.data || abuseData;
                console.log('AbuseIPDB extracted data:', ipData ? 'present' : 'missing');
                
                if ((type === "domain" || type === "url") && resolvedIp) {
                  ipData.resolvedFrom = type === "url" ? domainToResolve : value;
                  ipData.resolvedIp = resolvedIp;
                }
                results.abuseipdb = ipData;
              } catch (err) {
                console.log('AbuseIPDB exception:', err.message);
                results.abuseipdb = { error: err.message };
              }
            })()
          );
        } else {
          results.abuseipdb = { error: "ABUSEIPDB_KEY not configured" };
        }
      }

      // WHOIS - supports domains and URLs (by extracting base domain, no subdomains)
      if (type === "domain" || type === "url") {
        const rawDomain = type === "url" ? domainToResolve : value;
        // APILayer WHOIS requires the registrable base domain (e.g. abuseipdb.com),
        // NOT a subdomain like www.abuseipdb.com — strip subdomains here.
        const domainForWhois = rawDomain ? extractBaseDomain(rawDomain) : null;
        if (whoisApiKey && domainForWhois) {
          fastPromises.push(
            (async () => {
              try {
                const whois = await fetch(
                  `https://api.apilayer.com/whois/query?domain=${encodeURIComponent(domainForWhois)}`,
                  { headers: { "APIKEY": whoisApiKey } }
                );
                const whoisData = await whois.json();
                // APILayer returns { result: {...} } on success
                // or { message: "No WHOIS data available" } on failure (no .error key)
                if (whoisData.result) {
                  results.whois = whoisData.result;
                } else {
                  results.whois = { error: whoisData.message || whoisData.error || "No WHOIS data available" };
                }
              } catch (err) {
                results.whois = { error: err.message };
              }
            })()
          );
        } else if (!domainForWhois) {
          results.whois = { error: "Could not extract domain from URL" };
        } else {
          results.whois = { error: "WHOIS_API_KEY not configured" };
        }
      }

      // ── THREATFOX — IOC lookup (IP, domain, URL, hash) ──────────────────────
      // No key required for search_ioc queries — Auth-Key is optional but helps
      // with rate limits. We send it when available.
      if (abusechKey || true) { // ThreatFox search_ioc is available without a key
        fastPromises.push(
          (async () => {
            try {
              // Normalise the IOC value for ThreatFox:
              // IPs with port (e.g. "1.2.3.4:80") are valid ThreatFox IOC types.
              // For URLs we query the full URL; for domains/IPs we query as-is.
              const tfHeaders = { "Content-Type": "application/json" };
              if (abusechKey) tfHeaders["Auth-Key"] = abusechKey;

              const tfResp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
                method: "POST",
                headers: tfHeaders,
                body: JSON.stringify({ query: "search_ioc", search_term: value })
              });
              const tfData = await tfResp.json();

              if (tfData.query_status === "ok" && tfData.data && tfData.data.length > 0) {
                // Shape the response for the frontend — pick the most useful fields
                results.threatfox = {
                  found: true,
                  iocs: tfData.data.map(ioc => ({
                    id:               ioc.id,
                    ioc:              ioc.ioc,
                    ioc_type:         ioc.ioc_type,
                    threat_type:      ioc.threat_type,
                    threat_type_desc: ioc.threat_type_desc,
                    malware:          ioc.malware,
                    malware_printable: ioc.malware_printable,
                    malware_alias:    ioc.malware_alias,
                    malware_malpedia: ioc.malware_malpedia,
                    confidence_level: ioc.confidence_level,
                    first_seen:       ioc.first_seen,
                    last_seen:        ioc.last_seen,
                    reporter:         ioc.reporter,
                    reference:        ioc.reference,
                    tags:             ioc.tags || []
                  }))
                };
              } else if (tfData.query_status === "no_result") {
                results.threatfox = { found: false };
              } else {
                results.threatfox = { error: tfData.query_status || "ThreatFox error" };
              }
            } catch (err) {
              results.threatfox = { error: err.message };
            }
          })()
        );
      }

      // ── URLHAUS — malware URL / host / hash lookup ────────────────────────
      // URLhaus bulk API: POST to https://urlhaus-api.abuse.ch/v1/
      // Endpoints: /url/ (lookup by URL), /host/ (by IP or domain), /payload/ (by hash)
      if (type === "url" || type === "domain" || type === "ip" || type === "hash") {
        fastPromises.push(
          (async () => {
            try {
              const uhHeaders = { "Content-Type": "application/x-www-form-urlencoded" };
              if (abusechKey) uhHeaders["Auth-Key"] = abusechKey;

              let uhEndpoint = "";
              let uhBody = "";

              if (type === "url") {
                uhEndpoint = "https://urlhaus-api.abuse.ch/v1/url/";
                uhBody = `url=${encodeURIComponent(value)}`;
              } else if (type === "domain" || type === "ip") {
                uhEndpoint = "https://urlhaus-api.abuse.ch/v1/host/";
                // For domains: use base domain; for IPs: use as-is
                const host = type === "domain" ? extractBaseDomain(value) : value;
                uhBody = `host=${encodeURIComponent(host)}`;
              } else if (type === "hash") {
                uhEndpoint = "https://urlhaus-api.abuse.ch/v1/payload/";
                // URLhaus accepts both md5 and sha256 — detect by length
                const hashField = value.length === 32 ? "md5_hash" : "sha256_hash";
                uhBody = `${hashField}=${encodeURIComponent(value)}`;
              }

              const uhResp = await fetch(uhEndpoint, {
                method: "POST",
                headers: uhHeaders,
                body: uhBody
              });
              const uhData = await uhResp.json();

              if (uhData.query_status === "ok" || uhData.query_status === "is_host") {
                results.urlhaus = {
                  found: true,
                  query_status:   uhData.query_status,
                  urlhaus_ref:    uhData.urlhaus_reference || null,
                  url_status:     uhData.url_status || null,
                  threat:         uhData.threat || null,
                  date_added:     uhData.date_added || null,
                  tags:           uhData.tags || [],
                  blacklists:     uhData.blacklists || {},
                  // For host lookups — list of associated malware URLs
                  urls:           (uhData.urls || []).slice(0, 10).map(u => ({
                    url:        u.url,
                    url_status: u.url_status,
                    threat:     u.threat,
                    date_added: u.date_added,
                    tags:       u.tags || []
                  })),
                  // For hash lookups — payload details
                  file_type:      uhData.file_type || null,
                  file_size:      uhData.file_size || null,
                  md5_hash:       uhData.md5_hash || null,
                  sha256_hash:    uhData.sha256_hash || null,
                  signature:      uhData.signature || null
                };
              } else if (uhData.query_status === "no_results") {
                results.urlhaus = { found: false };
              } else {
                results.urlhaus_lookup = { error: uhData.query_status || "URLhaus error" };
              }
            } catch (err) {
              results.urlhaus = { error: err.message };
            }
          })()
        );
      }

      // ── MALWAREBAZAAR — hash lookup (hashes only) ─────────────────────────
      if (type === "hash") {
        fastPromises.push(
          (async () => {
            try {
              const mbHeaders = { "Content-Type": "application/x-www-form-urlencoded" };
              if (abusechKey) mbHeaders["Auth-Key"] = abusechKey;

              const mbResp = await fetch("https://mb-api.abuse.ch/api/v1/", {
                method: "POST",
                headers: mbHeaders,
                body: `query=get_info&hash=${encodeURIComponent(value)}`
              });
              const mbData = await mbResp.json();

              if (mbData.query_status === "ok" && mbData.data && mbData.data.length > 0) {
                const sample = mbData.data[0];
                results.malwarebazaar = {
                  found:          true,
                  sha256:         sample.sha256_hash,
                  md5:            sample.md5_hash,
                  sha1:           sample.sha1_hash,
                  file_name:      sample.file_name,
                  file_size:      sample.file_size,
                  file_type:      sample.file_type_mime,
                  file_type_desc: sample.file_type,
                  malware_family: sample.signature,
                  tags:           sample.tags || [],
                  first_seen:     sample.first_seen,
                  last_seen:      sample.last_seen,
                  reporter:       sample.reporter,
                  origin_country: sample.origin_country,
                  intelligence:   sample.intelligence || {},
                  vendor_intel:   sample.vendor_intel || {},
                  bazaar_ref:     `https://bazaar.abuse.ch/sample/${sample.sha256_hash}/`
                };
              } else if (mbData.query_status === "hash_not_found") {
                results.malwarebazaar = { found: false };
              } else if (mbData.query_status === "no_api_key") {
                results.malwarebazaar = { error: "abuse.ch Auth-Key required — add it in Settings" };
              } else if (mbData.query_status === "illegal_hash") {
                results.malwarebazaar = { error: "Invalid hash format — MalwareBazaar requires MD5, SHA1, or SHA256" };
              } else {
                results.malwarebazaar = { error: `MalwareBazaar: ${mbData.query_status || "unknown error"}` };
              }
            } catch (err) {
              results.malwarebazaar = { error: err.message };
            }
          })()
        );
      }

      // Execute fast API calls in parallel (no polling)
      await Promise.all(fastPromises);

      // URLSCAN — POST /scan then poll GET /result/{scanId}/
      // Both endpoints require the API-Key header (per urlscan docs).
      // Worker calls urlscan directly — no CORS proxy needed.
      if ((type === "url" || type === "domain") && urlscanKey) {
        try {
          const scanUrl = value.startsWith("http") ? value : "https://" + value;

          // Step 1: POST /api/v1/scan — requires API-Key
          const submitResp = await fetch("https://urlscan.io/api/v1/scan/", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "API-Key": urlscanKey
            },
            body: JSON.stringify({ url: scanUrl, visibility: "public" })
          });

          if (!submitResp.ok) {
            const errBody = await submitResp.json().catch(() => ({}));
            throw new Error(`URLScan submit failed (HTTP ${submitResp.status}): ${errBody.message || submitResp.statusText}`);
          }

          const submitData = await submitResp.json();
          const scanId = submitData?.uuid;
          if (!scanId) throw new Error("URLScan returned no UUID.");
          console.log("URLScan submitted, scanId:", scanId);

          // Step 2: Poll GET /api/v1/result/{scanId}/ — also requires API-Key
          // Docs recommend: wait 10s, then poll every 2s.
          // Free Worker CPU limit ~30s: 10s init + 4x2s = 18s — well within budget.
          const sleep = ms => new Promise(r => setTimeout(r, ms));
          await sleep(10000); // recommended 10s initial wait

          let finalResult = null;
          for (let attempt = 1; attempt <= 8; attempt++) {
            console.log(`URLScan poll ${attempt}/8 for ${scanId}`);
            try {
              const pollResp = await fetch(
                `https://urlscan.io/api/v1/result/${scanId}/`,
                {
                  headers: {
                    "API-Key": urlscanKey,  // required — GET /result needs auth too
                    "Accept": "application/json"
                  }
                }
              );

              if (pollResp.status === 200) {
                finalResult = await pollResp.json();
                console.log("URLScan complete on attempt", attempt);
                break;
              }
              if (pollResp.status === 404) {
                // Still processing — poll every 2s per docs recommendation
                if (attempt < 8) await sleep(2000);
                continue;
              }
              console.warn("URLScan unexpected poll status:", pollResp.status);
              if (attempt < 8) await sleep(2000);
            } catch (pollErr) {
              console.warn("URLScan poll error:", pollErr?.message);
              if (attempt < 8) await sleep(2000);
            }
          }

          if (finalResult) {
            results.urlscan = finalResult;
          } else {
            // Still pending after budget — return scanId for frontend to continue
            results.urlscan = {
              status: "pending",
              uuid: scanId,
              resultUrl: `https://urlscan.io/result/${scanId}/`,
              message: "Scan submitted. Frontend will continue polling via Worker."
            };
          }

        } catch (err) {
          results.urlscan = { error: err.message };
        }
      } else if (type === "url" || type === "domain") {
        results.urlscan = { error: "URLSCAN_KEY not configured" };
      }

      // Return aggregated response
      return json({
        ioc: value,
        type: type,
        virustotal:    results.virustotal    || null,
        abuseipdb:     results.abuseipdb     || null,
        urlscan:       results.urlscan       || null,
        whois:         results.whois         || null,
        threatfox:     results.threatfox     || null,
        urlhaus:       results.urlhaus       || null,
        malwarebazaar: results.malwarebazaar || null
      });

    } catch (err) {
      return json({ error: err.message }, 500);
    }
  }
};

// Extract registrable base domain from a hostname (strips subdomains incl. www)
// Needed because APILayer WHOIS rejects subdomains like www.example.com
function extractBaseDomain(hostname) {
  // Strip www. prefix
  if (hostname.startsWith("www.")) hostname = hostname.slice(4);

  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;

  // Handle compound country-code TLDs: co.uk, com.au, org.br, etc.
  const ccTLDs = ["co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"];
  if (ccTLDs.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// Detect IOC type from value
function detectIOCType(value) {
  value = value.trim();
  
  // URL detection
  if (/^https?:\/\//i.test(value)) {
    return "url";
  }
  
  // IPv4 detection
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
    return "ip";
  }
  
  // IPv6 detection
  if (/^([a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i.test(value)) {
    return "ip";
  }
  
  // Hash detection (MD5, SHA1, SHA256)
  if (/^[a-f0-9]{32}$/i.test(value)) return "hash";
  if (/^[a-f0-9]{40}$/i.test(value)) return "hash";
  if (/^[a-f0-9]{64}$/i.test(value)) return "hash";
  
  // Domain detection
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(value)) {
    return "domain";
  }
  
  return "unknown";
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-VT-API-Key, X-AbuseIPDB-Key, X-Whois-Key, X-URLScan-Key, X-AbuseCH-Key"
    }
  });
}
