export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-VT-API-Key, X-AbuseIPDB-Key, X-Whois-Key, X-URLScan-Key"
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

    // Debug: Log which keys are available
    console.log("API Keys - VT:", !!vtApiKey, "AbuseIPDB:", !!abuseipdbKey, "WHOIS:", !!whoisApiKey, "URLScan:", !!urlscanKey);

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

      // VIRUSTOTAL - supports IP, domain, URL
      if (type === "ip" || type === "domain" || type === "url") {
        let vtEndpoint = "";
        if (type === "ip") {
          vtEndpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
        } else if (type === "domain") {
          vtEndpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
        } else if (type === "url") {
          const encoded = btoa(value);
          vtEndpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`;
        }

        if (vtApiKey) {
          fastPromises.push(
            (async () => {
              try {
                const vt = await fetch(vtEndpoint, { headers: { "x-apikey": vtApiKey } });
                results.virustotal = await vt.json();
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

      // WHOIS - supports domains and URLs (by extracting domain)
      if (type === "domain" || type === "url") {
        const domainForWhois = type === "url" ? domainToResolve : value;
        if (whoisApiKey && domainForWhois) {
          fastPromises.push(
            (async () => {
              try {
                const whois = await fetch(
                  `https://api.apilayer.com/whois/query?domain=${encodeURIComponent(domainForWhois)}`,
                  { headers: { "APIKEY": whoisApiKey } }
                );
                const whoisData = await whois.json();
                results.whois = whoisData.result || whoisData;
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

      // Execute fast API calls in parallel (no polling)
      await Promise.all(fastPromises);

      // URLSCAN - submit scan then poll until result is ready
      if ((type === "url" || type === "domain") && urlscanKey) {
        try {
          const scanUrl = value.startsWith("http") ? value : "https://" + value;

          // Step 1: Submit the scan
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
          const uuid = submitData?.uuid;

          if (!uuid) {
            throw new Error("URLScan returned no UUID after submission.");
          }

          console.log("URLScan submitted, UUID:", uuid);

          // Step 2: Poll GET /result/{uuid} until HTTP 200
          // Note: Cloudflare Workers have a 30s CPU limit on the free plan.
          // We use a short initial delay + tight loop so we stay within budget.
          // If the scan doesn't complete in time the frontend will continue
          // polling via urlscan-poller.js using the uuid we return.
          const POLL_INTERVAL_MS = 5000;
          const MAX_ATTEMPTS     = 5;   // 5 × 5s = 25s max in the Worker
          const INITIAL_DELAY_MS = 8000;

          const sleep = (ms) => new Promise(r => setTimeout(r, ms));
          await sleep(INITIAL_DELAY_MS);

          let finalResult = null;

          for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            console.log(`URLScan polling attempt ${attempt}/${MAX_ATTEMPTS} for ${uuid}`);

            try {
              const pollResp = await fetch(
                `https://urlscan.io/api/v1/result/${uuid}/`,
                { headers: { "API-Key": urlscanKey, "Accept": "application/json" } }
              );

              if (pollResp.status === 200) {
                finalResult = await pollResp.json();
                console.log("URLScan complete on attempt", attempt);
                break;
              }

              if (pollResp.status === 404) {
                // Still processing — wait and retry
                if (attempt < MAX_ATTEMPTS) {
                  await sleep(POLL_INTERVAL_MS);
                }
                continue;
              }

              if (pollResp.status === 429) {
                console.warn("URLScan rate limited, backing off...");
                await sleep(POLL_INTERVAL_MS * 2);
                continue;
              }

              console.warn("Unexpected URLScan poll status:", pollResp.status);
              await sleep(POLL_INTERVAL_MS);

            } catch (pollErr) {
              console.warn("URLScan polling fetch error:", pollErr?.message);
              await sleep(POLL_INTERVAL_MS);
            }
          }

          if (finalResult) {
            // Return the full result — frontend renderURLScan() will parse it
            results.urlscan = finalResult;
          } else {
            // Worker timed out before scan finished — return uuid so the
            // frontend poller (urlscan-poller.js) can continue waiting
            results.urlscan = {
              status: "pending",
              uuid: uuid,
              resultUrl: `https://urlscan.io/result/${uuid}/`,
              message: "Scan submitted. Frontend will continue polling."
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
        virustotal: results.virustotal || null,
        abuseipdb: results.abuseipdb || null,
        urlscan: results.urlscan || null,
        whois: results.whois || null
      });

    } catch (err) {
      return json({ error: err.message }, 500);
    }
  }
};

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
      "Access-Control-Allow-Headers": "Content-Type, X-VT-API-Key, X-AbuseIPDB-Key, X-Whois-Key, X-URLScan-Key"
    }
  });
}
