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
      
      // Perform DNS resolution for domains and URLs
      if ((type === "domain" || type === "url") && domainToResolve && abuseipdbKey) {
        try {
          // Use DNS over HTTPS to resolve domain to IP
          const dnsResponse = await fetch(`https://dns.google/resolve?name=${domainToResolve}&type=A`);
          const dnsData = await dnsResponse.json();
          if (dnsData.Answer && dnsData.Answer.length > 0) {
            // Find first A record (IPv4)
            const aRecord = dnsData.Answer.find(r => r.type === 1);
            if (aRecord) {
              resolvedIp = aRecord.data;
            }
          }
        } catch (err) {
          // DNS resolution failed, continue without AbuseIPDB
        }
      }

      // VIRUSTOTAL - supports IP, domain, URL
      if (type === "ip" || type === "domain" || type === "url") {
        let vtEndpoint = "";

        if (type === "ip") {
          vtEndpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
        } else if (type === "domain") {
          vtEndpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
        } else if (type === "url") {
          // Encode URL for VT (base64 without padding)
          const encoded = btoa(value);
          vtEndpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`;
        }

        if (vtApiKey) {
          try {
            const vt = await fetch(vtEndpoint, {
              headers: {
                "x-apikey": vtApiKey
              }
            });
            results.virustotal = await vt.json();
          } catch (err) {
            results.virustotal = { error: err.message };
          }
        } else {
          results.virustotal = { error: "VT_API_KEY not configured" };
        }
      }

      // ABUSEIPDB - supports IP addresses (and domains/URLs via DNS resolution)
      if (type === "ip" || (type === "domain" && resolvedIp) || (type === "url" && resolvedIp)) {
        const ipToCheck = type === "ip" ? value : resolvedIp;
        
        if (abuseipdbKey) {
          try {
            const abuse = await fetch(
              `https://api.abuseipdb.com/api/v2/check?ipAddress=${ipToCheck}&maxAgeInDays=90`,
              {
                headers: {
                  Key: abuseipdbKey,
                  Accept: "application/json"
                }
              }
            );
            const abuseData = await abuse.json();
            // Add resolved domain info if we resolved an IP
            if ((type === "domain" || type === "url") && resolvedIp) {
              abuseData.resolvedFrom = type === "url" ? new URL(value).hostname : value;
              abuseData.resolvedIp = resolvedIp;
            }
            results.abuseipdb = abuseData;
          } catch (err) {
            results.abuseipdb = { error: err.message };
          }
        } else {
          results.abuseipdb = { error: "ABUSEIPDB_KEY not configured" };
        }
      }

      // WHOIS - supports domains and URLs (by extracting domain)
      if (type === "domain" || type === "url") {
        const domainForWhois = type === "url" ? domainToResolve : value;
        
        console.log("WHOIS lookup - type:", type, "domain:", domainForWhois, "hasKey:", !!whoisApiKey);
        
        if (whoisApiKey && domainForWhois) {
          try {
            const whois = await fetch(
              `https://api.apilayer.com/whois/query?domain=${encodeURIComponent(domainForWhois)}`,
              {
                headers: {
                  "APIKEY": whoisApiKey
                }
              }
            );
            const whoisData = await whois.json();
            console.log("WHOIS response status:", whois.status, "data:", whoisData);
            // APILayer returns data in { result: {...} } format, extract it
            results.whois = whoisData.result || whoisData;
          } catch (err) {
            console.error("WHOIS fetch error:", err);
            results.whois = { error: err.message };
          }
        } else if (!domainForWhois) {
          results.whois = { error: "Could not extract domain from URL" };
        } else {
          results.whois = { error: "WHOIS_API_KEY not configured" };
        }
      }

      // URLSCAN - supports URLs and domains
      if (type === "url" || type === "domain") {
        if (urlscanKey) {
          try {
            // First, submit the scan
            const urlscan = await fetch(
              "https://urlscan.io/api/v1/scan/",
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "API-Key": urlscanKey
                },
                body: JSON.stringify({
                  url: value,
                  visibility: "public"
                })
              }
            );
            const scanResult = await urlscan.json();
            
            // If scan was submitted, get the result
            if (scanResult.uuid) {
              // Wait for the scan to complete
              await new Promise(resolve => setTimeout(resolve, 2000));
              
              const resultResponse = await fetch(
                `https://urlscan.io/api/v1/result/${scanResult.uuid}/`,
                {
                  headers: {
                    "API-Key": urlscanKey,
                    "Accept": "application/json"
                  }
                }
              );
              results.urlscan = await resultResponse.json();
            } else {
              results.urlscan = scanResult;
            }
          } catch (err) {
            results.urlscan = { error: err.message };
          }
        } else {
          results.urlscan = { error: "URLSCAN_KEY not configured" };
        }
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
