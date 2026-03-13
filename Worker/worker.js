export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const value = url.searchParams.get("value");

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

        if (env.VT_API_KEY) {
          try {
            const vt = await fetch(vtEndpoint, {
              headers: {
                "x-apikey": env.VT_API_KEY
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

      // ABUSEIPDB - only supports IP addresses
      if (type === "ip") {
        if (env.ABUSEIPDB_KEY) {
          try {
            const abuse = await fetch(
              `https://api.abuseipdb.com/api/v2/check?ipAddress=${value}&maxAgeInDays=90`,
              {
                headers: {
                  Key: env.ABUSEIPDB_KEY,
                  Accept: "application/json"
                }
              }
            );
            results.abuseipdb = await abuse.json();
          } catch (err) {
            results.abuseipdb = { error: err.message };
          }
        } else {
          results.abuseipdb = { error: "ABUSEIPDB_KEY not configured" };
        }
      }

      // WHOIS - only supports domains
      if (type === "domain") {
        if (env.WHOIS_API_KEY) {
          try {
            const whois = await fetch(
              `https://api.apilayer.com/whois/query?domain=${value}`,
              {
                headers: {
                  apikey: env.WHOIS_API_KEY
                }
              }
            );
            results.whois = await whois.json();
          } catch (err) {
            results.whois = { error: err.message };
          }
        } else {
          results.whois = { error: "WHOIS_API_KEY not configured" };
        }
      }

      // URLSCAN - supports URLs and domains
      if (type === "url" || type === "domain") {
        if (env.URLSCAN_KEY) {
          try {
            // First, submit the scan
            const urlscan = await fetch(
              "https://urlscan.io/api/v1/scan/",
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "API-Key": env.URLSCAN_KEY
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
                    "API-Key": env.URLSCAN_KEY,
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
      "Access-Control-Allow-Origin": "*"
    }
  });
}
