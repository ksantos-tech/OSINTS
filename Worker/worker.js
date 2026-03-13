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

    // Route: /scan/ip, /scan/domain, /scan/url
    const ipMatch = path.match(/^\/scan\/ip\/(.+)$/);
    const domainMatch = path.match(/^\/scan\/domain\/(.+)$/);
    const urlMatch = path.match(/^\/scan\/url\/(.+)$/);

    let type = null;
    let value = null;

    if (ipMatch) {
      type = "ip";
      value = decodeURIComponent(ipMatch[1]);
    } else if (domainMatch) {
      type = "domain";
      value = decodeURIComponent(domainMatch[1]);
    } else if (urlMatch) {
      type = "url";
      value = decodeURIComponent(urlMatch[1]);
    }

    if (!type || !value) {
      return json({ error: "Invalid route. Use /scan/ip/:value, /scan/domain/:value, or /scan/url/:value" }, 400);
    }

    try {
      let results = {};

      // VIRUSTOTAL
      if (type === "ip" || type === "domain" || type === "url") {
        let vtEndpoint = "";

        if (type === "ip") {
          vtEndpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
        }
        if (type === "domain") {
          vtEndpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
        }

        if (type === "url") {
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

      // ABUSEIPDB
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

      // WHOIS
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

      // URLSCAN
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
              // Wait a moment for the scan to complete
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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
