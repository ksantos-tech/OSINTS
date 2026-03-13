export default {
  async fetch(request, env) {

    const url = new URL(request.url)
    const type = url.searchParams.get("type")
    const value = url.searchParams.get("value")

    if (!type || !value) {
      return json({ error: "Missing parameters" }, 400)
    }

    try {

      let results = {}

      // VIRUSTOTAL
      if (type === "ip" || type === "domain" || type === "url" || type === "hash") {

        let vtEndpoint = ""

        if (type === "ip") vtEndpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`
        if (type === "domain") vtEndpoint = `https://www.virustotal.com/api/v3/domains/${value}`
        if (type === "hash") vtEndpoint = `https://www.virustotal.com/api/v3/files/${value}`

        if (type === "url") {
          const encoded = btoa(value)
          vtEndpoint = `https://www.virustotal.com/api/v3/urls/${encoded}`
        }

        const vt = await fetch(vtEndpoint, {
          headers: {
            "x-apikey": env.VT_API_KEY
          }
        })

        results.virustotal = await vt.json()
      }

      // ABUSEIPDB
      if (type === "ip") {

        const abuse = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${value}&maxAgeInDays=90`,
          {
            headers: {
              Key: env.ABUSEIPDB_API_KEY,
              Accept: "application/json"
            }
          }
        )

        results.abuseipdb = await abuse.json()
      }

      // WHOIS
      if (type === "domain") {

        const whois = await fetch(
          `https://api.apilayer.com/whois/query?domain=${value}`,
          {
            headers: {
              apikey: env.WHOIS_API_KEY
            }
          }
        )

        results.whois = await whois.json()
      }

      // URLSCAN
      if (type === "url") {

        const urlscan = await fetch(
          "https://urlscan.io/api/v1/scan/",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "API-Key": env.URLSCAN_API_KEY
            },
            body: JSON.stringify({
              url: value,
              visibility: "public"
            })
          }
        )

        results.urlscan = await urlscan.json()
      }

      return json({
        ioc: value,
        type: type,
        results: results
      })

    } catch (err) {
      return json({ error: err.message }, 500)
    }
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  })
}