# Threat Intelligence Investigation Tool - Specification

## 1. Project Overview

**Project Name:** ThreatScan Investigator  
**Type:** Single-page Web Application (Static HTML/CSS/JS)  
**Core Functionality:** A threat intelligence investigation tool that queries VirusTotal and AbuseIPDB APIs to gather and display comprehensive security data for URLs, domains, IP addresses, and file hashes.  
**Target Users:** Security analysts, threat researchers, SOC analysts, and incident responders who need quick access to threat intelligence data.

---

## 2. Technical Architecture

### Hosting
- **Platform:** GitHub Pages (static site)
- **Files:** Single HTML file with embedded CSS and JavaScript
- **No server required:** All API calls made directly from client browser

### API Integrations

#### VirusTotal API v3
- **Endpoint:** `https://www.virustotal.com/api/v3/`
- **Supported lookups:**
  - IP addresses: `/ip_addresses/{ip}`
  - Domains: `/domains/{domain}`
  - URLs: `/urls/{url_id}` (requires URL scan first)
  - Files: `/files/{hash}`
- **Key fields to display:**
  - Last analysis stats (malicious, suspicious, undetected, harmless, timeout, confirmed-timeout, failure, type-unsupported)
  - Engine results (all vendor detections)
  - Popularity/Ranking data
  - Community vote
  - Threat labels
  - Sandbox verdicts
  - File details (size, type, PE headers, etc.)
  - WHOIS data (when available)
  - Related objects (URLs, domains, referring domains)

#### AbuseIPDB API
- **Endpoint:** `https://api.abuseipdb.com/api/v2/`
- **Supported lookups:****
  - Search: `/search/?q={query}`
  - Result: `/result/{uuid}/`
  - Screenshot: `/result/{uuid}/screenshot.png`
- **Key fields to display:**
  - Screenshot (full page)
  - Page URL and domain
  - IP addresses (server and client)
  - ASN and geo-location
  - HTTP requests/timeline
  - Links (external, domains, URLs)
  - Cookies
  - Scripts
  - Local storage
  - SSL certificate details
  - Server type
  - Meta tags
  - Domain summary (whois, registrar)

---

## 3. UI/UX Specification

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│  HEADER: Logo + Title + API Key Configuration                   │
├────────────────────────┬────────────────────────────────────────┤
│                        │                                         │
│   INPUT PANEL          │   RESULTS PANEL                        │
│   (Left - 35%)         │   (Right - 65%)                        │
│                        │                                         │
│   - IOC Input          │   - Tab: VirusTotal Results            │
│   - Scan Type          │   - Tab: AbuseIPDB Results            │
│   - Scan Button        │   - Tab: Combined View                 │
│   - Recent Scans       │                                        │
│                        │   Each tab shows:                      │
│                        │   - Summary cards                       │
│                        │   - Detailed data tables                │
│                        │   - Export buttons                      │
│                        │                                         │
├────────────────────────┴────────────────────────────────────────┤
│  FOOTER: Credits + Version                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Visual Design

**Color Palette:**
- Primary Background: `#0d1117` (GitHub dark)
- Secondary Background: `#161b22` (card backgrounds)
- Border/Accent: `#30363d` (subtle borders)
- Primary Text: `#e6edf3` (high contrast)
- Secondary Text: `#8b949e` (muted)
- Accent Blue: `#58a6ff` (links, buttons)
- Success Green: `#3fb950` (safe/clean results)
- Warning Yellow: `#d29922` (suspicious)
- Danger Red: `#f85149` (malicious detections)
- Info Purple: `#a371f7` (informational)

**Typography:**
- Font Family: `"JetBrains Mono", "Fira Code", monospace` (tech/cyber aesthetic)
- Headings: `"Segoe UI", system-ui, sans-serif`
- Font Sizes:
  - H1: 24px
  - H2: 18px
  - Body: 14px
  - Small/Labels: 12px

**Spacing:**
- Base unit: 8px
- Card padding: 16px
- Section gaps: 24px
- Border radius: 6px

**Visual Effects:**
- Cards: subtle box-shadow `0 1px 3px rgba(0,0,0,0.3)`
- Hover states: background lighten 5%
- Loading: pulsing skeleton screens
- Results: fade-in animation (200ms)

### Components

**1. Header Bar**
- Logo: Shield icon (SVG)
- Title: "ThreatScan Investigator"
- API Key toggle button (shows modal for key entry)

**2. Input Panel (Left Sidebar)**
- IOC Input: Large text area for URL, IP, domain, or hash
- Scan Type selector: Auto-detect / URL / IP / Domain / Hash
- "Scan" button (primary action)
- Recent scans list (last 10, clickable)

**3. Results Panel (Main Area)**
- Tab navigation: VirusTotal | AbuseIPDB | Combined
- Each result in collapsible cards:
  - **Summary Card:** Key stats (detection ratio, country, etc.)
  - **Details Card:** Full data in scrollable table
  - **Raw Data Card:** JSON view (expandable)

**4. Export Section**
- Buttons: "Export CSV" | "Export TXT"
- Downloads file with timestamp in filename

**5. API Key Modal**
- Input field for VirusTotal API key
- Input field for AbuseIPDB API key
- "Save Keys" button (stored in localStorage)
- "Clear Keys" button

---

## 4. Functionality Specification

### Core Features

**F1: API Key Management**
- Store keys in localStorage (encrypted base64)
- Validate key format on entry
- Show key masked in UI with edit option
- Clear keys option

**F2: IOC Input Processing**
- Accept: URLs, IPv4/IPv6, domains, MD5/SHA1/SHA256
- Auto-detect input type using regex patterns
- Normalize URL format (add https:// if missing)

**F3: VirusTotal Integration**
- Query appropriate endpoint based on IOC type
- Display all analysis results in organized tables
- Show detection ratio as visual progress bar
- List all engine detections with details
- Show related IOCs (referring domains, etc.)

**F4: AbuseIPDB Integration**
- Query IP address information
- Display abuse confidence score
- Show reported threats and categories
- List recent reports
- Extract and list all IOCs (IPs, domains, URLs)
- Show HTTP timeline as table

**F5: Combined View**
- Merge relevant data from both sources
- Highlight matching IOCs
- Show correlation summary

**F6: Export Functionality**
- CSV format: Structured table with all fields
- Plain text: Human-readable formatted output
- Filename format: `threatscan_{ioc}_{timestamp}.csv/txt`

### User Interactions

1. **First use:** User enters API keys in settings
2. **Enter IOC:** Paste URL/hash/IP in input field
3. **Click Scan:** System queries both APIs
4. **View Results:** Switch between tabs to see detailed data
5. **Export:** Click export button to download results

### Edge Cases
- Invalid API key: Show error message with instructions
- Rate limiting: Display warning, suggest waiting
- No results found: Show "No data available" message
- Network error: Show retry button
- Large data sets: Paginate or virtualize tables

---

## 5. File Structure

```
phising/
├── index.html          # Main application (single file)
├── SPEC.md             # This specification
└── README.md           # Setup instructions for GitHub Pages
```

---

## 6. Acceptance Criteria

1. ✅ Page loads without errors on GitHub Pages
2. ✅ API keys can be saved and persist across sessions
3. ✅ IOC input correctly detects type (URL/IP/domain/hash)
4. ✅ VirusTotal API returns and displays all relevant fields
5. ✅ AbuseIPDB API returns and displays IP reputation data
6. ✅ Results display in organized, readable format
7. ✅ CSV export produces valid, complete CSV file
8. ✅ Plain text export produces readable formatted output
9. ✅ UI is responsive and works on different screen sizes
10. ✅ Error states are handled gracefully with user feedback
=======
# Threat Intelligence Investigation Tool - Specification

## 1. Project Overview

**Project Name:** ThreatScan Investigator  
**Type:** Single-page Web Application (Static HTML/CSS/JS)  
**Core Functionality:** A threat intelligence investigation tool that queries VirusTotal and AbuseIPDB APIs to gather and display comprehensive security data for URLs, domains, IP addresses, and file hashes.  
**Target Users:** Security analysts, threat researchers, SOC analysts, and incident responders who need quick access to threat intelligence data.

---

## 2. Technical Architecture

### Hosting
- **Platform:** GitHub Pages (static site)
- **Files:** Single HTML file with embedded CSS and JavaScript
- **No server required:** All API calls made directly from client browser

### API Integrations

#### VirusTotal API v3
- **Endpoint:** `https://www.virustotal.com/api/v3/`
- **Supported lookups:**
  - IP addresses: `/ip_addresses/{ip}`
  - Domains: `/domains/{domain}`
  - URLs: `/urls/{url_id}` (requires URL scan first)
  - Files: `/files/{hash}`
- **Key fields to display:**
  - Last analysis stats (malicious, suspicious, undetected, harmless, timeout, confirmed-timeout, failure, type-unsupported)
  - Engine results (all vendor detections)
  - Popularity/Ranking data
  - Community vote
  - Threat labels
  - Sandbox verdicts
  - File details (size, type, PE headers, etc.)
  - WHOIS data (when available)
  - Related objects (URLs, domains, referring domains)

#### AbuseIPDB API
- **Endpoint:** `https://api.abuseipdb.com/api/v2/`
- **Supported lookups:****
  - Search: `/search/?q={query}`
  - Result: `/result/{uuid}/`
  - Screenshot: `/result/{uuid}/screenshot.png`
- **Key fields to display:**
  - Screenshot (full page)
  - Page URL and domain
  - IP addresses (server and client)
  - ASN and geo-location
  - HTTP requests/timeline
  - Links (external, domains, URLs)
  - Cookies
  - Scripts
  - Local storage
  - SSL certificate details
  - Server type
  - Meta tags
  - Domain summary (whois, registrar)

---

## 3. UI/UX Specification

### Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│  HEADER: Logo + Title + API Key Configuration                   │
├────────────────────────┬────────────────────────────────────────┤
│                        │                                         │
│   INPUT PANEL          │   RESULTS PANEL                        │
│   (Left - 35%)         │   (Right - 65%)                        │
│                        │                                         │
│   - IOC Input          │   - Tab: VirusTotal Results            │
│   - Scan Type          │   - Tab: AbuseIPDB Results            │
│   - Scan Button        │   - Tab: Combined View                 │
│   - Recent Scans       │                                        │
│                        │   Each tab shows:                      │
│                        │   - Summary cards                       │
│                        │   - Detailed data tables                │
│                        │   - Export buttons                      │
│                        │                                         │
├────────────────────────┴────────────────────────────────────────┤
│  FOOTER: Credits + Version                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Visual Design

**Color Palette:**
- Primary Background: `#0d1117` (GitHub dark)
- Secondary Background: `#161b22` (card backgrounds)
- Border/Accent: `#30363d` (subtle borders)
- Primary Text: `#e6edf3` (high contrast)
- Secondary Text: `#8b949e` (muted)
- Accent Blue: `#58a6ff` (links, buttons)
- Success Green: `#3fb950` (safe/clean results)
- Warning Yellow: `#d29922` (suspicious)
- Danger Red: `#f85149` (malicious detections)
- Info Purple: `#a371f7` (informational)

**Typography:**
- Font Family: `"JetBrains Mono", "Fira Code", monospace` (tech/cyber aesthetic)
- Headings: `"Segoe UI", system-ui, sans-serif`
- Font Sizes:
  - H1: 24px
  - H2: 18px
  - Body: 14px
  - Small/Labels: 12px

**Spacing:**
- Base unit: 8px
- Card padding: 16px
- Section gaps: 24px
- Border radius: 6px

**Visual Effects:**
- Cards: subtle box-shadow `0 1px 3px rgba(0,0,0,0.3)`
- Hover states: background lighten 5%
- Loading: pulsing skeleton screens
- Results: fade-in animation (200ms)

### Components

**1. Header Bar**
- Logo: Shield icon (SVG)
- Title: "ThreatScan Investigator"
- API Key toggle button (shows modal for key entry)

**2. Input Panel (Left Sidebar)**
- IOC Input: Large text area for URL, IP, domain, or hash
- Scan Type selector: Auto-detect / URL / IP / Domain / Hash
- "Scan" button (primary action)
- Recent scans list (last 10, clickable)

**3. Results Panel (Main Area)**
- Tab navigation: VirusTotal | AbuseIPDB | Combined
- Each result in collapsible cards:
  - **Summary Card:** Key stats (detection ratio, country, etc.)
  - **Details Card:** Full data in scrollable table
  - **Raw Data Card:** JSON view (expandable)

**4. Export Section**
- Buttons: "Export CSV" | "Export TXT"
- Downloads file with timestamp in filename

**5. API Key Modal**
- Input field for VirusTotal API key
- Input field for AbuseIPDB API key
- "Save Keys" button (stored in localStorage)
- "Clear Keys" button

---

## 4. Functionality Specification

### Core Features

**F1: API Key Management**
- Store keys in localStorage (encrypted base64)
- Validate key format on entry
- Show key masked in UI with edit option
- Clear keys option

**F2: IOC Input Processing**
- Accept: URLs, IPv4/IPv6, domains, MD5/SHA1/SHA256
- Auto-detect input type using regex patterns
- Normalize URL format (add https:// if missing)

**F3: VirusTotal Integration**
- Query appropriate endpoint based on IOC type
- Display all analysis results in organized tables
- Show detection ratio as visual progress bar
- List all engine detections with details
- Show related IOCs (referring domains, etc.)

**F4: AbuseIPDB Integration**
- Query IP address information
- Display abuse confidence score
- Show reported threats and categories
- List recent reports
- Extract and list all IOCs (IPs, domains, URLs)
- Show HTTP timeline as table

**F5: Combined View**
- Merge relevant data from both sources
- Highlight matching IOCs
- Show correlation summary

**F6: Export Functionality**
- CSV format: Structured table with all fields
- Plain text: Human-readable formatted output
- Filename format: `threatscan_{ioc}_{timestamp}.csv/txt`

### User Interactions

1. **First use:** User enters API keys in settings
2. **Enter IOC:** Paste URL/hash/IP in input field
3. **Click Scan:** System queries both APIs
4. **View Results:** Switch between tabs to see detailed data
5. **Export:** Click export button to download results

### Edge Cases
- Invalid API key: Show error message with instructions
- Rate limiting: Display warning, suggest waiting
- No results found: Show "No data available" message
- Network error: Show retry button
- Large data sets: Paginate or virtualize tables

---

## 5. File Structure

```
phising/
├── index.html          # Main application (single file)
├── SPEC.md             # This specification
└── README.md           # Setup instructions for GitHub Pages
```

---

## 6. Acceptance Criteria

1. ✅ Page loads without errors on GitHub Pages
2. ✅ API keys can be saved and persist across sessions
3. ✅ IOC input correctly detects type (URL/IP/domain/hash)
4. ✅ VirusTotal API returns and displays all relevant fields
5. ✅ AbuseIPDB API returns and displays IP reputation data
6. ✅ Results display in organized, readable format
7. ✅ CSV export produces valid, complete CSV file
8. ✅ Plain text export produces readable formatted output
9. ✅ UI is responsive and works on different screen sizes
10. ✅ Error states are handled gracefully with user feedback
>>>>>>> 13a2e2182bbcb5a9590e9b75f0d522377b6505d6
