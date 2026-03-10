# ThreatScan Investigator

A powerful threat intelligence investigation tool that combines data from [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com) APIs for comprehensive security analysis.

## Features

- **VirusTotal Integration**: Query IP addresses, domains, URLs, and file hashes
  - Detection statistics and engine-by-engine results
  - Sandbox verdicts from multiple vendors
  - Threat labels and popularity rankings
  - Community voting data
  - Full raw JSON data export

- **AbuseIPDB Integration**: Check IP reputation and abuse history
  - Abuse confidence score
  - Reported threats and categories
  - Network information (ISP, ASN, geo)

- **Combined View**: Cross-reference data from both sources

- **Export Options**: Download results as CSV or plain text reports

- **User-Friendly Interface**:
  - Split-view layout (input left, results right)
  - Dark theme optimized for security analysts
  - Auto-detect IOC type
  - Recent scans history
  - Collapsible result cards

## Getting Started

### 1. Get API Keys

**VirusTotal API Key:**
1. Go to [virustotal.com](https://www.virustotal.com)
2. Create a free account
3. Go to your profile settings
4. Copy your API key

**AbuseIPDB API Key:**
1. Go to [AbuseIPDB](https://www.abuseipdb.com)
2. Create a free account
3. Navigate to API section
4. Copy your API key

### 2. Host on GitHub Pages

1. **Create a GitHub Repository:**
   - Go to [github.com](https://github.com) and sign in
   - Click "New repository"
   - Name it `threatscan` (or any name you prefer)
   - Select "Public"
   - Click "Create repository"

2. **Upload the Files:**
   - Click "uploading an existing file"
   - Drag and drop `index.html` and `README.md`
   - Click "Commit changes"

3. **Enable GitHub Pages:**
   - Go to repository Settings
   - Click "Pages" in the left sidebar
   - Under "Build and deployment" > "Branch":
     - Select `main` (or `master`)
     - Select `/ (root)` 
     - Click "Save"
   - Wait 1-2 minutes for deployment

4. **Access Your Site:**
   - Your site will be available at: `https://yourusername.github.io/threatscan/`

### 3. Configure API Keys

1. Open your deployed site
2. Click the "Settings" button in the header
3. Enter your VirusTotal API key
4. Enter your AbuseIPDB API key
5. Click "Save Keys"

The keys are stored locally in your browser (localStorage) - they are never sent to any server except the official VirusTotal and AbuseIPDB APIs.

## Usage

1. **Enter an IOC**: Type a URL, IP address, domain, or file hash (MD5/SHA1/SHA256)
2. **Select Type**: Choose "Auto-detect" or manually specify the type
3. **Click Scan**: The tool will query both APIs
4. **View Results**: Switch between tabs to see detailed data
5. **Export**: Download reports in CSV or TXT format

## Supported IOC Types

| Type | Example |
|------|---------|
| URL | `https://example.com` |
| IP | `8.8.8.8` or `2001:4860:4860::8888` |
| Domain | `example.com` |
| Hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Browser Compatibility

- Chrome (latest)
- Firefox (latest)
- Edge (latest)
- Safari (latest)

## Security Notes

- API keys are stored only in your browser's localStorage
- All API calls go directly from your browser to the official APIs
- No data is sent to any third-party servers
- Remember to protect your API keys - don't share screenshots with keys visible

## License

MIT License - Feel free to use and modify for your needs.

---

Built for security analysts, by security analysts. 🛡️
