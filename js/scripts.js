// State
        let currentResults = {
            vt: null,
            abuseipdb: null,
            whois: null,
            urlscan: null,
            ioc: '',
            type: ''
        };
        let recentScans = [];
        let scanMode = 'single'; // 'single' or 'bulk'
        let bulkResults = [];
        let bulkScanProgress = 0;
        let workspaceItems = []; // Workspace items for investigation summary

        // ============================================
        // UTILITY FUNCTIONS
        // ============================================
        
        // Safe DOM element getter - returns null instead of throwing
        function $(id) {
            return document.getElementById(id);
        }
        
        // Safe innerHTML setter with null check
        function setHTML(id, html) {
            const el = $(id);
            if (el) el.innerHTML = html;
        }
        
        // Safe textContent setter
        function setText(id, text) {
            const el = $(id);
            if (el) el.textContent = text;
        }
        
        // Safe style setter
        function setStyle(id, prop, value) {
            const el = $(id);
            if (el && el.style) el.style[prop] = value;
        }
        
        // Safe event listener
        function onReady(id, callback) {
            const el = $(id);
            if (el) {
                if (document.readyState === 'complete') {
                    callback(el);
                } else {
                    window.addEventListener('load', () => callback(el));
                }
            }
        }
        
        // Safe fetch with error handling
        async function safeFetch(url, options = {}) {
            try {
                const response = await fetch(url, options);
                if (!response.ok) {
                    console.warn(`API request failed: ${response.status} ${response.statusText}`);
                    return null;
                }
                return await response.json();
            } catch (e) {
                console.error('Fetch error:', e.message);
                return null;
            }
        }
        
        // Show toast notification
        function showToast(message, type = 'info') {
            const container = $('toastContainer');
            if (!container) return;
            
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `
                <span>${message}</span>
                <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--text-muted);cursor:pointer;margin-left:auto;">×</button>
            `;
            container.appendChild(toast);
            
            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => toast.remove(), 300);
            }, 4000);
        }
        
        // Theme Management
        function initTheme() {
            const savedTheme = localStorage.getItem('threatanalyzer_theme') || 'dark';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);
        }

        function updateThemeIcon(theme) {
            const icon = document.getElementById('themeIcon');
            if (icon) {
                icon.textContent = theme === 'dark' ? '🌙' : '☀️';
            }
        }

        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('threatanalyzer_theme', newTheme);
            updateThemeIcon(newTheme);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initTheme();
            loadKeys();
            loadRecentScans();
            loadNotes();
            loadTimezonePreference();
            updateApiStatus();
            
            // Setup investigation notes autosave
            document.getElementById('investigationNotes').addEventListener('input', handleNotesInput);
            
            // Check if first time user - show welcome prompt
            const hasVisited = localStorage.getItem('threatscan_visited');
            const keys = getKeys();
            if (!hasVisited || (!keys.vt && !keys.abuse && !keys.whois)) {
                // Show welcome banner
                setTimeout(() => {
                    showWelcomeBanner();
                }, 500);
                localStorage.setItem('threatscan_visited', 'true');
            }
            
            // Auto-detect IOC type
            document.getElementById('iocInput').addEventListener('input', (e) => {
                const value = e.target.value.trim();
                if (value && document.getElementById('iocType').value === 'auto') {
                    const type = detectIOCType(value);
                    // Don't auto-select, just for reference
                }
            });
        });
        
        // Welcome Banner for new users
        function showWelcomeBanner() {
            // Create overlay
            const overlay = document.createElement('div');
            overlay.id = 'welcomeOverlay';
            overlay.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                z-index: 9999;
            `;
            
            const banner = document.createElement('div');
            banner.id = 'welcomeBanner';
            banner.style.cssText = `
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: var(--bg-secondary);
                border: 2px solid var(--accent-blue);
                border-radius: 16px;
                padding: 40px;
                z-index: 10000;
                max-width: 520px;
                text-align: center;
                box-shadow: 0 0 40px rgba(88, 166, 255, 0.4), inset 0 0 60px rgba(88, 166, 255, 0.05);
                animation: modalEnter 0.3s ease-out;
            `;
            
            banner.innerHTML = `
                <style>
                    @keyframes modalEnter {
                        from { opacity: 0; transform: translate(-50%, -50%) scale(0.95); }
                        to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
                    }
                </style>
                <div style="margin-bottom: 24px;">
                    <img src="mainlogo.png" style="width: 280px; height: 240px; margin-bottom: 12px; filter: drop-shadow(0 0 8px rgba(0,150,255,0.6));">
                    <h2 style="color: #66b3ff; margin: 0; font-size: 32px; font-weight: 700; letter-spacing: 0.5px; text-shadow: 0 0 10px rgba(0,150,255,0.4);">Welcome to ThreatAnalyzer</h2>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 24px; line-height: 1.6; font-size: 15px;">
                    Connect your threat intelligence providers by adding your API keys.
                </p>
                <div style="margin-bottom: 28px; text-align: left; background: rgba(88, 166, 255, 0.08); border-radius: 10px; padding: 16px 20px;">
                    <p style="color: var(--accent-blue); margin: 0 0 12px 0; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">What You Can Do</p>
                    <ul style="margin: 0; padding-left: 20px; color: var(--text-secondary); line-height: 1.8; font-size: 14px; list-style: none;">
                        <li> IOC Reputation Analysis</li>
                        <li> Threat Intelligence Correlation</li>
                        <li> SIEM Query Generator</li>
                        <li> Bulk IOC Investigation</li>
                        <li> Export Investigation Results</li>
                    </ul>
                </div>
                <div style="margin-bottom: 20px; text-align: left; background: rgba(34, 197, 94, 0.08); border-radius: 8px; padding: 10px 14px; border-left: 3px solid #22C55E;">
                    <p style="color: #22C55E; margin: 0 0 6px 0; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Privacy Notice</p>
                    <ul style="margin: 0; padding-left: 14px; color: var(--text-secondary); line-height: 1.5; font-size: 11px; list-style: none;">
                        <li> All analysis happens locally in your browser</li>
                        <li> No IOC data is stored or transmitted by ThreatAnalyzer</li>
                    </ul>
                </div>
                <div style="margin-bottom: 20px; text-align: left; background: rgba(59, 130, 246, 0.08); border-radius: 8px; padding: 10px 14px; border-left: 3px solid #3B82F6;">
                    <p style="color: #3B82F6; margin: 0 0 6px 0; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Recent Features</p>
                    <ul style="margin: 0; padding-left: 14px; color: var(--text-secondary); line-height: 1.5; font-size: 11px; list-style: none;">
                        <li> Bulk IOC scanning</li>
                        <li> Risk scoring engine</li>
                        <li> SIEM query generator</li>
                        <li> Combined results dashboard</li>
                    </ul>
                </div>
                <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
                    <button onclick="openSettings(); closeWelcomeBanner();" 
                        style="background: var(--accent-blue); color: white; border: none; padding: 14px 28px; border-radius: 8px; cursor: pointer; font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                         Configure API Keys
                    </button>
                    <button onclick="openFAQs(); closeWelcomeBanner();" 
                        style="background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid rgba(255,255,255,0.1); padding: 14px 28px; border-radius: 8px; cursor: pointer; font-size: 15px; opacity: 0.8;">
                         View Documentation
                    </button>
                </div>
                <p style="color: var(--text-muted); font-size: 12px; margin-top: 24px;">
                    Press ESC to close
                </p>
            `;
            
            // Close function
            window.closeWelcomeBanner = function() {
                if (overlay.parentNode) overlay.remove();
                if (banner.parentNode) banner.remove();
            };
            
            // Close on overlay click
            overlay.onclick = closeWelcomeBanner;
            
            // Close on escape key
            document.addEventListener('keydown', function closeWelcome(e) {
                if (e.key === 'Escape') {
                    closeWelcomeBanner();
                    document.removeEventListener('keydown', closeWelcome);
                }
            });
            
            document.body.appendChild(overlay);
            document.body.appendChild(banner);
        }
        
        // Keyboard Shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl+Enter to investigate
            if (e.ctrlKey && e.key === 'Enter') {
                const ioc = document.getElementById('iocInput').value.trim();
                if (ioc) {
                    investigateIOC();
                }
            }
            // Ctrl+K to focus on IOC input
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                document.getElementById('iocInput').focus();
                document.getElementById('iocInput').select();
            }
        });

        // IOC Type Detection
        function detectIOCType(ioc) {
            ioc = ioc.trim();
            
            // URL pattern
            if (/^https?:\/\//i.test(ioc) || ioc.includes('.') && !/^[a-f0-9]{32,64}$/i.test(ioc)) {
                if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) {
                    return 'ip';
                }
                return 'url';
            }
            
            // IPv6
            if (/^([a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i.test(ioc)) {
                return 'ip';
            }
            
            // IPv4
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) {
                return 'ip';
            }
            
            // Hashes
            if (/^[a-f0-9]{32}$/i.test(ioc)) return 'hash';
            if (/^[a-f0-9]{40}$/i.test(ioc)) return 'hash';
            if (/^[a-f0-9]{64}$/i.test(ioc)) return 'hash';
            
            // Domain (no protocol, just domain)
            if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(ioc)) {
                return 'domain';
            }
            
            return 'unknown';
        }

        // Scan Mode Toggle
        function setScanMode(mode) {
            scanMode = mode;
            document.querySelectorAll('.mode-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.mode === mode) {
                    btn.classList.add('active');
                }
            });
            
            const hint = document.querySelector('.bulk-hint');
            const input = document.getElementById('iocInput');
            const bulkTabBtn = document.querySelector('.bulk-tab');
            
            if (mode === 'bulk') {
                hint.style.display = 'block';
                input.placeholder = 'Enter one IOC per line\n8.8.8.8\n1.1.1.1\nmalicious.com';
                if (bulkTabBtn) bulkTabBtn.style.display = 'inline-flex';
                // Switch to bulk tab when entering bulk mode
                switchTab('bulk');
            } else {
                hint.style.display = 'none';
                input.placeholder = 'Enter URL, IP, Domain, or Hash (MD5/SHA1/SHA256)';
                if (bulkTabBtn) bulkTabBtn.style.display = 'none';
                // Switch back to vt tab when leaving bulk mode
                switchTab('vt');
            }
        }

        // API Key Management
        function loadKeys() {
            const vtKey = localStorage.getItem('vt_api_key');
            const abuseipdbKey = localStorage.getItem('abuseipdb_api_key');
            const whoisKey = localStorage.getItem('whois_api_key');
            const urlscanKey = localStorage.getItem('urlscan_api_key');
            if (vtKey) document.getElementById('vtApiKey').value = atob(vtKey);
            if (abuseipdbKey) document.getElementById('abuseipdbApiKey').value = atob(abuseipdbKey);
            if (whoisKey) document.getElementById('whoisApiKey').value = atob(whoisKey);
            if (urlscanKey) document.getElementById('urlscanApiKey').value = atob(urlscanKey);
        }

        function saveKeys() {
            const vtKey = document.getElementById('vtApiKey').value.trim();
            const abuseipdbKey = document.getElementById('abuseipdbApiKey').value.trim();
            const whoisKey = document.getElementById('whoisApiKey').value.trim();
            const urlscanKey = document.getElementById('urlscanApiKey').value.trim();
            
            if (vtKey) localStorage.setItem('vt_api_key', btoa(vtKey));
            else localStorage.removeItem('vt_api_key');
            
            if (abuseipdbKey) localStorage.setItem('abuseipdb_api_key', btoa(abuseipdbKey));
            else localStorage.removeItem('abuseipdb_api_key');
            
            if (whoisKey) localStorage.setItem('whois_api_key', btoa(whoisKey));
            else localStorage.removeItem('whois_api_key');
            
            if (urlscanKey) localStorage.setItem('urlscan_api_key', btoa(urlscanKey));
            else localStorage.removeItem('urlscan_api_key');
            
            updateApiStatus();
            closeSettings();
        }

        function clearKeys() {
            localStorage.removeItem('vt_api_key');
            localStorage.removeItem('abuseipdb_api_key');
            localStorage.removeItem('whois_api_key');
            localStorage.removeItem('urlscan_api_key');
            document.getElementById('vtApiKey').value = '';
            document.getElementById('abuseipdbApiKey').value = '';
            document.getElementById('whoisApiKey').value = '';
            document.getElementById('urlscanApiKey').value = '';
            updateApiStatus();
        }

        // Toast Notification System
        function showToast(message, type) {
            type = type || 'info';
            var container = document.getElementById('toastContainer');
            var toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            container.appendChild(toast);
            
            // Auto-remove after 3 seconds
            setTimeout(function() {
                toast.style.animation = 'slideIn 0.3s ease reverse';
                setTimeout(function() { toast.remove(); }, 300);
            }, 3000);
        }

        function getKeys() {
            return {
                vt: localStorage.getItem('vt_api_key') ? atob(localStorage.getItem('vt_api_key')) : '',
                abuseipdb: localStorage.getItem('abuseipdb_api_key') ? atob(localStorage.getItem('abuseipdb_api_key')) : '',
                whois: localStorage.getItem('whois_api_key') ? atob(localStorage.getItem('whois_api_key')) : '',
                urlscan: localStorage.getItem('urlscan_api_key') ? atob(localStorage.getItem('urlscan_api_key')) : ''
            };
        }

        function updateApiStatus() {
            const keys = getKeys();
            document.getElementById('vtStatus').classList.toggle('active', !!keys.vt);
            document.getElementById('abuseipdbStatus').classList.toggle('active', !!keys.abuseipdb);
            document.getElementById('whoisStatus').classList.toggle('active', !!keys.whois);
            document.getElementById('urlscanStatus').classList.toggle('active', !!keys.urlscan);
        }

        // Modal
        function openSettings() {
            document.getElementById('settingsModal').classList.add('active');
        }

        function closeSettings() {
            document.getElementById('settingsModal').classList.remove('active');
        }

        function openAbout() {
            document.getElementById('aboutModal').classList.add('active');
        }

        function closeAbout() {
            document.getElementById('aboutModal').classList.remove('active');
        }

        // Workspace Functions
        function openSummaryModal() {
            document.getElementById('summaryModal').classList.add('active');
            updateSummaryStats();
        }

        function closeSummaryModal() {
            document.getElementById('summaryModal').classList.remove('active');
        }

        function updateSummaryStats() {
            const statsContainer = document.getElementById('summaryStats');
            const total = recentScans.length + workspaceItems.length;
            const highRisk = [...recentScans, ...workspaceItems].filter(item => item.riskLevel === 'high').length;
            const mediumRisk = [...recentScans, ...workspaceItems].filter(item => item.riskLevel === 'medium').length;
            const lowRisk = [...recentScans, ...workspaceItems].filter(item => item.riskLevel === 'low').length;
            
            statsContainer.innerHTML = `
                <div style="background: var(--bg-tertiary); padding: 12px; border-radius: 8px; flex: 1; min-width: 100px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: var(--text-primary);">${total}</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">Total IOCs</div>
                </div>
                <div style="background: rgba(239, 68, 68, 0.2); padding: 12px; border-radius: 8px; flex: 1; min-width: 100px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: #ef4444;">${highRisk}</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">High Risk</div>
                </div>
                <div style="background: rgba(251, 191, 36, 0.2); padding: 12px; border-radius: 8px; flex: 1; min-width: 100px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: #fbbf24;">${mediumRisk}</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">Medium Risk</div>
                </div>
                <div style="background: rgba(34, 197, 94, 0.2); padding: 12px; border-radius: 8px; flex: 1; min-width: 100px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: #22c55e;">${lowRisk}</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">Low Risk</div>
                </div>
            `;
        }

        function addToWorkspace() {
            const iocInput = document.getElementById('iocInput');
            const ioc = iocInput.value.trim();
            if (!ioc) {
                alert('Please enter an IOC first');
                return;
            }
            
            const iocType = document.getElementById('iocType').value;
            const riskLevel = currentResults.riskLevel || 'unknown';
            
            const item = {
                ioc: ioc,
                type: iocType === 'auto' ? detectIOCType(ioc) : iocType,
                riskLevel: riskLevel,
                timestamp: new Date().toISOString(),
                vtResults: currentResults.vt,
                abuseipdbResults: currentResults.abuseipdb,
                whoisResults: currentResults.whois
            };
            
            workspaceItems.push(item);
            alert(`Added ${ioc} to workspace!`);
        }

        function exportWorkspaceReport() {
            if (recentScans.length === 0 && workspaceItems.length === 0) {
                alert('No data to export. Run some scans first.');
                return;
            }
            
            let csv = 'IOC,Type,Risk Level,Timestamp\n';
            const allItems = [...recentScans, ...workspaceItems];
            allItems.forEach(item => {
                csv += `${item.ioc},${item.type},${item.riskLevel},${item.timestamp}\n`;
            });
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threatscan_export_${new Date().toISOString().slice(0,10)}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        }

        function clearWorkspace() {
            if (confirm('Are you sure you want to clear all workspace data? This will also clear recent scans.')) {
                recentScans = [];
                workspaceItems = [];
                localStorage.setItem('recent_scans', JSON.stringify(recentScans));
                renderRecentScans();
                alert('Workspace cleared!');
            }
        }

        function generateInvestigationSummary() {
            const allItems = [...recentScans, ...workspaceItems];
            
            if (allItems.length === 0) {
                document.getElementById('summaryText').value = 'No scan data available. Run some investigations first.';
                return;
            }
            
            const now = new Date();
            const reportDate = now.toISOString().slice(0, 19).replace('T', ' ');
            
            // Calculate statistics
            const highRiskItems = allItems.filter(item => item.riskLevel === 'high');
            const mediumRiskItems = allItems.filter(item => item.riskLevel === 'medium');
            const lowRiskItems = allItems.filter(item => item.riskLevel === 'low');
            
            // Detect IOC types
            const urls = allItems.filter(item => item.type === 'url' || (item.ioc && (item.ioc.startsWith('http://') || item.ioc.startsWith('https://'))));
            const ips = allItems.filter(item => item.type === 'ip' || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(item.ioc));
            const domains = allItems.filter(item => item.type === 'domain' && !urls.some(u => u.ioc === item.ioc));
            const hashes = allItems.filter(item => item.type === 'hash');
            
            // Smart detection - find potential phishing indicators
            const phishingIndicators = [];
            allItems.forEach(item => {
                if (item.ioc) {
                    const iocLower = item.ioc.toLowerCase();
                    // Check for suspicious TLDs
                    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link'];
                    suspiciousTLDs.forEach(tld => {
                        if (iocLower.includes(tld)) {
                            phishingIndicators.push({ ioc: item.ioc, reason: `Suspicious TLD: ${tld}` });
                        }
                    });
                    // Check for URL shorteners
                    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
                    shorteners.forEach(s => {
                        if (iocLower.includes(s)) {
                            phishingIndicators.push({ ioc: item.ioc, reason: `URL shortener: ${s}` });
                        }
                    });
                }
            });
            
            // Build the report
            let report = `================================================================================
                        SOC INVESTIGATION SUMMARY REPORT
================================================================================

Generated: ${reportDate}
Tool: ThreatAnalyzer by KS

--------------------------------------------------------------------------------
EXECUTIVE SUMMARY
--------------------------------------------------------------------------------

Total Indicators Analyzed: ${allItems.length}
- High Risk: ${highRiskItems.length}
- Medium Risk: ${mediumRiskItems.length}
- Low Risk: ${lowRiskItems.length}
- Unknown Risk: ${allItems.length - highRiskItems.length - mediumRiskItems.length - lowRiskItems.length}

IOC Breakdown:
- URLs: ${urls.length}
- IP Addresses: ${ips.length}
- Domains: ${domains.length}
- File Hashes: ${hashes.length}

`;
            
            // Add threat findings
            if (highRiskItems.length > 0) {
                report += `--------------------------------------------------------------------------------
HIGH RISK INDICATORS (${highRiskItems.length})
--------------------------------------------------------------------------------
`;
                highRiskItems.forEach((item, idx) => {
                    report += `${idx + 1}. ${item.ioc} [${item.type.toUpperCase()}]
   Risk Level: HIGH
   Timestamp: ${item.timestamp}
`;
                    // Add VT stats if available
                    if (item.vtResults && item.vtResults.data) {
                        const stats = item.vtResults.data.attributes?.last_analysis_stats;
                        if (stats) {
                            report += `   VirusTotal: ${stats.malicious || 0}/${stats.undetected + (stats.malicious || 0)} malicious detections\n`;
                        }
                    }
                    report += '\n';
                });
            }
            
            if (mediumRiskItems.length > 0) {
                report += `--------------------------------------------------------------------------------
MEDIUM RISK INDICATORS (${mediumRiskItems.length})
--------------------------------------------------------------------------------
`;
                mediumRiskItems.forEach((item, idx) => {
                    report += `${idx + 1}. ${item.ioc} [${item.type.toUpperCase()}]
   Risk Level: MEDIUM
   Timestamp: ${item.timestamp}\n\n`;
                });
            }
            
            if (phishingIndicators.length > 0) {
                report += `--------------------------------------------------------------------------------
PHISHING INFRASTRUCTURE INDICATORS (${phishingIndicators.length})
--------------------------------------------------------------------------------
`;
                phishingIndicators.forEach((item, idx) => {
                    report += `${idx + 1}. ${item.ioc}
   Reason: ${item.reason}\n\n`;
                });
            }
            
            // Add recommendations
            report += `--------------------------------------------------------------------------------
RECOMMENDATIONS
--------------------------------------------------------------------------------

`;
            
            if (highRiskItems.length > 0) {
                report += ` CRITICAL: ${highRiskItems.length} high-risk indicator(s) detected.
   - Block all identified high-risk IPs at firewall/IDS
   - Add malicious URLs to web proxy block list
   - Notify SOC team immediately for incident response
   - Preserve logs for forensic analysis

`;
            }
            
            if (phishingIndicators.length > 0) {
                report += ` PHISHING: ${phishingIndicators.length} potential phishing indicator(s) detected.
   - Investigate email headers for related campaigns
   - Check if domain is registered recently (WHOIS)
   - Block associated URLs in email gateway

`;
            }
            
            if (urls.length > 0) {
                report += ` URL ANALYSIS: ${urls.length} URL(s) analyzed.
   - Validate URLs against safe browsing APIs
   - Check for URL shortener expansion
   - Analyze URL structure for obfuscation

`;
            }
            
            report += `================================================================================
                           END OF INVESTIGATION REPORT
================================================================================
`;
            
            document.getElementById('summaryText').value = report;
        }

        function copySummary() {
            const summaryText = document.getElementById('summaryText');
            summaryText.select();
            document.execCommand('copy');
            alert('Summary copied to clipboard!');
        }

        function downloadSummary(format) {
            const content = document.getElementById('summaryText').value;
            if (!content || content.includes('No scan data available')) {
                alert('Generate a summary first!');
                return;
            }
            
            let blob, filename;
            if (format === 'txt') {
                blob = new Blob([content], { type: 'text/plain' });
                filename = `investigation_report_${new Date().toISOString().slice(0,10)}.txt`;
            } else if (format === 'md') {
                // Convert to Markdown
                let md = content
                    .replace(/^=+$/gm, '')
                    .replace(/^-+$/gm, '')
                    .replace(/^(\d+)\. /gm, '- ')
                    .replace(/^\s{3}(\d+)\. /gm, '  - ');
                blob = new Blob([md], { type: 'text/markdown' });
                filename = `investigation_report_${new Date().toISOString().slice(0,10)}.md`;
            }
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
        }

        // Helper function to detect IOC type
        function detectIOCType(ioc) {
            if (!ioc) return 'unknown';
            const iocLower = ioc.toLowerCase();
            
            // URL detection
            if (iocLower.startsWith('http://') || iocLower.startsWith('https://')) {
                return 'url';
            }
            
            // IP detection
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) {
                return 'ip';
            }
            
            // Hash detection (MD5, SHA1, SHA256)
            if (/^[a-f0-9]{32}$/i.test(ioc)) return 'hash';
            if (/^[a-f0-9]{40}$/i.test(ioc)) return 'hash';
            if (/^[a-f0-9]{64}$/i.test(ioc)) return 'hash';
            
            // Domain detection (default)
            return 'domain';
        }

        // Recent Scans
        function loadRecentScans() {
            const saved = localStorage.getItem('recent_scans');
            if (saved) {
                recentScans = JSON.parse(saved);
                renderRecentScans();
            }
        }

        function saveRecentScan(ioc, type, riskLevel = 'unknown') {
            const existing = recentScans.findIndex(s => s.ioc === ioc);
            if (existing >= 0) recentScans.splice(existing, 1);
            
            recentScans.unshift({ ioc, type, riskLevel, timestamp: new Date().toISOString() });
            if (recentScans.length > 10) recentScans.pop();
            
            localStorage.setItem('recent_scans', JSON.stringify(recentScans));
            renderRecentScans();
        }

        function renderRecentScans() {
            const container = document.getElementById('recentList');
            if (recentScans.length === 0) {
                container.innerHTML = '<div class="empty-state" style="padding: 20px;"><span>No recent scans</span></div>';
                return;
            }
            
            // Get type icon
            const getTypeIcon = (type) => {
                return type === 'ip' ? '' : type === 'domain' ? '' : type === 'url' ? '' : type === 'hash' ? '' : '';
            };
            
            // Get risk color
            const getRiskColor = (risk) => {
                return risk === 'high' ? 'var(--accent-red)' : risk === 'medium' ? 'var(--accent-yellow)' : risk === 'low' ? 'var(--accent-green)' : 'var(--text-muted)';
            };
            
            // Get risk icon
            const getRiskIcon = (risk) => {
                return risk === 'high' ? '' : risk === 'medium' ? '' : risk === 'low' ? '' : '';
            };
            
            container.innerHTML = recentScans.map(scan => `
                <div class="recent-item" onclick="loadRecent('${scan.ioc.replace(/'/g, "\\'")}', '${scan.type}')">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="font-size: 12px;">${getTypeIcon(scan.type)}</span>
                        <span class="ioc">${scan.ioc}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="font-size: 10px; color: var(--text-muted);">${scan.type.toUpperCase()}</span>
                        <span style="font-size: 10px;">${getRiskIcon(scan.riskLevel)}</span>
                    </div>
                </div>
            `).join('');
        }

        function loadRecent(ioc, type) {
            document.getElementById('iocInput').value = ioc;
            document.getElementById('iocType').value = type;
        }

        // Tab Switching
        function switchTab(tab) {
            // Handle bulk tab specially - show vt tab but keep bulk button active
            if (tab === 'bulk') {
                document.querySelectorAll('.tab-btn').forEach(btn => {
                    btn.classList.remove('active');
                    if (btn.dataset.tab === 'bulk') {
                        btn.classList.add('active');
                    }
                });
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.remove('active');
                });
                document.getElementById('vtTab').classList.add('active');
                return;
            }
            
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tab === tab);
            });
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.toggle('active', content.id === tab + 'Tab');
            });
            
            if (tab === 'combined') {
                // Always re-render combined view when switching to it
                renderCombined();
            }
        }

        // Investigation Notes Functions
        let notesSaveTimeout = null;
        
        // Load notes on page load
        function loadNotes() {
            const savedNotes = localStorage.getItem('threatscan_investigation_notes');
            if (savedNotes) {
                document.getElementById('investigationNotes').value = savedNotes;
            }
        }
        
        // Debounced autosave - save only after user stops typing for 600ms
        function handleNotesInput() {
            const textarea = document.getElementById('investigationNotes');
            const statusEl = document.getElementById('notesStatus');
            
            // Clear any pending save
            if (notesSaveTimeout) {
                clearTimeout(notesSaveTimeout);
            }
            
            // Set new timeout - save after 600ms of inactivity
            notesSaveTimeout = setTimeout(() => {
                const notes = textarea.value;
                localStorage.setItem('threatscan_investigation_notes', notes);
                
                // Update status
                const now = new Date();
                const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
                statusEl.textContent = `Saved ${timeStr}`;
                
                // Clear status after 3 seconds
                setTimeout(() => {
                    statusEl.textContent = '';
                }, 3000);
            }, 600);
        }
        
        // Insert timestamp at cursor position
        function insertTimestamp() {
            const textarea = document.getElementById('investigationNotes');
            const timezoneSelector = document.getElementById('timezoneSelector');
            const selectedTimezone = timezoneSelector ? timezoneSelector.value : 'UTC';
            
            const now = new Date();
            const tzInfo = getTimezoneOffset(selectedTimezone);
            
            // Get UTC timestamp and apply timezone offset directly
            const targetTime = new Date(now.getTime() + (tzInfo.offset * 3600000));
            
            // Format: YYYY-MM-DD HH:MM:SS TZ
            const year = targetTime.getUTCFullYear();
            const month = String(targetTime.getUTCMonth() + 1).padStart(2, '0');
            const day = String(targetTime.getUTCDate()).padStart(2, '0');
            const hours = String(targetTime.getUTCHours()).padStart(2, '0');
            const minutes = String(targetTime.getUTCMinutes()).padStart(2, '0');
            const seconds = String(targetTime.getUTCSeconds()).padStart(2, '0');
            
            const timestamp = `[${year}-${month}-${day} ${hours}:${minutes}:${seconds} ${tzInfo.label}]`;
            
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const text = textarea.value;
            
            textarea.value = text.substring(0, start) + timestamp + text.substring(end);
            textarea.selectionStart = textarea.selectionEnd = start + timestamp.length;
            textarea.focus();
            
            // Trigger autosave
            handleNotesInput();
        }
        
        // Get timezone offset in hours for a given timezone
        function getTimezoneOffset(tz) {
            const now = new Date();
            
            switch (tz) {
                case 'UTC':
                    return { offset: 0, label: 'UTC' };
                case 'Local':
                    return { offset: -now.getTimezoneOffset() / 60, label: 'Local' };
                case 'CET':
                    return { offset: 1, label: 'CET' };
                case 'EST':
                    return { offset: -5, label: 'EST' };
                case 'PST':
                    return { offset: -8, label: 'PST' };
                case 'GMT+1':
                    return { offset: 1, label: 'GMT+1' };
                case 'GMT+2':
                    return { offset: 2, label: 'GMT+2' };
                case 'GMT+3':
                    return { offset: 3, label: 'GMT+3' };
                case 'GMT+4':
                    return { offset: 4, label: 'GMT+4' };
                case 'GMT+5':
                    return { offset: 5, label: 'GMT+5' };
                case 'GMT+6':
                    return { offset: 6, label: 'GMT+6' };
                case 'GMT+7':
                    return { offset: 7, label: 'GMT+7' };
                case 'GMT+8':
                    return { offset: 8, label: 'GMT+8' };
                case 'GMT+9':
                    return { offset: 9, label: 'GMT+9' };
                case 'GMT+10':
                    return { offset: 10, label: 'GMT+10' };
                default:
                    return { offset: 0, label: 'UTC' };
            }
        }
        
        // Load timezone preference on page load
        function loadTimezonePreference() {
            const savedTimezone = localStorage.getItem('threatscan_timezone');
            if (savedTimezone) {
                const selector = document.getElementById('timezoneSelector');
                if (selector) {
                    selector.value = savedTimezone;
                }
            }
        }
        
        // Save timezone preference to localStorage
        function saveTimezonePreference() {
            const selector = document.getElementById('timezoneSelector');
            if (selector) {
                localStorage.setItem('threatscan_timezone', selector.value);
            }
        }
        
        // Keyboard shortcut: Ctrl+3 to insert timestamp
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === '3') {
                e.preventDefault();
                insertTimestamp();
            }
        });
        
        // Copy notes to clipboard
        function copyNotes() {
            const textarea = document.getElementById('investigationNotes');
            textarea.select();
            document.execCommand('copy');
            
            const statusEl = document.getElementById('notesStatus');
            statusEl.textContent = 'Copied!';
            setTimeout(() => { statusEl.textContent = ''; }, 2000);
        }
        
        // Export notes as TXT
        function exportNotes() {
            const notes = document.getElementById('investigationNotes').value;
            if (!notes.trim()) {
                alert('No notes to export!');
                return;
            }
            
            const blob = new Blob([notes], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'threatscan_investigation_notes.txt';
            a.click();
            URL.revokeObjectURL(url);
        }
        
        // Clear notes
        function clearNotes() {
            if (confirm('Are you sure you want to clear all investigation notes?')) {
                document.getElementById('investigationNotes').value = '';
                localStorage.removeItem('threatscan_investigation_notes');
                
                const statusEl = document.getElementById('notesStatus');
                statusEl.textContent = 'Cleared';
                setTimeout(() => { statusEl.textContent = ''; }, 2000);
            }
        }
        
        // Insert investigation template
        function insertTemplate() {
            const textarea = document.getElementById('investigationNotes');
            const templateSelector = document.getElementById('templateSelector');
            const selectedTemplate = templateSelector.value;
            
            if (!selectedTemplate) {
                alert('Please select a template first!');
                return;
            }
            
            const templates = {
                phishing: `PHISHING INVESTIGATION
========================================

Alert / Ticket ID:

Email Subject:

Sender Address:

Recipient:

Time Received:

Originating IP:

Malicious Indicators
URLs:
Attachments:
Domains:

Analysis:

Verdict:

Actions Taken:

Analyst Name:
Date:
`,
                appattack: `PUBLIC-FACING APPLICATION SECURITY ALERT
========================================

Alert Source:
AWS / Cloudflare / Akamai / WAF

Application / Domain:

Public IP:

Attack Type:

Source IP:

Country:

Evidence Collected:

Mitigation Actions:

Conclusion:

Analyst Name:
Date:
`,
                process: `ABNORMAL PROCESS EXECUTION
========================================

Host Name:

User:

Process Name:

Parent Process:

Command Line:

File Hash:

Network Connections:

Investigation Findings:

Conclusion:

Analyst Name:
Date:
`,
                credential: `IDENTITY / LOGIN INVESTIGATION
========================================

User Account:

Login Time:

Source IP:

Country:

Device Information:

Failed Login Attempts:

Suspicious Activity:

Actions Taken:

Conclusion:

Analyst Name:
Date:
`,
                dlp: `DATA SECURITY / DLP ALERT
========================================

User:

File Name:

File Type:

Data Classification:

Transfer Method:

Destination:

Policy Violated:

Containment Actions:

Conclusion:

Analyst Name:
Date:
`,
                malware: `MALWARE DETECTION
========================================

Host:

User:

Malware Name:

File Path:

File Hash:

Threat Intelligence:

Containment Actions:

Conclusion:

Analyst Name:
Date:
`,
                network: `NETWORK SECURITY INVESTIGATION
========================================

Source IP:

Destination IP:

Protocol:

Port:

Threat Intelligence:

Network Behavior:

Systems Affected:

Conclusion:

Analyst Name:
Date:
`,
                endpoint: `ENDPOINT SECURITY ALERT
========================================

Host Name:

User:

Detection Name:

Process Activity:

File Changes:

Network Activity:

Containment Actions:

Conclusion:

Analyst Name:
Date:
`,
                cloud: `CLOUD SECURITY INVESTIGATION
========================================

Cloud Provider:

Service:

Alert Source:

Account / User:

Activity Detected:

Source IP:

Mitigation Actions:

Conclusion:

Analyst Name:
Date:
`,
                generic: `SECURITY INVESTIGATION
========================================

Alert / Ticket ID:

Alert Source:

Affected System:

Indicators
IP:
Domain:
Hash:

Evidence Collected:

Investigation Notes:

Conclusion:

Recommendation:

Analyst Name:
Date:
`
            };
            
            const template = templates[selectedTemplate];
            if (!template) return;
            
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const text = textarea.value;
            
            textarea.value = text.substring(0, start) + template + text.substring(end);
            
            // Position cursor after the template title to allow immediate typing
            const newPosition = start + (selectedTemplate === 'quick' ? 20 : 23);
            textarea.selectionStart = textarea.selectionEnd = newPosition;
            textarea.focus();
            
            // Trigger autosave
            handleNotesInput();
            
            // Reset the selector
            templateSelector.value = '';
        }

        // IP Query Generator Functions
        let selectedIPOption = 'source';
        let selectedQueryLogic = 'or';
        let selectedPortField = 'noport';

        function selectIPOption(element, value) {
            // Remove selected class from all options in this group
            const parent = element.parentElement;
            parent.querySelectorAll('.radio-option').forEach(opt => opt.classList.remove('selected'));
            element.classList.add('selected');
            selectedIPOption = value;
            generateQuery();
        }

        function selectQueryLogic(element, value) {
            const parent = element.parentElement;
            parent.querySelectorAll('.radio-option').forEach(opt => opt.classList.remove('selected'));
            element.classList.add('selected');
            selectedQueryLogic = value;
            generateQuery();
        }

        function selectPortField(element, value) {
            const parent = element.parentElement;
            parent.querySelectorAll('.radio-option').forEach(opt => opt.classList.remove('selected'));
            element.classList.add('selected');
            selectedPortField = value;
            generateQuery();
        }

        function generateQuery() {
            const ipInput = document.getElementById('ipQueryInput').value;
            const portSelect = document.getElementById('portSelect');
            const port = portSelect.value;
            const output = document.getElementById('queryOutput');
            const ipCountEl = document.getElementById('ipCount');
            const platform = document.getElementById('siemPlatform').value;

            // Parse and validate IP addresses
            const lines = ipInput.split('\n').map(line => line.trim()).filter(line => line.length > 0);
            const ips = lines.filter(line => isValidIP(line));
            
            ipCountEl.textContent = ips.length;

            if (ips.length === 0) {
                output.textContent = 'Enter valid IP addresses above to generate a query...';
                return;
            }

            // Generate query based on platform
            let query = '';
            switch(platform) {
                case 'kibana':
                    query = generateKibanaQuery(ips, port);
                    break;
                case 'sentinel':
                    query = generateSentinelQuery(ips, port);
                    break;
                case 'crowdstrike':
                    query = generateCrowdstrikeQuery(ips, port);
                    break;
                case 'cortex':
                    query = generateCortexQuery(ips, port);
                    break;
                case 'splunk':
                    query = generateSplunkQuery(ips, port);
                    break;
                case 'sentinelone':
                    query = generateSentinelOneQuery(ips, port);
                    break;
                case 'qradar':
                    query = generateQRadarQuery(ips, port);
                    break;
                case 'exabeam':
                    query = generateExabeamQuery(ips, port);
                    break;
                case 'logrhythm':
                    query = generateLogRhythmQuery(ips, port);
                    break;
                case 'paloalto':
                    query = generatePaloAltoQuery(ips, port);
                    break;
                case 'sumologic':
                    query = generateSumoLogicQuery(ips, port);
                    break;
                case 'solarwinds':
                    query = generateSolarWindsQuery(ips, port);
                    break;
                case 'alienvault':
                    query = generateAlienVaultQuery(ips, port);
                    break;
                default:
                    query = generateKibanaQuery(ips, port);
            }

            output.value = query;
        }

        // Microsoft Sentinel (KQL)
        function generateSentinelQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'SourceIP:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'DestinationIP:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
            } else {
                const srcPart = 'SourceIP:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
                const dstPart = 'DestinationIP:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
                ipQueryPart = srcPart + ' OR ' + dstPart;
            }

            if (port) {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' | where DestinationPort == ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' | where SourcePort == ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' | where DestinationPort == ' + port + ' or SourcePort == ' + port;
                }
            }
            return ipQueryPart;
        }

        // Kibana (KQL)
        function generateKibanaQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'srcip:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'dstip:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
            } else {
                const srcPart = 'srcip:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
                const dstPart = 'dstip:(' + ips.map(ip => '"' + ip + '"').join(' OR ') + ')';
                ipQueryPart = srcPart + ' OR ' + dstPart;
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dstport:"' + port + '"';
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND srcport:"' + port + '"';
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dstport:"' + port + '" OR srcport:"' + port + '")';
                }
            }
            return ipQueryPart;
        }

        // Crowdstrike (FQL)
        function generateCrowdstrikeQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = '(src_ip:(' + ips.join(' OR ') + '))';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = '(dst_ip:(' + ips.join(' OR ') + '))';
            } else {
                const srcPart = '(src_ip:(' + ips.join(' OR ') + '))';
                const dstPart = '(dst_ip:(' + ips.join(' OR ') + '))';
                ipQueryPart = srcPart + ' OR ' + dstPart;
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port:' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port:' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port:' + port + ' OR src_port:' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // Cortex (Lucene)
        function generateCortexQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'src_ip:(' + ips.join(' OR ') + ')';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'dst_ip:(' + ips.join(' OR ') + ')';
            } else {
                const srcPart = 'src_ip:(' + ips.join(' OR ') + ')';
                const dstPart = 'dst_ip:(' + ips.join(' OR ') + ')';
                ipQueryPart = srcPart + ' OR ' + dstPart;
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port:' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port:' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port:' + port + ' OR src_port:' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // Splunk (SPL)
        function generateSplunkQuery(ips, port) {
            let ipQueryPart = '';
            const ipList = ips.map(ip => '"' + ip + '"').join(', ');

            if (selectedIPOption === 'source') {
                ipQueryPart = '(src_ip IN (' + ipList + '))';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = '(dst_ip IN (' + ipList + '))';
            } else {
                ipQueryPart = '(src_ip IN (' + ipList + ') OR dst_ip IN (' + ipList + '))';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port=' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port=' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port=' + port + ' OR src_port=' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // SentinelOne (S1QL)
        function generateSentinelOneQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '")';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'dst_ip IN ("' + ips.join('", "') + '")';
            } else {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '") OR dst_ip IN ("' + ips.join('", "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port = ' + port + ' OR src_port = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // IBM QRadar (AQL)
        function generateQRadarQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = '(SRC_IP IN (' + ips.join(', ') + '))';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = '(DST_IP IN (' + ips.join(', ') + '))';
            } else {
                ipQueryPart = '(SRC_IP IN (' + ips.join(', ') + ') OR DST_IP IN (' + ips.join(', ') + '))';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND DST_PORT = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND SRC_PORT = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (DST_PORT = ' + port + ' OR SRC_PORT = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // Exabeam
        function generateExabeamQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '")';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'dst_ip IN ("' + ips.join('", "') + '")';
            } else {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '") OR dst_ip IN ("' + ips.join('", "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port = ' + port + ' OR src_port = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // LogRhythm
        function generateLogRhythmQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'SourceIP = "' + ips.join('" OR SourceIP = "') + '"';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'DestinationIP = "' + ips.join('" OR DestinationIP = "') + '"';
            } else {
                ipQueryPart = '(SourceIP = "' + ips.join('" OR SourceIP = "') + '") OR (DestinationIP = "' + ips.join('" OR DestinationIP = "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND DestinationPort = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND SourcePort = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (DestinationPort = ' + port + ' OR SourcePort = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // Palo Alto X-SIAM (XQL)
        function generatePaloAltoQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '")';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'dst_ip IN ("' + ips.join('", "') + '")';
            } else {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '") OR dst_ip IN ("' + ips.join('", "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port = ' + port + ' OR src_port = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // Sumo Logic
        function generateSumoLogicQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = '_srcIp IN ("' + ips.join('", "') + '")';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = '_dstIp IN ("' + ips.join('", "') + '")';
            } else {
                ipQueryPart = '_srcIp IN ("' + ips.join('", "') + '") OR _dstIp IN ("' + ips.join('", "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND _dstPort = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND _srcPort = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (_dstPort = ' + port + ' OR _srcPort = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // SolarWinds SIEM
        function generateSolarWindsQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'SourceIP = "' + ips.join('" OR SourceIP = "') + '"';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'DestinationIP = "' + ips.join('" OR DestinationIP = "') + '"';
            } else {
                ipQueryPart = '(SourceIP = "' + ips.join('" OR SourceIP = "') + '") OR (DestinationIP = "' + ips.join('" OR DestinationIP = "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND DestinationPort = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND SourcePort = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (DestinationPort = ' + port + ' OR SourcePort = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        // AlienVault (AT&T Cybersecurity)
        function generateAlienVaultQuery(ips, port) {
            let ipQueryPart = '';

            if (selectedIPOption === 'source') {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '")';
            } else if (selectedIPOption === 'destination') {
                ipQueryPart = 'dst_ip IN ("' + ips.join('", "') + '")';
            } else {
                ipQueryPart = 'src_ip IN ("' + ips.join('", "') + '") OR dst_ip IN ("' + ips.join('", "') + '")';
            }

            if (port && selectedPortField !== 'noport') {
                if (selectedPortField === 'dstport') {
                    return ipQueryPart + ' AND dst_port = ' + port;
                } else if (selectedPortField === 'srcport') {
                    return ipQueryPart + ' AND src_port = ' + port;
                } else if (selectedPortField === 'bothport') {
                    return ipQueryPart + ' AND (dst_port = ' + port + ' OR src_port = ' + port + ')';
                }
            }
            return ipQueryPart;
        }

        function isValidIP(ip) {
            // Basic IPv4 validation
            const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (ipv4Regex.test(ip)) {
                const parts = ip.split('.').map(Number);
                return parts.every(part => part >= 0 && part <= 255);
            }
            // IPv6 validation (simplified)
            const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
            return ipv6Regex.test(ip);
        }

        function copyQuery() {
            const output = document.getElementById('queryOutput');
            const query = output.value;
            
            if (!query || query.startsWith('Enter')) {
                alert('Please generate a query first');
                return;
            }

            navigator.clipboard.writeText(query).then(() => {
                const btn = document.querySelector('.query-preview-header .btn');
                const originalText = btn.innerHTML;
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg> Copied!';
                setTimeout(() => {
                    btn.innerHTML = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
                alert('Failed to copy to clipboard');
            });
        }

        function clearIPQuery() {
            // Just clear the input fields for analyst to start over
            document.getElementById('ipQueryInput').value = '';
            document.getElementById('ipCount').textContent = '0';
            document.getElementById('queryOutput').value = '';
        }

        // Helper function to extract domain from URL
        function extractDomain(input) {
            // Remove protocol and path
            let domain = input.trim().replace(/[\n\r]/g, '');
            
            // Remove protocol (http://, https://, etc.)
            domain = domain.replace(/^https?:\/\//i, '');
            
            // Remove path, query string, and hash
            domain = domain.split('/')[0];
            domain = domain.split('?')[0];
            domain = domain.split('#')[0];
            
            // Remove port number
            domain = domain.split(':')[0];
            
            // Remove www. prefix for cleaner domain
            if (domain.startsWith('www.')) {
                domain = domain.substring(4);
            }
            
            return domain;
        }

        // Helper function to extract base domain (removes subdomains)
        function extractBaseDomain(domain) {
            // Trim whitespace and newlines
            domain = domain.trim().replace(/[\n\r]/g, '');
            
            const parts = domain.split('.');
            // Common TLDs that need special handling
            const commonTLDs = ['com', 'net', 'org', 'edu', 'gov', 'co', 'ac', 'or', 'ne', 'go', 'mil', 'ai', 'io', 'biz', 'info', 'me', 'cc', 'tv', 'ru', 'cn', 'de', 'uk', 'eu', 'jp'];
            
            // If domain has more than 2 parts, check if we need to combine first parts
            if (parts.length > 2) {
                const tld = parts[parts.length - 1];
                const secondLevel = parts[parts.length - 2];
                
                // Check if second level is a common TLD modifier
                if (commonTLDs.includes(secondLevel)) {
                    // e.g., co.uk -> return last 3 parts
                    return parts.slice(-3).join('.');
                }
                // Otherwise return last 2 parts (base domain)
                return parts.slice(-2).join('.');
            }
            
            return domain;
        }

        // Main Scan Function
        async function startScan() {
            const inputEl = document.getElementById('iocInput');
            const input = inputEl ? inputEl.value.trim() : '';
            if (!input) {
                showToast('Please enter an IOC to scan', 'error');
                return;
            }

            console.log('Starting scan:', input, 'mode:', scanMode);

            if (scanMode === 'bulk') {
                await startBulkScan(input);
            } else {
                await startSingleScan(input);
            }
        }

        // Single IOC Scan
        async function startSingleScan(input) {
            const typeEl = document.getElementById('iocType');
            const typeSelect = typeEl ? typeEl.value : 'auto';
            const ioc = input.trim();
            const type = typeSelect === 'auto' ? detectIOCType(ioc) : typeSelect;
            
            // Show guidance for multiple IOCs in single mode
            if (input.includes('\n') || (input.match(/\n/g) || []).length > 0) {
                showToast('Tip: Multiple IOCs detected. Switch to Bulk IOCs mode for better handling!', 'info');
            }
            
            if (type === 'unknown') {
                showToast('Unable to detect IOC type. Please select a type manually.', 'error');
                return;
            }
            
            currentResults.ioc = ioc;
            currentResults.type = type;

            console.log('Scanning IOC:', ioc, 'type:', type);

            // Save to recent
            saveRecentScan(ioc, type);

            // Show loading states
            showLoading('vt');
            showLoading('abuseipdb');
            showLoading('whois');
            showLoading('urlscan');

            // Update export bar
            const exportBar = document.getElementById('exportBar');
            if (exportBar) exportBar.style.display = 'flex';

            // Run scans in parallel with error isolation
            const keys = getKeys();
            const scanPromises = [];
            
            if (keys.vt) {
                scanPromises.push(scanVirusTotal(ioc, type));
            } else {
                showError('vt', 'VirusTotal API key not configured');
            }

            if (keys.abuseipdb) {
                scanPromises.push(scanAbuseIPDB(ioc));
            } else {
                showError('abuseipdb', 'AbuseIPDB API key not configured');
            }
            
            // WHOIS lookup - APILayer WHOIS only works for domains, not IPs
            if (keys.whois && (type === 'domain' || type === 'url')) {
                scanPromises.push(scanWhois(ioc));
            } else if (keys.whois && type === 'ip') {
                const whoisResults = document.getElementById('whoisResults');
                if (whoisResults) {
                    whoisResults.innerHTML = '<div class="info-message">WHOIS lookup is not available for IP addresses (only domains)</div>';
                }
                const whoisEmpty = document.getElementById('whoisEmpty');
                if (whoisEmpty) whoisEmpty.style.display = 'none';
            } else if (keys.whois) {
                const whoisResults = document.getElementById('whoisResults');
                if (whoisResults) {
                    whoisResults.innerHTML = '<div class="info-message">WHOIS lookup is not available for this IOC type (only domains)</div>';
                }
                const whoisEmpty = document.getElementById('whoisEmpty');
                if (whoisEmpty) whoisEmpty.style.display = 'none';
            } else {
                showError('whois', 'WHOIS API key not configured');
            }
            
            // URLScan lookup - URLScan only works for URLs and domains, not IPs or hashes
            if (keys.urlscan && (type === 'url' || type === 'domain')) {
                scanPromises.push(scanURLScan(ioc));
            } else if (keys.urlscan && (type === 'ip' || type === 'hash')) {
                const urlscanResults = document.getElementById('urlscanResults');
                if (urlscanResults) {
                    urlscanResults.innerHTML = '<div class="info-message">URLScan only supports URLs and domains, not IP addresses or hashes.</div>';
                }
                const urlscanEmpty = document.getElementById('urlscanEmpty');
                if (urlscanEmpty) urlscanEmpty.style.display = 'none';
            } else if (keys.urlscan) {
                const urlscanResults = document.getElementById('urlscanResults');
                if (urlscanResults) {
                    urlscanResults.innerHTML = '<div class="info-message">URLScan lookup is not available for this IOC type</div>';
                }
                const urlscanEmpty = document.getElementById('urlscanEmpty');
                if (urlscanEmpty) urlscanEmpty.style.display = 'none';
            } else if (type === 'url' || type === 'domain') {
                showError('urlscan', 'URLScan API key not configured');
            }
            
            // Ensure errors in one API do not block others
            await Promise.allSettled(scanPromises);

            // Update SOC dashboard widgets if present
            try {
                if (typeof updateReputationGrid === 'function') {
                    updateReputationGrid(currentResults.vt, currentResults.abuseipdb, currentResults.whois, currentResults.urlscan);
                }
                if (typeof updateRightSidebar === 'function') {
                    updateRightSidebar(currentResults.whois, currentResults.abuseipdb);
                }
            } catch (e) {
                console.warn('SOC dashboard update failed:', e);
            }
            
            // Render combined view if active
            const combinedTab = document.getElementById('combinedTab');
            if (combinedTab && combinedTab.classList.contains('active')) {
                renderCombined();
            }
        }

        // Bulk IOC Scan
        async function startBulkScan(input) {
            // First split by newlines
            const lines = input.split(/\r?\n/);
            
            // Then for each line, also split by commas
            const iocs = [];
            lines.forEach(line => {
                const trimmed = line.trim();
                if (!trimmed) return;
                
                // Split by commas if present
                const parts = trimmed.split(',').map(p => p.trim()).filter(p => p);
                parts.forEach(part => iocs.push(part));
            });
            
            // Limit to 100 IOCs
            const validIocs = iocs.slice(0, 100);
            
            if (validIocs.length === 0) {
                alert('Please enter at least one IOC to scan');
                return;
            }

            // Show guidance for single IOC in bulk mode
            if (validIocs.length === 1) {
                showToast(' Tip: For a single IOC, switch to Single IOC mode for detailed results!', 'info');
            }

            const keys = getKeys();
            if (!keys.vt) {
                alert('VirusTotal API key is required for bulk scanning');
                return;
            }

            // Initialize bulk results
            bulkResults = [];
            bulkScanProgress = 0;

            // Show bulk results tab
            switchTab('vt');
            document.getElementById('exportBar').style.display = 'flex';

            // Render initial progress
            renderBulkProgress(0, validIocs.length);

            // Sleep helper function for rate limiting
            function sleep(ms) {
                return new Promise(resolve => setTimeout(resolve, ms));
            }

            // Process each IOC
            async function processIOC(ioc, type, keys) {
                // Process all API calls in parallel for better performance
                const [vtResult, abuseResult, whoisResult] = await Promise.all([
                    // Get VirusTotal result
                    (async () => {
                        try {
                            return { result: await scanVirusTotalBulk(ioc, type, keys.vt), error: null };
                        } catch (e) {
                            return { result: null, error: e.message };
                        }
                    })(),
                    // Get AbuseIPDB result
                    (async () => {
                        if (type === 'hash' || !keys.abuseipdb) {
                            return { result: null, error: null };
                        }
                        let ipToQuery = ioc;
                        try {
                            if (type === 'domain' || type === 'url') {
                                const domain = extractDomain(ioc);
                                const resolvedIP = await resolveDNS(domain);
                                if (resolvedIP) {
                                    ipToQuery = resolvedIP;
                                }
                            }
                            if (type === 'ip' || type === 'domain' || type === 'url') {
                                const result = await scanAbuseIPDBBulk(ipToQuery, keys.abuseipdb);
                                return { result, error: null };
                            }
                            return { result: null, error: null };
                        } catch (e) {
                            return { result: null, error: e.message };
                        }
                    })(),
                    // Get WHOIS result
                    (async () => {
                        if (!keys.whois) {
                            return { result: null, error: null };
                        }
                        try {
                            if (type === 'domain' || type === 'url') {
                                const result = await scanWhoisBulk(ioc, keys.whois);
                                return { result, error: null };
                            } else if (type === 'ip') {
                                return { result: { notAvailable: 'WHOIS is not available for IP addresses' }, error: null };
                            }
                            return { result: null, error: null };
                        } catch (e) {
                            return { result: null, error: e.message };
                        }
                    })()
                ]);
                
                const vtError = vtResult.error;
                const abuseError = abuseResult.error;
                const whoisError = whoisResult.error;
                
                return {
                    vtResult: vtResult.result,
                    vtError,
                    abuseResult: abuseResult.result,
                    abuseError,
                    whoisResult: whoisResult.result,
                    whoisError,
                    status: (vtError && !vtResult.result) ? 'error' : 'success'
                };
            }

            // Process each IOC
            for (let i = 0; i < validIocs.length; i++) {
                const ioc = validIocs[i];
                const type = detectIOCType(ioc);
                
                // Process with retry logic
                const { vtResult, vtError, abuseResult, abuseError, whoisResult, whoisError } = await processIOC(ioc, type, keys);
                
                bulkResults.push({
                    ioc: ioc,
                    type: type,
                    vt: vtResult,
                    vtError: vtError,
                    abuseipdb: abuseResult,
                    abuseError: abuseError,
                    whois: whoisResult,
                    whoisError: whoisError,
                    status: (vtError && !vtResult) ? 'error' : 'success'
                });
                
                bulkScanProgress = i + 1;
                renderBulkProgress(bulkScanProgress, iocs.length);
                
                // Rate limiting: wait between requests to avoid blocking
                // VirusTotal free tier allows ~4 requests per minute
                // Add a delay of 1.5 seconds between each request
                if (i < iocs.length - 1) {
                    await sleep(1500);
                }
            }

            // Render final results
            renderBulkResults();
        }

        // Bulk AbuseIPDB Scan
        async function scanAbuseIPDBBulk(ioc, apiKey) {
            try {
                const response = await fetch(CORS_PROXY + encodeURIComponent(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90&verbose=`), {
                    headers: {
                        'Key': apiKey,
                        'Accept': 'application/json'
                    }
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch IP information');
                }

                const data = await response.json();
                return data.data;
            } catch (error) {
                return { error: error.message };
            }
        }

        // Bulk WHOIS Scan
        async function scanWhoisBulk(ioc, apiKey) {
            try {
                // Extract domain and get base domain for WHOIS
                let domain = extractDomain(ioc);
                const baseDomain = extractBaseDomain(domain);
                
                // Check for unsupported TLDs
                const unsupportedTLDs = ['.onion', '.i2p', '.bit', '.zero', '.exit'];
                const isUnsupportedTLD = unsupportedTLDs.some(tld => baseDomain.toLowerCase().endsWith(tld));
                
                if (isUnsupportedTLD) {
                    return { error: 'WHOIS not supported for this TLD' };
                }
                
                const response = await fetch(`https://api.apilayer.com/whois/query?domain=${encodeURIComponent(baseDomain)}`, {
                    headers: {
                        'APIKEY': apiKey
                    }
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorText || 'Failed'}`);
                }

                const data = await response.json();
                return data.result || null;
            } catch (error) {
                console.error('WHOIS Bulk Error:', error);
                return { error: error.message };
            }
        }

        // Bulk VirusTotal Scan (returns result for bulk mode)
        async function scanVirusTotalBulk(ioc, type, apiKey) {
            let endpoint = '';
            try {
                switch (type) {
                    case 'ip':
                        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
                        break;
                    case 'domain':
                        endpoint = `https://www.virustotal.com/api/v3/domains/${ioc}`;
                        break;
                    case 'url':
                        endpoint = `https://www.virustotal.com/api/v3/urls`;
                        break;
                    case 'hash':
                        endpoint = `https://www.virustotal.com/api/v3/files/${ioc}`;
                        break;
                    default:
                        return { error: 'Unsupported type' };
                }

                let url = endpoint;
                let method = 'GET';
                let body = null;
                
                // For URLs, use btoa encoding like single scan (more reliable)
                if (type === 'url') {
                    // Use base64 encoding without padding (VirusTotal requirement)
                    const urlId = btoa(ioc).replace(/=+$/, '');
                    url = `https://www.virustotal.com/api/v3/urls/${urlId}`;
                }

                // Try direct API call first (like single scan), then fallback to proxy
                let response;
                try {
                    response = await fetch(url, {
                        method: method,
                        headers: {
                            'x-apikey': apiKey,
                            'Content-Type': 'application/json'
                        },
                        body: type === 'url' ? body : null
                    });
                } catch (directError) {
                    // If direct fails, try with CORS proxy
                    const proxyUrl = CORS_PROXY + encodeURIComponent(url);
                    response = await fetch(proxyUrl, {
                        method: method,
                        headers: {
                            'x-apikey': apiKey,
                            'Content-Type': 'application/json'
                        },
                        body: type === 'url' ? body : null
                    });
                }

                if (!response.ok) {
                    if (response.status === 404) {
                        return { notFound: true, ioc: ioc };
                    }
                    if (response.status === 400) {
                        return { error: 'Bad request - check API key and URL format', ioc: ioc };
                    }
                    if (response.status === 429) {
                        return { error: 'Rate limited - please wait and try again', ioc: ioc };
                    }
                    throw new Error(`API error: ${response.status}`);
                }

                const data = await response.json();
                
                return data;
            } catch (error) {
                return { error: error.message };
            }
        }

        // Render Bulk Progress
        function renderBulkProgress(current, total) {
            const container = document.getElementById('vtResults');
            const percentage = Math.round((current / total) * 100);
            
            container.innerHTML = `
                <div class="bulk-progress">
                    <h3>Scanning ${total} IOCs...</h3>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${percentage}%"></div>
                    </div>
                    <div class="progress-stats">
                        <span>Progress: ${current} / ${total}</span>
                        <span>${percentage}% complete</span>
                    </div>
                </div>
            `;
            document.getElementById('vtEmpty').style.display = 'none';
        }

        // Bulk Table Sorting State
        let bulkSortColumn = 'risk';
        let bulkSortAsc = false;

        // Sort bulk results by column
        function sortBulkTable(column) {
            // Handle dropdown values (e.g., "risk-asc")
            if (column.includes('-asc')) {
                bulkSortColumn = column.replace('-asc', '');
                bulkSortAsc = true;
            } else {
                bulkSortColumn = column;
                bulkSortAsc = false;
            }
            renderBulkResults();
        }

        // Column resize functionality
        function initColumnResize(tableId) {
            const table = document.getElementById(tableId);
            if (!table) return;

            const headers = table.querySelectorAll('th');
            headers.forEach(th => {
                const handle = document.createElement('div');
                handle.className = 'resize-handle';
                th.appendChild(handle);

                let startX, startWidth;

                handle.addEventListener('mousedown', (e) => {
                    startX = e.pageX;
                    startWidth = th.offsetWidth;
                    document.addEventListener('mousemove', doDrag);
                    document.addEventListener('mouseup', stopDrag);
                });

                function doDrag(e) {
                    th.style.width = (startWidth + e.pageX - startX) + 'px';
                }

                function stopDrag() {
                    document.removeEventListener('mousemove', doDrag);
                    document.removeEventListener('mouseup', stopDrag);
                }
            });
        }

        // Filter by column value
        let columnFilters = {};
        
        function filterByColumn(column, value) {
            columnFilters[column] = value;
            renderBulkResults();
        }

        function getUniqueValues(results, column) {
            const values = new Set();
            results.forEach(r => {
                let val = '';
                switch(column) {
                    case 'ioc': val = r.ioc || ''; break;
                    case 'type': val = r.type || ''; break;
                    case 'vt':
                        if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                            const stats = r.vt.data.attributes.last_analysis_stats;
                            val = String((stats.malicious || 0) + (stats.suspicious || 0));
                        }
                        break;
                    case 'abuse':
                        if (r.abuseipdb && !r.abuseipdb.error) {
                            val = String(r.abuseipdb.abuseConfidenceScore || 0);
                        }
                        break;
                    case 'age':
                        if (r.whois && !r.whoisError && r.whois.creation_date) {
                            const days = Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24));
                            if (days < 30) val = '< 30 days';
                            else if (days < 90) val = '30-90 days';
                            else if (days < 180) val = '90-180 days';
                            else if (days < 365) val = '180-365 days';
                            else val = '> 1 year';
                        }
                        break;
                    case 'risk':
                        let malCount = 0, abuseConf = 0, vtStats = null;
                        if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                            vtStats = r.vt.data.attributes.last_analysis_stats;
                            malCount = (vtStats.malicious || 0) + (vtStats.suspicious || 0);
                        }
                        if (r.abuseipdb && !r.abuseipdb.error) {
                            abuseConf = r.abuseipdb.abuseConfidenceScore || 0;
                        }
                        const domainAge = r.whois && !r.whoisError && r.whois.creation_date 
                            ? Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24)) : 0;
                        const score = calculateThreatScore(r.ioc, vtStats, abuseConf, domainAge);
                        if (score >= 80) val = 'HIGH';
                        else if (score >= 50) val = 'MEDIUM';
                        else val = 'LOW';
                        break;
                }
                if (val) values.add(val);
            });
            return Array.from(values).sort();
        }

        // Render Bulk Results
        function renderBulkResults() {
            const container = document.getElementById('vtResults');
            
            // Calculate stats
            let malicious = 0, suspicious = 0, clean = 0, undetected = 0, errors = 0;
            
            bulkResults.forEach(r => {
                if (r.status === 'error') {
                    errors++;
                    return;
                }
                
                const vtData = r.vt;
                const abuseData = r.abuseipdb;
                
                let malCount = 0;
                let abuseConfidence = 0;
                
                if (vtData && vtData.data && vtData.data.attributes && vtData.data.attributes.last_analysis_stats) {
                    const attrs = vtData.data.attributes;
                    const lastAnalysis = attrs.last_analysis_stats;
                    malCount = (lastAnalysis.malicious || 0) + (lastAnalysis.suspicious || 0);
                } else if (vtData && vtData.error) {
                    // Handle API errors gracefully
                    errors++;
                    return;
                }
                
                if (abuseData && !abuseData.error) {
                    abuseConfidence = abuseData.abuseConfidenceScore || 0;
                }
                
                // Use TLD-weighted threat score for stats
                let vtStats = null;
                if (vtData && vtData.data && vtData.data.attributes && vtData.data.attributes.last_analysis_stats) {
                    vtStats = vtData.data.attributes.last_analysis_stats;
                }
                const whoisAge = r.whois && !r.whoisError && r.whois.creation_date 
                    ? Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24)) 
                    : 0;
                const riskScore = calculateThreatScore(r.ioc, vtStats, abuseConfidence, whoisAge);
                
                if (riskScore >= 80) malicious++;
                else if (riskScore >= 50) suspicious++;
                else if (malCount === 0 && abuseConfidence === 0) clean++;
                else undetected++;
            });

            // Apply column filters first
            let filteredResults = bulkResults.filter(r => {
                for (const col in columnFilters) {
                    if (!columnFilters[col]) continue;
                    let val = '';
                    switch(col) {
                        case 'ioc': val = r.ioc || ''; break;
                        case 'type': val = r.type || ''; break;
                        case 'vt':
                            if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                                const stats = r.vt.data.attributes.last_analysis_stats;
                                val = String((stats.malicious || 0) + (stats.suspicious || 0));
                            }
                            break;
                        case 'abuse':
                            if (r.abuseipdb && !r.abuseipdb.error) {
                                val = String(r.abuseipdb.abuseConfidenceScore || 0);
                            }
                            break;
                        case 'age':
                            if (r.whois && !r.whoisError && r.whois.creation_date) {
                                const days = Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24));
                                if (days < 30) val = '< 30 days';
                                else if (days < 90) val = '30-90 days';
                                else if (days < 180) val = '90-180 days';
                                else if (days < 365) val = '180-365 days';
                                else val = '> 1 year';
                            }
                            break;
                        case 'risk':
                            let malCount = 0, abuseConf = 0, vtStats = null;
                            if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                                vtStats = r.vt.data.attributes.last_analysis_stats;
                                malCount = (vtStats.malicious || 0) + (vtStats.suspicious || 0);
                            }
                            if (r.abuseipdb && !r.abuseipdb.error) {
                                abuseConf = r.abuseipdb.abuseConfidenceScore || 0;
                            }
                            const domainAge = r.whois && !r.whoisError && r.whois.creation_date 
                                ? Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24)) : 0;
                            const score = calculateThreatScore(r.ioc, vtStats, abuseConf, domainAge);
                            if (score >= 80) val = 'HIGH';
                            else if (score >= 50) val = 'MEDIUM';
                            else val = 'LOW';
                            break;
                    }
                    if (val !== columnFilters[col]) return false;
                }
                return true;
            });
            
            // Get unique values for dropdowns
            const uniqueValues = {
                ioc: getUniqueValues(bulkResults, 'ioc'),
                type: ['ip', 'domain', 'url', 'hash'],
                vt: getUniqueValues(bulkResults, 'vt'),
                abuse: getUniqueValues(bulkResults, 'abuse'),
                age: ['< 30 days', '30-90 days', '90-180 days', '180-365 days', '> 1 year'],
                risk: ['HIGH', 'MEDIUM', 'LOW']
            };
            
            // Sort by selected column
            const sortedResults = [...filteredResults].sort((a, b) => {
                let valA, valB;
                
                switch(bulkSortColumn) {
                    case 'ioc':
                        valA = (a.ioc || '').toLowerCase();
                        valB = (b.ioc || '').toLowerCase();
                        return bulkSortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
                    
                    case 'type':
                        valA = a.type || '';
                        valB = b.type || '';
                        return bulkSortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
                    
                    case 'vt':
                        valA = 0; valB = 0;
                        if (a.vt && a.vt.data && a.vt.data.attributes && a.vt.data.attributes.last_analysis_stats) {
                            const stats = a.vt.data.attributes.last_analysis_stats;
                            valA = (stats.malicious || 0) + (stats.suspicious || 0);
                        }
                        if (b.vt && b.vt.data && b.vt.data.attributes && b.vt.data.attributes.last_analysis_stats) {
                            const stats = b.vt.data.attributes.last_analysis_stats;
                            valB = (stats.malicious || 0) + (stats.suspicious || 0);
                        }
                        return bulkSortAsc ? valA - valB : valB - valA;
                    
                    case 'abuse':
                        valA = (a.abuseipdb && !a.abuseipdb.error) ? (a.abuseipdb.abuseConfidenceScore || 0) : 0;
                        valB = (b.abuseipdb && !b.abuseipdb.error) ? (b.abuseipdb.abuseConfidenceScore || 0) : 0;
                        return bulkSortAsc ? valA - valB : valB - valA;
                    
                    case 'age':
                        valA = (a.whois && !a.whoisError && a.whois.creation_date) 
                            ? Math.floor((new Date() - new Date(a.whois.creation_date)) / (1000 * 60 * 60 * 24)) : 99999;
                        valB = (b.whois && !b.whoisError && b.whois.creation_date) 
                            ? Math.floor((new Date() - new Date(b.whois.creation_date)) / (1000 * 60 * 60 * 24)) : 99999;
                        return bulkSortAsc ? valA - valB : valB - valA;
                    
                    case 'risk':
                    default:
                        let malCountA = 0, abuseA = 0, vtStatsA = null;
                        if (a.vt && a.vt.data && a.vt.data.attributes && a.vt.data.attributes.last_analysis_stats) {
                            const stats = a.vt.data.attributes.last_analysis_stats;
                            malCountA = (stats.malicious || 0) + (stats.suspicious || 0);
                            vtStatsA = stats;
                        }
                        if (a.abuseipdb && !a.abuseipdb.error) {
                            abuseA = a.abuseipdb.abuseConfidenceScore || 0;
                        }
                        const domainAgeA = (a.whois && !a.whoisError && a.whois.creation_date) 
                            ? Math.floor((new Date() - new Date(a.whois.creation_date)) / (1000 * 60 * 60 * 24)) : 0;
                        
                        let malCountB = 0, abuseB = 0, vtStatsB = null;
                        if (b.vt && b.vt.data && b.vt.data.attributes && b.vt.data.attributes.last_analysis_stats) {
                            const stats = b.vt.data.attributes.last_analysis_stats;
                            malCountB = (stats.malicious || 0) + (stats.suspicious || 0);
                            vtStatsB = stats;
                        }
                        if (b.abuseipdb && !b.abuseipdb.error) {
                            abuseB = b.abuseipdb.abuseConfidenceScore || 0;
                        }
                        const domainAgeB = (b.whois && !b.whoisError && b.whois.creation_date) 
                            ? Math.floor((new Date() - new Date(b.whois.creation_date)) / (1000 * 60 * 60 * 24)) : 0;
                        
                        const scoreA = calculateThreatScore(a.ioc, vtStatsA, abuseA, domainAgeA);
                        const scoreB = calculateThreatScore(b.ioc, vtStatsB, abuseB, domainAgeB);
                        return bulkSortAsc ? scoreA - scoreB : scoreB - scoreA;
                }
            });

            // Add copy button style
            let html = `
                <style>
                    .copy-btn-small {
                        background: var(--bg-tertiary);
                        border: 1px solid var(--border);
                        color: var(--text-primary);
                        padding: 4px 8px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 11px;
                        margin-left: 8px;
                    }
                    .copy-btn-small:hover {
                        background: var(--accent-blue);
                        color: white;
                    }
                </style>
                <div style="margin-bottom:16px;">
                    <button class="btn btn-sm" onclick="copyAllBulkResults()">
                        Copy All Results
                    </button>
                </div>
                <div class="bulk-summary">
                    <div class="summary-card malicious">
                        <div class="stat-value malicious">${malicious}</div>
                        <div class="stat-label">Malicious</div>
                    </div>
                    <div class="summary-card suspicious">
                        <div class="stat-value suspicious">${suspicious}</div>
                        <div class="stat-label">Suspicious</div>
                    </div>
                    <div class="summary-card clean">
                        <div class="stat-value clean">${clean}</div>
                        <div class="stat-label">Clean</div>
                    </div>
                    <div class="summary-card undetected">
                        <div class="stat-value undetected">${undetected}</div>
                        <div class="stat-label">Undetected</div>
                    </div>
                </div>
                
                <table class="bulk-results-table" id="bulkResultsTable">
                    <thead>
                        <tr>
                            <th>
                                <div class="th-content">
                                    IOC
                                    <select class="header-sort" id="filter-ioc" onchange="filterByColumn('ioc', this.value)" title="Filter by IOC">
                                        <option value="">All</option>
                                    </select>
                                </div>
                            </th>
                            <th>
                                <div class="th-content">
                                    Type
                                    <select class="header-sort" id="filter-type" onchange="filterByColumn('type', this.value)" title="Filter by Type">
                                        <option value="">All</option>
                                    </select>
                                </div>
                            </th>
                            <th>
                                <div class="th-content">
                                    VirusTotal
                                    <select class="header-sort" id="filter-vt" onchange="filterByColumn('vt', this.value)" title="Filter by VT">
                                        <option value="">All</option>
                                    </select>
                                </div>
                            </th>
                            <th>
                                <div class="th-content">
                                    AbuseIPDB
                                    <select class="header-sort" id="filter-abuse" onchange="filterByColumn('abuse', this.value)" title="Filter by AbuseIPDB">
                                        <option value="">All</option>
                                    </select>
                                </div>
                            </th>
                            <th>
                                <div class="th-content">
                                    WHOIS
                                    <select class="header-sort" id="filter-age" onchange="filterByColumn('age', this.value)" title="Filter by Age">
                                        <option value="">All</option>
                                    </select>
                                </div>
                            </th>
                            <th>
                                <div class="th-content">
                                    Risk
                                    <select class="header-sort" id="filter-risk" onchange="filterByColumn('risk', this.value)" title="Filter by Risk">
                                        <option value="">All</option>
                                        <option value="HIGH">HIGH</option>
                                        <option value="MEDIUM">MEDIUM</option>
                                        <option value="LOW">LOW</option>
                                    </select>
                                </div>
                            </th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            sortedResults.forEach(r => {
                let vtText = '-';
                let abuseText = '-';
                let whoisText = '-';
                let riskLevel = 'LOW';
                let badgeClass = 'clean';
                let rowClass = 'row-low-risk';
                let malCount = 0;
                let abuseConf = 0;
                let total = 0;
                let threatScore = 0;
                
                // VirusTotal
                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    const stats = r.vt.data.attributes.last_analysis_stats;
                    total = Object.values(stats).reduce((a, b) => a + b, 0);
                    malCount = (stats.malicious || 0) + (stats.suspicious || 0);
                    vtText = malCount + '/' + total;
                } else if (r.vtError || (r.vt && r.vt.error)) {
                    vtText = 'Error';
                }
                
                // AbuseIPDB
                if (r.abuseipdb && !r.abuseipdb.error) {
                    abuseConf = r.abuseipdb.abuseConfidenceScore || 0;
                    const reports = r.abuseipdb.totalReports || 0;
                    abuseText = `Conf: ${abuseConf}% / Rep: ${reports}`;
                } else if (r.type === 'ip') {
                    abuseText = 'N/A';
                }
                
                // WHOIS
                if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                    const created = r.whois.creation_date ? new Date(r.whois.creation_date) : null;
                    
                    let createdText = '-';
                    let expiresText = '-';
                    let registrarText = r.whois.registrar || '-';
                    let ageText = '-';
                    
                    if (created) {
                        createdText = created.toLocaleDateString();;
                        const ageDays = Math.floor((new Date() - created) / (1000 * 60 * 60 * 24));
                        ageText = `${ageDays} days`;
                    }
                    
                    if (r.whois.expiration_date) {
                        expiresText = new Date(r.whois.expiration_date).toLocaleDateString();
                    }
                    
                    whoisText = `Created: ${createdText}<br>Expires: ${expiresText}<br>Registrar: ${registrarText}<br>Age: ${ageText}`;
                }
                
                // Calculate threat score FIRST (before risk level)
                let vtStats = null;
                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    vtStats = r.vt.data.attributes.last_analysis_stats;
                }
                const domainAge = r.whois && !r.whoisError && r.whois.creation_date 
                    ? Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24)) 
                    : 0;
                threatScore = calculateThreatScore(r.ioc, vtStats, abuseConf, domainAge);
                
                // Risk level based on TLD-weighted threat score
                if (threatScore >= 80) {
                    riskLevel = 'HIGH';
                    badgeClass = 'malicious';
                    rowClass = 'row-high-risk';
                } else if (threatScore >= 50) {
                    riskLevel = 'MEDIUM';
                    badgeClass = 'suspicious';
                    rowClass = 'row-medium-risk';
                } else {
                    riskLevel = 'LOW';
                    badgeClass = 'clean';
                    rowClass = 'row-low-risk';
                }
                
                // TLD badge for high-risk TLDs
                const tldCat = getTldCategory(r.ioc);
                const tldBadge = tldCat ? `<span class="${tldCat.class}">${tldCat.label}</span>` : '';

                // Pivot buttons
                let pivotBtns = '';
                if (r.type === 'ip') {
                    pivotBtns = '<div class="pivot-btns"><a class="pivot-btn" href="https://www.virustotal.com/gui/ip-address/' + r.ioc + '" target="_blank">VT</a> <a class="pivot-btn" href="https://www.shodan.io/search?query=' + r.ioc + '" target="_blank">Shodan</a> <a class="pivot-btn" href="https://www.greynoise.io/viz/ip/' + r.ioc + '" target="_blank">GN</a></div>';
                } else if (r.type === 'domain') {
                    pivotBtns = '<div class="pivot-btns"><a class="pivot-btn" href="https://www.virustotal.com/gui/domain/' + r.ioc + '" target="_blank">VT</a></div>';
                } else if (r.type === 'url') {
                    pivotBtns = '<div class="pivot-btns"><a class="pivot-btn" href="https://www.virustotal.com/gui/url/' + encodeURIComponent(r.ioc) + '" target="_blank">VT</a></div>';
                }

                html += `
                    <tr class="${rowClass}">
                        <td class="ioc-cell" title="${r.ioc}"><strong>${r.ioc}</strong>${tldBadge}<br>${pivotBtns}</td>
                        <td>${r.type}</td>
                        <td><span class="vt-detections"><span class="vt-malicious">${malCount}</span>/<span class="vt-clean">${total}</span></span></td>
                        <td>${abuseText}</td>
                        <td>${whoisText}</td>
                        <td><span class="threat-score ${threatScore >= 80 ? 'threat-score-high' : threatScore >= 50 ? 'threat-score-medium' : 'threat-score-low'}">${threatScore}</span><div class="threat-bar"><div class="threat-bar-fill" style="width:${threatScore}%;background:${threatScore >= 80 ? '#ef4444' : threatScore >= 50 ? '#f59e0b' : '#22c55e'}"></div></div><span class="category-badge ${badgeClass}">${riskLevel}</span></td>
                        <td><button class="copy-btn-small" onclick="copyBulkRow('${r.ioc}')">Copy</button></td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            container.innerHTML = html;
            document.getElementById('vtEmpty').style.display = 'none';
            
            // Populate filter dropdowns with actual values
            setTimeout(() => {
                ['ioc', 'type', 'vt', 'abuse', 'age', 'risk'].forEach(col => {
                    const select = document.getElementById('filter-' + col);
                    if (!select) return;
                    const currentVal = columnFilters[col] || '';
                    select.innerHTML = '<option value="">All</option>';
                    if (col === 'risk') {
                        ['HIGH', 'MEDIUM', 'LOW'].forEach(v => {
                            select.innerHTML += `<option value="${v}">${v}</option>`;
                        });
                    } else if (col === 'type') {
                        ['ip', 'domain', 'url', 'hash'].forEach(v => {
                            select.innerHTML += `<option value="${v}">${v}</option>`;
                        });
                    } else if (uniqueValues[col]) {
                        uniqueValues[col].forEach(v => {
                            select.innerHTML += `<option value="${v}">${v}</option>`;
                        });
                    }
                    select.value = currentVal;
                });
            }, 50);
            
            // Initialize column resizing
            setTimeout(() => initColumnResize('bulkResultsTable'), 100);
        }

        // Copy single bulk row
        function copyBulkRow(ioc) {
            const r = bulkResults.find(b => b.ioc === ioc);
            if (!r) return;
            
            let malCount = 0;
            let abuseConf = 0;
            let reports = 0;
            let total = 0;
            let whoisCreated = '-';
            let whoisExpires = '-';
            let whoisRegistrar = '-';
            let whoisAge = '-';
            
            if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                const stats = r.vt.data.attributes.last_analysis_stats;
                total = Object.values(stats).reduce((a, b) => a + b, 0);
                malCount = (stats.malicious || 0) + (stats.suspicious || 0);
            }
            if (r.abuseipdb && !r.abuseipdb.error) {
                abuseConf = r.abuseipdb.abuseConfidenceScore || 0;
                reports = r.abuseipdb.totalReports || 0;
            }
            if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                const created = r.whois.creation_date ? new Date(r.whois.creation_date) : null;
                const expires = r.whois.expiration_date ? new Date(r.whois.expiration_date) : null;
                const now = new Date();
                
                whoisRegistrar = r.whois.registrar || '-';
                
                if (created) {
                    const ageDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
                    whoisAge = `${ageDays} days`;
                    whoisCreated = created.toLocaleDateString();
                }
                
                if (expires) {
                    whoisExpires = expires.toLocaleDateString();
                }
            }
            
            const text = `${ioc} | Type: ${r.type} | VT: ${malCount}/${total} | AbuseIPDB: ${abuseConf}%/${reports} | WHOIS: Age: ${whoisAge} | Expires: ${whoisExpires} | Registrar: ${whoisRegistrar}`;
            navigator.clipboard.writeText(text);
        }

        // Copy all bulk results
        function copyAllBulkResults() {
            let text = 'IOC | Type | VirusTotal | AbuseIPDB | WHOIS Age | WHOIS Expires | WHOIS Registrar\n';
            text += '--- | --- | --- | --- | --- | --- | ---\n';
            
            bulkResults.forEach(r => {
                let malCount = 0;
                let abuseConf = 0;
                let reports = 0;
                let total = 0;
                let whoisAge = '-';
                let whoisExpires = '-';
                let whoisRegistrar = '-';
                
                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    const stats = r.vt.data.attributes.last_analysis_stats;
                    total = Object.values(stats).reduce((a, b) => a + b, 0);
                    malCount = (stats.malicious || 0) + (stats.suspicious || 0);
                }
                if (r.abuseipdb && !r.abuseipdb.error) {
                    abuseConf = r.abuseipdb.abuseConfidenceScore || 0;
                    reports = r.abuseipdb.totalReports || 0;
                }
                if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                    const created = r.whois.creation_date ? new Date(r.whois.creation_date) : null;
                    const expires = r.whois.expiration_date ? new Date(r.whois.expiration_date) : null;
                    const now = new Date();
                    
                    whoisRegistrar = r.whois.registrar || '-';
                    
                    if (created) {
                        const ageDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
                        whoisAge = `${ageDays} days`;
                    }
                    
                    if (expires) {
                        whoisExpires = expires.toLocaleDateString();
                    }
                }
                
                text += `${r.ioc} | ${r.type} | ${malCount}/${total} | ${abuseConf}%/${reports} | ${whoisAge} | ${whoisExpires} | ${whoisRegistrar}\n`;
            });
            
            navigator.clipboard.writeText(text);
        }

        // Render single bulk result card
        function renderBulkResultCard(r) {
            let vtDetection = '-';
            let vtRisk = '-';
            let abuseConfidence = '-';
            let abuseReports = '-';
            let riskLevel = 'LOW';
            let badgeClass = 'clean';
            let analysisText = '';
            let recommendations = '';
            
            // VirusTotal data
            if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                const attrs = r.vt.data.attributes;
                const lastAnalysis = attrs.last_analysis_stats;
                const total = Object.values(lastAnalysis).reduce((a, b) => a + b, 0);
                const malCount = (lastAnalysis.malicious || 0) + (lastAnalysis.suspicious || 0);
                
                vtDetection = `<span class="vt-malicious">${malCount}</span>/<span class="vt-clean">${total}</span> detections`;
                vtRisk = malCount >= 5 ? 'HIGH' : malCount >= 2 ? 'MEDIUM' : 'LOW';
            } else if (r.vtError || (r.vt && r.vt.error)) {
                vtDetection = 'Error';
            }
            
            // AbuseIPDB data
            if (r.abuseipdb && !r.abuseipdb.error) {
                abuseConfidence = r.abuseipdb.abuseConfidenceScore + '%';
                abuseReports = r.abuseipdb.totalReports || 0;
            } else if (r.abuseError) {
                abuseConfidence = 'Error';
            }
            
            // WHOIS data
            let whoisCreated = '-';
            let whoisExpires = '-';
            let whoisRegistrar = '-';
            let whoisAge = '-';
            if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                if (r.whois.creation_date) {
                    const created = new Date(r.whois.creation_date);
                    whoisCreated = created.toLocaleDateString();
                    const ageDays = Math.floor((new Date() - created) / (1000 * 60 * 60 * 24));
                    whoisAge = `${ageDays} days`;
                }
                if (r.whois.expiration_date) {
                    whoisExpires = new Date(r.whois.expiration_date).toLocaleDateString();
                }
                whoisRegistrar = r.whois.registrar || '-';
            }
            
            // Determine combined risk
            let malCount = 0;
            let abuseConf = 0;
            
            if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                const stats = r.vt.data.attributes.last_analysis_stats;
                malCount = (stats.malicious || 0) + (stats.suspicious || 0);
            }
            if (r.abuseipdb && !r.abuseipdb.error) {
                abuseConf = r.abuseipdb.abuseConfidenceScore || 0;
            }
            
            const combinedRisk = malCount + (abuseConf > 50 ? 20 : 0);
            
            // Calculate threat score with TLD weighting
            let vtStats = null;
            if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                vtStats = r.vt.data.attributes.last_analysis_stats;
            }
            let domainAge = 0;
            if (r.whois && r.whois.creation_date) {
                domainAge = Math.floor((new Date() - new Date(r.whois.creation_date)) / (1000 * 60 * 60 * 24));
            }
            const threatScore = calculateThreatScore(r.ioc, vtStats, abuseConf, domainAge);
            
            // TLD badge
            const tldCat = getTldCategory(r.ioc);
            
                // Risk level based on threat score
            if (threatScore >= 80) {
                riskLevel = 'HIGH';
                badgeClass = 'malicious';
                analysisText = `The IP address ${r.ioc} has been reported multiple times for malicious activity with a high abuse confidence score of ${abuseConf}%. This indicator shows strong indicators of being involved in malicious activity.`;
                recommendations = `
                    <li>Block the IP address at firewall/IPS level</li>
                    <li>Check internal logs for any connections to this IP</li>
                    <li>Scan affected systems for indicators of compromise</li>
                    <li>Report to relevant abuse email (ISP/hosting provider)</li>
                `;
            } else if (threatScore >= 50) {
                riskLevel = 'MEDIUM';
                badgeClass = 'suspicious';
                analysisText = `The IP address ${r.ioc} has some suspicious indicators with ${malCount} VirusTotal detections and ${abuseConf}% abuse confidence. Further investigation is recommended.`;
                recommendations = `
                    <li>Monitor connections from this IP</li>
                    <li>Review firewall logs for any matches</li>
                    <li>Check if this activity is expected</li>
                `;
            } else {
                riskLevel = 'LOW';
                badgeClass = 'clean';
                analysisText = `The IP address ${r.ioc} shows no significant malicious indicators.`;
                recommendations = `<li>No immediate action required</li>`;
            }
            
            // TLD warning if applicable
            const tldWarningHtml = tldCat ? `<div style="margin-top:8px;padding:8px;background:rgba(248,81,73,0.1);border-left:3px solid #f85149;border-radius:4px;"><strong> TLD Warning:</strong> ${tldCat.label}</div>` : '';

            const linksHtml = r.type === 'ip' ? `
                <p style="margin-top:12px;"><strong>Links:</strong></p>
                <ul style="margin:8px 0;">
                    ${r.abuseipdb && !r.abuseipdb.error ? `<li><a href="https://www.abuseipdb.com/check/${r.ioc}" target="_blank" style="color:var(--accent-blue);">AbuseIPDB: https://www.abuseipdb.com/check/${r.ioc}</a></li>` : ''}
                    <li><a href="https://www.virustotal.com/gui/ip-address/${r.ioc}" target="_blank" style="color:var(--accent-blue);">VirusTotal: https://www.virustotal.com/gui/ip-address/${r.ioc}</a></li>
                </ul>
            ` : '';

            return `
                <div class="result-card" style="margin-bottom:16px;${riskLevel === 'HIGH' ? 'border-left:4px solid #ef4444;' : riskLevel === 'MEDIUM' ? 'border-left:4px solid #f59e0b;' : 'border-left:4px solid #22c55e;'}">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3>
                            <span class="ioc-cell" style="max-width:300px;">${r.ioc}</span>
                            <span class="category-badge ${badgeClass}">${riskLevel} RISK</span>
                        </h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <p><strong>Type:</strong> ${r.type.toUpperCase()}</p>
                        ${r.type === 'ip' ? `
                        <p><strong>AbuseIPDB Confidence:</strong> ${abuseConfidence}</p>
                        <p><strong>AbuseIPDB Total Reports:</strong> ${abuseReports}</p>
                        ` : ''}
                        ${(r.type === 'domain' || r.type === 'url') && whoisCreated !== '-' ? `
                        <p><strong>WHOIS Created:</strong> ${whoisCreated}</p>
                        <p><strong>WHOIS Expires:</strong> ${whoisExpires}</p>
                        <p><strong>WHOIS Registrar:</strong> ${whoisRegistrar}</p>
                        <p><strong>WHOIS Age:</strong> ${whoisAge}</p>
                        ` : ''}
                        <p><strong>VirusTotal:</strong> ${vtDetection} (${vtRisk} RISK)</p>
                        <p><strong>Threat Score:</strong> <span class="threat-score ${threatScore >= 80 ? 'threat-score-high' : threatScore >= 50 ? 'threat-score-medium' : 'threat-score-low'}">${threatScore}/100</span></p>
                        ${r.type === 'ip' && abuseConfidence !== '-' && abuseConfidence !== 'Error' ? `
                        <p style="margin-top:12px;"><strong>Analysis:</strong></p>
                        <p>${analysisText}</p>
                        ${linksHtml}
                        <p style="margin-top:12px;"><strong>Recommendations:</strong></p>
                        <ul style="margin:8px 0;padding-left:20px;">
                            ${recommendations}
                        </ul>
                        ` : ''}
                    </div>
                </div>
            `;
        }

        // Export Bulk Results to CSV
        function exportBulkCSV() {
            let csv = 'IOC,Type,VirusTotal Detection,Risk Level,AbuseIPDB Confidence,AbuseIPDB Reports,Domain,CountryCode,Hostnames,IsPublic,IsWhitelisted,UsageType,IPVersion,NumDistinctUsers,LastReportedAt,IsTor,WHOIS Created,WHOIS Expires,WHOIS Registrar,WHOIS Age\n';
            
            bulkResults.forEach(r => {
                let malCount = 0;
                let abuseConf = '-';
                let abuseRep = '-';
                let domain = '-';
                let countryCode = '-';
                let hostnames = '-';
                let isPublic = '-';
                let isWhitelisted = '-';
                let usageType = '-';
                let ipVersion = '-';
                let numDistinctUsers = '-';
                let lastReportedAt = '-';
                let isTor = '-';
                let whoisCreated = '-';
                let whoisExpires = '-';
                let whoisRegistrar = '-';
                let whoisAge = '-';
                
                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    const stats = r.vt.data.attributes.last_analysis_stats;
                    malCount = (stats.malicious || 0) + (stats.suspicious || 0);
                }
                if (r.abuseipdb && !r.abuseipdb.error) {
                    abuseConf = r.abuseipdb.abuseConfidenceScore + '%';
                    abuseRep = r.abuseipdb.totalReports || 0;
                    domain = r.abuseipdb.domain || '-';
                    countryCode = r.abuseipdb.countryCode || '-';
                    hostnames = r.abuseipdb.hostnames ? r.abuseipdb.hostnames.join('; ') : '-';
                    isPublic = r.abuseipdb.isPublic !== undefined ? (r.abuseipdb.isPublic ? 'TRUE' : 'FALSE') : '-';
                    isWhitelisted = r.abuseipdb.isWhitelisted ? 'TRUE' : 'FALSE';
                    usageType = r.abuseipdb.usageType || '-';
                    ipVersion = r.abuseipdb.ipVersion || '-';
                    numDistinctUsers = r.abuseipdb.numDistinctUsers || 0;
                    lastReportedAt = r.abuseipdb.lastReportedAt || '-';
                    isTor = r.abuseipdb.isTor ? 'TRUE' : 'FALSE';
                }
                if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                    if (r.whois.creation_date) {
                        const created = new Date(r.whois.creation_date);
                        whoisCreated = created.toLocaleDateString();
                        const ageDays = Math.floor((new Date() - created) / (1000 * 60 * 60 * 24));
                        whoisAge = `${ageDays} days`;
                    }
                    whoisExpires = r.whois.expiration_date ? new Date(r.whois.expiration_date).toLocaleDateString() : '-';
                    whoisRegistrar = r.whois.registrar || '-';
                }
                
                const risk = malCount > 10 || (r.abuseipdb && r.abuseipdb.abuseConfidenceScore > 75) ? 'HIGH' : 
                             malCount > 0 || (r.abuseipdb && r.abuseipdb.abuseConfidenceScore > 25) ? 'MEDIUM' : 'LOW';
                
                csv += `"${r.ioc}","${r.type}","${malCount}","${risk}","${abuseConf}","${abuseRep}","${domain}","${countryCode}","${hostnames}","${isPublic}","${isWhitelisted}","${usageType}","${ipVersion}","${numDistinctUsers}","${lastReportedAt}","${isTor}","${whoisCreated}","${whoisExpires}","${whoisRegistrar}","${whoisAge}"\n`;
            });
            
            downloadFile(csv, 'bulk_scan_results.csv', 'text/csv');
        }

        // Export Single Result to TXT - SOC Report Format
        function exportTXT() {
            if (!currentResults.ioc) {
                showToast('No results to export', 'warning');
                return;
            }
            
            const ioc = currentResults.ioc;
            const type = currentResults.type || 'N/A';
            
            // Calculate threat intelligence
            let vtMalicious = 0;
            let vtTotal = 0;
            let vtResult = 'No security vendors flagged the indicator as malicious';
            if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                const stats = currentResults.vt.data.attributes.last_analysis_stats;
                vtTotal = Object.values(stats).reduce((a, b) => a + b, 0);
                vtMalicious = stats.malicious + stats.suspicious;
                if (vtMalicious > 0) {
                    vtResult = vtMalicious + ' security vendors flagged the indicator as malicious';
                }
            }
            
            let abuseResult = 'No abuse reports were identified';
            let abuseConfidence = 0;
            let isWhitelisted = false;
            if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
                abuseConfidence = currentResults.abuseipdb.abuseConfidenceScore || 0;
                const totalReports = currentResults.abuseipdb.totalReports || 0;
                isWhitelisted = currentResults.abuseipdb.isWhitelisted || false;
                if (isWhitelisted) {
                    abuseResult = 'No abuse reports were identified and the IP is listed as whitelisted';
                } else if (totalReports > 0) {
                    abuseResult = totalReports + ' abuse reports were identified';
                }
            }
            
            // Determine threat reputation
            let threatReputation = 'Inconclusive';
            if (vtMalicious > 10 || abuseConfidence > 75) threatReputation = 'Malicious';
            else if (vtMalicious > 0 || abuseConfidence > 50) threatReputation = 'Suspicious';
            else if (vtMalicious === 0 && abuseConfidence === 0) threatReputation = 'Clean';
            
            // Domain age analysis
            let domainAge = 'N/A';
            let ageClassification = 'N/A';
            let creationDate = null;
            if (currentResults.whois && currentResults.whois.creation_date) {
                creationDate = new Date(currentResults.whois.creation_date);
                const ageMs = new Date() - creationDate;
                const ageMonths = Math.floor(ageMs / (30.44 * 24 * 60 * 60 * 1000));
                const ageYears = (ageMonths / 12).toFixed(1);
                
                if (ageMonths < 6) {
                    ageClassification = 'Suspicious';
                    domainAge = ageMonths + ' months';
                } else if (ageMonths < 12) {
                    ageClassification = 'Medium Suspicion';
                    domainAge = ageMonths + ' months';
                } else if (ageMonths < 24) {
                    ageClassification = 'Low Risk';
                    domainAge = ageYears + ' years';
                } else {
                    ageClassification = 'Low Risk / Neutral';
                    domainAge = ageYears + ' years';
                }
            }
            
            // Infrastructure
            let ipAddress = 'N/A';
            let hostingProvider = 'N/A';
            let asn = 'N/A';
            let country = 'N/A';
            let infraObservations = 'No infrastructure data available';
            
            if (currentResults.abuseipdb && currentResults.abuseipdb.ipAddress) {
                ipAddress = currentResults.abuseipdb.ipAddress;
                hostingProvider = currentResults.abuseipdb.isp || currentResults.abuseipdb.hostname || 'N/A';
                asn = currentResults.abuseipdb.asn || 'N/A';
                country = currentResults.abuseipdb.countryName || 'N/A';
                
                const hostingLower = hostingProvider.toLowerCase();
                if (hostingLower.includes('amazon') || hostingLower.includes('aws') || 
                    hostingLower.includes('google') || hostingLower.includes('cloud') ||
                    hostingLower.includes('azure') || hostingLower.includes('microsoft')) {
                    infraObservations = ' Hosted on major cloud provider\n Cloud and internet service provider\n No suspicious infrastructure indicators observed';
                } else if (hostingLower.includes('ovh') || hostingLower.includes('digitalocean') || hostingLower.includes('linode')) {
                    infraObservations = ' Hosted on cloud/virtualization platform\n Could be legitimate or malicious use\n Further investigation recommended';
                } else {
                    infraObservations = ' Hosting provider identified\n Standard hosting profile\n No obvious suspicious indicators';
                }
            }
            
            let infraAssessment = 'Unable to assess';
            if (ipAddress !== 'N/A') {
                if (threatReputation === 'Clean') infraAssessment = 'Legitimate';
                else if (threatReputation === 'Malicious') infraAssessment = 'Potentially Suspicious - associated with malicious activity';
                else infraAssessment = 'Further investigation needed';
            }
            
            // Final verdict
            let finalRiskRating = 'Medium Risk';
            let conclusion = '';
            
            if (threatReputation === 'Malicious' || ageClassification === 'Suspicious') {
                finalRiskRating = 'High Risk';
                conclusion = 'Multiple indicators suggest malicious activity. Domain age is concerning and threat intelligence sources report malicious activity.';
            } else if (threatReputation === 'Suspicious' || ageClassification === 'Medium Suspicion') {
                finalRiskRating = 'Medium Risk';
                conclusion = 'Some indicators require attention. Further investigation recommended before making security decisions.';
            } else if (threatReputation === 'Clean' && ageClassification === 'Low Risk / Neutral') {
                finalRiskRating = 'Low Risk';
                conclusion = 'No malicious indicators were identified across WHOIS data, threat intelligence sources, or infrastructure analysis.';
            } else {
                finalRiskRating = 'Low Risk';
                conclusion = 'No malicious indicators were identified.';
            }
            
            // Build report
            let txt = '';
            txt += 'Indicator: ' + ioc + '\n';
            txt += 'Investigation Type: Threat Intelligence / Infrastructure Analysis\n';
            txt += '\n';
            txt += '--------------------------------------------------\n';
            txt += '\n';
            txt += '1. Domain Age Analysis (WHOIS)\n';
            txt += '\n';
            if (creationDate) {
                txt += 'The domain ' + ioc + ' was registered on ' + creationDate.toLocaleDateString('en-GB') + '. At the time of investigation, the domain age is approximately ' + domainAge + '.\n';
            } else {
                txt += 'WHOIS data not available for this indicator.\n';
            }
            txt += '\n';
            txt += 'Domain Age Risk Classification:\n';
            txt += ' < 6 months  Suspicious\n';
            txt += ' 612 months  Medium Suspicion\n';
            txt += ' > 12 months  Low Risk / Neutral\n';
            txt += '\n';
            txt += 'Assessment:\n';
            txt += 'Domain age classification: ' + ageClassification + '.\n';
            txt += '\n';
            txt += '--------------------------------------------------\n';
            txt += '\n';
            txt += '2. Threat Intelligence Correlation\n';
            txt += '\n';
            txt += 'VirusTotal:\n';
            txt += vtResult + '.\n';
            txt += '\n';
            txt += 'AbuseIPDB:\n';
            txt += abuseResult + '.\n';
            txt += '\n';
            txt += 'Assessment:\n';
            txt += 'Threat intelligence reputation is assessed as ' + threatReputation + '.\n';
            txt += '\n';
            txt += '--------------------------------------------------\n';
            txt += '\n';
            txt += '3. Infrastructure Analysis (ASN / Hosting)\n';
            txt += '\n';
            txt += 'IP Address: ' + ipAddress + '\n';
            txt += 'Hosting Provider / Organization: ' + hostingProvider + '\n';
            txt += 'ASN: ' + asn + '\n';
            txt += 'Country: ' + country + '\n';
            txt += '\n';
            txt += 'Infrastructure Observations:\n';
            txt += infraObservations + '\n';
            txt += '\n';
            txt += 'Assessment:\n';
            txt += 'Infrastructure appears ' + infraAssessment + '.\n';
            txt += '\n';
            txt += '--------------------------------------------------\n';
            txt += '\n';
            txt += '4. Final Verdict\n';
            txt += '\n';
            txt += 'Final Risk Rating: ' + finalRiskRating + '\n';
            txt += '\n';
            txt += 'Conclusion:\n';
            txt += 'Based on the analysis of domain age, threat intelligence reputation, and infrastructure context, ' + ioc + ' is assessed as ' + finalRiskRating + '. ' + conclusion + '\n';
            txt += '\n';
            txt += '--------------------------------------------------\n';
            txt += '\n';
            txt += '5. Analyst Reference Links\n';
            txt += '\n';
            if (currentResults.abuseipdb && currentResults.abuseipdb.ipAddress) {
                txt += 'AbuseIPDB:\n';
                txt += 'https://www.abuseipdb.com/check/' + currentResults.abuseipdb.ipAddress + '\n';
            }
            txt += 'VirusTotal:\n';
            if (type === 'ip') {
                txt += 'https://www.virustotal.com/gui/ip-address/' + ioc + '\n';
            } else if (type === 'domain') {
                txt += 'https://www.virustotal.com/gui/domain/' + ioc + '\n';
            } else {
                txt += 'https://www.virustotal.com/gui/search/' + ioc + '\n';
            }
            txt += 'WHOIS Lookup:\n';
            txt += 'https://www.whois.com/whois/' + ioc + '\n';
            
            downloadFile(txt, 'threatscan_report.txt', 'text/plain');
            showToast('Report exported!', 'success');
        }

        // Export Bulk Results to TXT
        function exportBulkTXT() {
            let txt = 'BULK IOC SCAN RESULTS\n';
            txt += '===================\n\n';
            
            bulkResults.forEach(r => {
                let malCount = 0;
                let abuseConf = 'N/A';
                let abuseRep = 'N/A';
                
                txt += `IOC: ${r.ioc}\n`;
                txt += `Type: ${r.type}\n`;
                
                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    const stats = r.vt.data.attributes.last_analysis_stats;
                    const total = Object.values(stats).reduce((a, b) => a + b, 0);
                    malCount = (stats.malicious || 0) + (stats.suspicious || 0);
                    txt += `VirusTotal: ${malCount}/${total} detections\n`;
                }
                if (r.abuseipdb && !r.abuseipdb.error) {
                    abuseConf = r.abuseipdb.abuseConfidenceScore + '%';
                    abuseRep = r.abuseipdb.totalReports || 0;
                    txt += `AbuseIPDB Confidence: ${abuseConf}\n`;
                    txt += `AbuseIPDB Total Reports: ${abuseRep}\n`;
                    txt += `Domain: ${r.abuseipdb.domain || 'N/A'}\n`;
                    txt += `Country Code: ${r.abuseipdb.countryCode || 'N/A'}\n`;
                    txt += `Hostnames: ${r.abuseipdb.hostnames ? r.abuseipdb.hostnames.join(', ') : 'N/A'}\n`;
                    txt += `Is Public: ${r.abuseipdb.isPublic !== undefined ? (r.abuseipdb.isPublic ? 'Yes' : 'No') : 'N/A'}\n`;
                    txt += `Is Whitelisted: ${r.abuseipdb.isWhitelisted ? 'Yes' : 'No'}\n`;
                    txt += `Usage Type: ${r.abuseipdb.usageType || 'N/A'}\n`;
                    txt += `IP Version: ${r.abuseipdb.ipVersion || 'N/A'}\n`;
                    txt += `Num Distinct Users: ${r.abuseipdb.numDistinctUsers || 0}\n`;
                    txt += `Last Reported At: ${r.abuseipdb.lastReportedAt || 'N/A'}\n`;
                    txt += `Is Tor: ${r.abuseipdb.isTor ? 'Yes' : 'No'}\n`;
                }
                txt += '\n';
            });
            
            downloadFile(txt, 'bulk_scan_results.txt', 'text/plain');
        }

        function showLoading(target) {
            const container = document.getElementById(target + 'Results');
            if (!container) return;
            let loadingText = '';
            if (target === 'vt') loadingText = 'Scanning VirusTotal...';
            else if (target === 'abuseipdb') loadingText = 'Scanning AbuseIPDB...';
            else if (target === 'whois') loadingText = 'Querying WHOIS...';
            else if (target === 'urlscan') loadingText = 'Querying URLScan.io...';
            else loadingText = `Scanning ${target}...`;
            
            container.innerHTML = `
                <div class="loading">
                    <div class="spinner"></div>
                    <span>${loadingText}</span>
                </div>
            `;
            const emptyEl = document.getElementById(target + 'Empty');
            if (emptyEl) emptyEl.style.display = 'none';
        }

        function showError(target, message) {
            console.error(`Error in ${target}:`, message);
            const container = document.getElementById(target + 'Results');
            if (container) {
                container.innerHTML = `<div class="error-message">${message}</div>`;
            }
            const emptyEl = document.getElementById(target + 'Empty');
            if (emptyEl) {
                emptyEl.style.display = 'none';
            }
            // Also show toast for visibility
            showToast(message, 'error');
        }

        // CORS Proxy (fallback when direct API calls fail)
        // Using corsproxy.io which supports custom headers
        const CORS_PROXY = 'https://corsproxy.io/?';
        
        // TLD Risk Weights for threat scoring
        const TLD_RISK_WEIGHTS = {
            // High risk - Anonymous/Darknet
            '.onion': 30,
            '.i2p': 30,
            '.b32.i2p': 30,
            '.exit': 25,
            '.anon': 25,
            '.bazar': 30,
            '.glass': 25,
            // Medium-High risk - Crypto/DNS
            '.loki': 20,
            '.snode': 20,
            '.loki.network': 20,
            '.bit': 20,
            '.crypto': 15,
            '.coin': 15,
            '.emc': 15,
            '.neo': 15,
            '.pirate': 15,
            // Medium risk
            '.free': 10,
            '.gopher': 10,
            '.ku': 10,
            '.lib': 10,
            '.l2p': 15
        };
        
        // Get TLD from domain/URL
        function getTld(ioc) {
            try {
                // For URLs, extract the domain first
                let domain = ioc;
                if (ioc.startsWith('http://') || ioc.startsWith('https://')) {
                    domain = new URL(ioc).hostname;
                }
                const parts = domain.split('.');
                if (parts.length >= 2) {
                    return '.' + parts[parts.length - 1];
                }
            } catch (e) {}
            return '';
        }
        
        // Calculate threat score with TLD weighting
        function calculateThreatScore(ioc, vtStats, abuseScore, domainAge) {
            let score = 0;
            
            // VirusTotal: 5+ = HIGH (+80), 2-4 = MEDIUM (+50)
            if (vtStats) {
                const vtMalicious = (vtStats.malicious || 0);
                const vtSuspicious = (vtStats.suspicious || 0);
                const vtTotal = vtMalicious + vtSuspicious;
                if (vtTotal >= 5) {
                    score += 80;
                } else if (vtTotal >= 2) {
                    score += 50;
                } else if (vtTotal > 0) {
                    score += 10;
                }
            }
            
            // AbuseIPDB: if >55% confidence, it's HIGH (+80)
            if (abuseScore > 55) {
                score += 80;
            } else if (abuseScore > 25) {
                score += 20;
            } else if (abuseScore > 0) {
                score += 10;
            }
            
            // Domain age: +15 if <30 days, +5 if <180 days
            if (domainAge > 0) {
                if (domainAge < 30) score += 15;
                else if (domainAge < 180) score += 5;
            }
            
            // TLD risk - Add +80 for risky TLDs
            const tld = getTld(ioc);
            if (TLD_RISK_WEIGHTS[tld]) {
                score += 80;
            }
            
            return Math.min(score, 100);
        }
        
        // Get TLD category label
        function getTldCategory(ioc) {
            const tld = getTld(ioc);
            const highRisk = ['.onion', '.i2p', '.b32.i2p', '.bazar'];
            const cryptoRisk = ['.crypto', '.coin', '.bit', '.neo', '.emc'];
            
            if (highRisk.includes(tld)) return { label: 'Privacy Network', class: 'tld-warning' };
            if (cryptoRisk.includes(tld)) return { label: 'Crypto DNS', class: 'tld-warning' };
            if (TLD_RISK_WEIGHTS[tld]) return { label: 'Alt TLD', class: 'tld-medium' };
            return null;
        }
        
        // VirusTotal API
        async function scanVirusTotal(ioc, type) {
            const keys = getKeys();
            let endpoint = '';

            try {
                switch (type) {
                    case 'ip':
                        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
                        break;
                    case 'domain':
                        endpoint = `https://www.virustotal.com/api/v3/domains/${ioc}`;
                        break;
                    case 'url':
                        // Need to encode URL for VT (base64 without padding)
                        const urlId = btoa(ioc).replace(/=+$/, '');
                        endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
                        break;
                    case 'hash':
                        endpoint = `https://www.virustotal.com/api/v3/files/${ioc}`;
                        break;
                    default:
                        throw new Error('Unknown IOC type');
                }

                console.log('VirusTotal request:', endpoint);

                // Try direct API call first (no proxy)
                let response;
                try {
                    response = await fetch(endpoint, {
                        headers: {
                            'x-apikey': keys.vt,
                            'Content-Type': 'application/json'
                        }
                    });
                } catch (directError) {
                    // If direct fails, try with CORS proxy
                    const proxyUrl = CORS_PROXY + encodeURIComponent(endpoint);
                    response = await fetch(proxyUrl, {
                        headers: {
                            'x-apikey': keys.vt,
                            'Content-Type': 'application/json'
                        }
                    });
                }

                if (!response.ok) {
                    if (response.status === 404) {
                        throw new Error('No results found in VirusTotal (404)');
                    }
                    if (response.status === 429) {
                        throw new Error('Rate limited - please wait and try again');
                    }
                    if (response.status === 403) {
                        throw new Error('Access denied - check API key');
                    }
                    throw new Error(`API error: ${response.status}`);
                }

                const data = await response.json();
                console.log('VirusTotal response:', data);
                currentResults.vt = data;
                renderVirusTotal(data);
                
                // Update combined view
                const combinedContainer = document.getElementById('combinedResults');
                if (combinedContainer && currentResults.abuseipdb) {
                    renderCombined();
                }

            } catch (error) {
                console.error('VirusTotal Error:', error);
                if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                    showError('vt', 'Network error - check connection and try again');
                } else {
                    showError('vt', error.message);
                }
            }
        }

        function renderVirusTotal(data) {
            const container = document.getElementById('vtResults');
            if (!container || !data || !data.data || !data.data.attributes) {
                if (container) {
                    container.innerHTML = '<div class="error-message">VirusTotal data not available.</div>';
                }
                const emptyEl = document.getElementById('vtEmpty');
                if (emptyEl) emptyEl.style.display = 'none';
                return;
            }
            const d = data.data.attributes;
            
            // Detection stats
            const stats = d.last_analysis_stats || {};
            const total = Object.values(stats).reduce((a, b) => a + b, 0);
            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const undetected = stats.undetected || 0;
            const harmless = stats.harmless || 0;

            // Calculate percentages for bar
            const maliciousPct = total > 0 ? (malicious / total) * 100 : 0;
            const suspiciousPct = total > 0 ? (suspicious / total) * 100 : 0;
            const undetectedPct = total > 0 ? (undetected / total) * 100 : 0;
            const harmlessPct = total > 0 ? (harmless / total) * 100 : 0;

            // Popularity rank
            const popularity = d.popularity_ranks || {};
            let popularityHtml = '';
            for (const [source, info] of Object.entries(popularity)) {
                popularityHtml += `<span class="ioc-tag" title="Rank: ${info.rank}">${source}: #${info.rank}</span>`;
            }

            // Threat labels
            const threatLabels = d.threat_labels || [];
            const threatLabelsHtml = threatLabels.length > 0 
                ? threatLabels.map(l => `<span class="category-badge malicious">${l}</span>`).join(' ')
                : '<span class="category-badge undetected">None</span>';

            // Engine results
            const engines = d.last_analysis_results || {};
            const engineResults = Object.entries(engines).map(([name, result]) => ({
                name,
                category: result.category,
                result: result.result,
                method: result.method,
                engine_version: result.engine_version
            }));

            // Community vote
            const vote = d.user_votes || { harmless: 0, malicious: 0, suspicious: 0 };

            // Sandbox verdicts
            const sandbox = d.sandbox_verdicts || {};
            const sandboxHtml = Object.entries(sandbox).length > 0
                ? Object.entries(sandbox).map(([sandboxName, verdict]) => `
                    <tr>
                        <td>${sandboxName}</td>
                        <td><span class="category-badge ${(verdict.category || 'undetected').toLowerCase()}">${verdict.category || 'N/A'}</span></td>
                        <td>${verdict.malware_classification || '-'}</td>
                        <td>${verdict.threat === '-' ? '-' : verdict.threat}</td>
                    </tr>
                `).join('')
                : '<tr><td colspan="4" style="text-align: center; color: var(--text-muted)">No sandbox results</td></tr>';

            // File specific info
            let fileInfoHtml = '';
            if (d.size && d.type_description) {
                fileInfoHtml = `
                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> File Information</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <tr><th style="width: 200px;">Property</th><th>Value</th></tr>
                            <tr><td>File Type</td><td>${d.type_description || 'N/A'}</td></tr>
                            <tr><td>File Size</td><td>${(d.size / 1024).toFixed(2)} KB</td></tr>
                            <tr><td>Magic Signature</td><td>${d.trid || 'N/A'}</td></tr>
                            <tr><td>SHA256</td><td>${d.sha256 || 'N/A'}</td></tr>
                            <tr><td>SHA1</td><td>${d.sha1 || 'N/A'}</td></tr>
                            <tr><td>MD5</td><td>${d.md5 || 'N/A'}</td></tr>
                        </table>
                    </div>
                </div>
                `;
            }

            // Last analysis breakdown
            const lastAnalysis = d.last_analysis_date ? new Date(d.last_analysis_date * 1000).toLocaleString() : 'N/A';
            const firstSubmission = d.first_submission_date ? new Date(d.first_submission_date * 1000).toLocaleString() : 'N/A';
            const lastMod = d.last_modification_date ? new Date(d.last_modification_date * 1000).toLocaleString() : 'N/A';

            container.innerHTML = `
                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Detection Summary</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <div class="stats-grid">
                            <div class="stat-box">
                                <div class="stat-value malicious">${malicious}</div>
                                <div class="stat-label">Malicious</div>
                            </div>
                            <div class="stat-box">
                                <div class="stat-value suspicious">${suspicious}</div>
                                <div class="stat-label">Suspicious</div>
                            </div>
                            <div class="stat-box">
                                <div class="stat-value clean">${harmless}</div>
                                <div class="stat-label">Harmless</div>
                            </div>
                            <div class="stat-box">
                                <div class="stat-value undetected">${undetected}</div>
                                <div class="stat-label">Undetected</div>
                            </div>
                        </div>
                        <div class="detection-bar">
                            <div class="detection-segment malicious" style="width: ${maliciousPct}%"></div>
                            <div class="detection-segment suspicious" style="width: ${suspiciousPct}%"></div>
                            <div class="detection-segment harmless" style="width: ${harmlessPct}%"></div>
                            <div class="detection-segment undetected" style="width: ${undetectedPct}%"></div>
                        </div>
                        <div style="text-align: center; color: var(--text-secondary); margin-top: 12px;">
                            Detection Ratio: <strong>${malicious + suspicious}/${total}</strong> engines detected threats
                        </div>
                    </div>
                </div>

                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Key Information</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <tr><th style="width: 200px;">Property</th><th>Value</th></tr>
                            <tr><td>First Submission</td><td>${firstSubmission}</td></tr>
                            <tr><td>Last Analysis</td><td>${lastAnalysis}</td></tr>
                            <tr><td>Last Modification</td><td>${lastMod}</td></tr>
                            <tr><td>Threat Labels</td><td>${threatLabelsHtml}</td></tr>
                            <tr><td>Popularity Rank</td><td>${popularityHtml || '<span style="color: var(--text-muted)">No data</span>'}</td></tr>
                            <tr><td>Community Votes</td><td>
                                <span style="color: var(--accent-green)"> ${vote.harmless} harmless</span> | 
                                <span style="color: var(--accent-red)"> ${vote.malicious} malicious</span> | 
                                <span style="color: var(--accent-yellow)"> ${vote.suspicious} suspicious</span>
                            </td></tr>
                        </table>
                    </div>
                </div>

                ${fileInfoHtml}

                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Engine Results (${engineResults.length} engines)</h3>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <select id="engineFilter" onchange="filterEngineResults()" style="padding:4px 8px;border-radius:4px;background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border);font-size:11px;">
                                <option value="all">All Engines</option>
                                <option value="malicious">Malicious Only</option>
                                <option value="suspicious">Suspicious Only</option>
                                <option value="harmless">Harmless Only</option>
                                <option value="undetected">Undetected Only</option>
                            </select>
                            <span></span>
                        </div>
                    </div>
                    <div class="card-body">
                        <table class="data-table" id="engineResultsTable">
                            <thead>
                                <tr><th>Engine</th><th>Category</th><th>Result</th><th>Method</th></tr>
                            </thead>
                            <tbody id="engineResultsBody">
                                ${engineResults.sort((a, b) => a.name.localeCompare(b.name)).map(e => `
                                    <tr data-category="${e.category || ''}">
                                        <td>${e.name}</td>
                                        <td><span class="category-badge ${e.category || 'undetected'}">${e.category || 'N/A'}</span></td>
                                        <td>${e.result || '-'}</td>
                                        <td>${e.method || '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Sandbox Verdicts</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <thead>
                                <tr><th>Sandbox</th><th>Category</th><th>Malware Class</th><th>Threat</th></tr>
                            </thead>
                            <tbody>
                                ${sandboxHtml}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Raw JSON Data</h3>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <button class="copy-btn-small" onclick="event.stopPropagation();copyRawJSON('vt')">Copy JSON</button>
                            <span></span>
                        </div>
                    </div>
                    <div class="card-body">
                        <pre class="json-view" id="rawJsonVt">${JSON.stringify(data, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        // Copy raw JSON
        function copyRawJSON(type) {
            const el = document.getElementById(type === 'vt' ? 'rawJsonVt' : 'rawJsonAbuse');
            if (el) {
                navigator.clipboard.writeText(el.textContent);
            }
        }

        // Filter engine results
        function filterEngineResults() {
            const filter = document.getElementById('engineFilter');
            if (!filter) return;
            const filterValue = filter.value;
            const rows = document.querySelectorAll('#engineResultsBody tr');
            rows.forEach(row => {
                const category = row.getAttribute('data-category');
                if (filterValue === 'all') {
                    row.style.display = '';
                } else {
                    row.style.display = category === filterValue ? '' : 'none';
                }
            });
        }

        // AbuseIPDB API
        async function scanAbuseIPDB(ioc) {
            const keys = getKeys();
            let ipToQuery = ioc;
            let resolvedFromDomain = null;

            try {
                // Check if input is a hash - AbuseIPDB doesn't support hash searches
                const iocType = detectIOCType(ioc);
                if (iocType === 'hash') {
                    showError('abuseipdb', 'AbuseIPDB does not support hash searches. It only supports IP addresses and domains.');
                    return;
                }

                // Check if input is a domain/URL and resolve to IP
                if (iocType === 'domain' || iocType === 'url') {
                    const domain = extractDomain(ioc);
                    const resolvedIP = await resolveDNS(domain);
                    if (resolvedIP) {
                        resolvedFromDomain = domain;
                        ipToQuery = resolvedIP;
                        console.log(`Resolved ${domain} to ${resolvedIP}`);
                    } else {
                        showError('abuseipdb', `Could not resolve domain ${domain} to IP address`);
                        return;
                    }
                }

                // Query AbuseIPDB API
                const response = await fetch(CORS_PROXY + encodeURIComponent(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipToQuery)}&maxAgeInDays=90&verbose=`), {
                    headers: {
                        'Key': keys.abuseipdb,
                        'Accept': 'application/json'
                    }
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch IP information from AbuseIPDB');
                }

                const data = await response.json();
                const ipData = data.data;

                console.log('AbuseIPDB response:', ipData);

                // Add resolved domain info to the result
                if (resolvedFromDomain) {
                    ipData.resolvedFrom = resolvedFromDomain;
                }

                currentResults.abuseipdb = ipData;
                renderAbuseIPDB(ipData);
                
                // Update combined view
                const combinedContainer = document.getElementById('combinedResults');
                if (combinedContainer && currentResults.vt) {
                    renderCombined();
                }

            } catch (error) {
                console.error('AbuseIPDB Error:', error);
                showError('abuseipdb', error.message);
            }
        }

        // DNS Resolution function
        async function resolveDNS(domain) {
            try {
                // Use Google's DNS-over-HTTPS API
                const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
                if (!response.ok) {
                    return null;
                }
                const data = await response.json();
                
                // Find first A record (IPv4)
                if (data.Answer) {
                    for (const answer of data.Answer) {
                        if (answer.type === 1) { // Type 1 is A record
                            return answer.data;
                        }
                    }
                }
                return null;
            } catch (error) {
                console.error('DNS resolution error:', error);
                return null;
            }
        }

        // WHOIS API (APILayer)
        async function scanWhois(ioc) {
            const keys = getKeys();
            
            // Extract domain from URL if needed
            let domain = extractDomain(ioc);
            
            // Get base domain (removes subdomains) for WHOIS lookup
            // WHOIS only works with base domains, not subdomains
            const baseDomain = extractBaseDomain(domain);
            console.log('WHOIS API Key present:', !!keys.whois, 'Key:', keys.whois ? keys.whois.substring(0, 5) + '...' : 'none', 'Domain:', baseDomain);
            
            // Check for unsupported TLDs
            const unsupportedTLDs = ['.onion', '.i2p', '.bit', '.zero', '.exit'];
            const isUnsupportedTLD = unsupportedTLDs.some(tld => baseDomain.toLowerCase().endsWith(tld));
            
            if (isUnsupportedTLD) {
                showError('whois', 'WHOIS lookup not supported for this TLD (.onion domains use Tor network)');
                return;
            }

            try {
                // Query WHOIS API with base domain
                const response = await fetch(`https://api.apilayer.com/whois/query?domain=${encodeURIComponent(baseDomain)}`, {
                    headers: {
                        'APIKEY': keys.whois
                    }
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorText || 'Failed to fetch WHOIS information'}`);
                }

                const data = await response.json();
                
                if (data.result) {
                    console.log('WHOIS response:', data.result);
                    currentResults.whois = data.result;
                    renderWhois(data.result);
                    
                    // Update combined view
                    const combinedContainer = document.getElementById('combinedResults');
                    if (combinedContainer && currentResults.vt) {
                        renderCombined();
                    }
                } else {
                    showError('whois', 'No WHOIS data found for this domain');
                }

            } catch (error) {
                console.error('WHOIS Error:', error);
                showError('whois', error.message);
            }
        }

        // URLScan.io API
        async function scanURLScan(ioc) {
            const keys = getKeys();
            
            // Extract domain from URL if needed
            let domain = extractDomain(ioc);
            
            console.log('URLScan API Key present:', !!keys.urlscan, 'Key:', keys.urlscan ? keys.urlscan.substring(0, 5) + '...' : 'none', 'Domain:', domain);
            
            try {
                // Use the search endpoint filtered by domain
                // Build the search query as a plain string first
                const searchQuery = `domain:${domain}`;
                // Encode the query once
                const encodedQuery = encodeURIComponent(searchQuery);
                // Construct the API URL
                const urlscanUrl = `https://urlscan.io/api/v1/search/?q=${encodedQuery}&size=25`;
                // If using the CORS proxy, encode the entire URL only once
                const proxyUrl = `https://corsproxy.io/?${encodeURIComponent(urlscanUrl)}`;
                
                const response = await fetch(proxyUrl, {
                    headers: {
                        'API-Key': keys.urlscan,
                        'Accept': 'application/json'
                    }
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorText || 'Failed to fetch URLScan data'}`);
                }

                const data = await response.json();
                console.log('URLScan search results:', data.total, 'results');
                if (data.results && data.results.length > 0) {
                    console.log('First result:', data.results[0]?._id, 'page.domain:', data.results[0]?.page?.domain, 'apexDomain:', data.results[0]?.page?.apexDomain);
                    // Pick the best matching result for the queried domain
                    const normalizeHost = (value) => {
                        if (!value || typeof value !== 'string') return '';
                        let host = value.trim().toLowerCase();
                        host = host.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/$/, '');
                        return host;
                    };

                    const requestedHost = normalizeHost(domain);
                    const getPrimaryTaskHost = (value) => {
                        if (!value || typeof value !== 'string') return '';
                        try {
                            return normalizeHost(new URL(value).hostname);
                        } catch (_) {
                            return normalizeHost(value);
                        }
                    };

                    const normalizeHostFromUrl = (value) => {
                        if (!value || typeof value !== 'string') return '';
                        try {
                            return normalizeHost(new URL(value).hostname);
                        } catch (_) {
                            return normalizeHost(value);
                        }
                    };

                    // Simple domain match: exact or subdomain of query domain
                    const domainMatch = (resultUrl, queryDomain) => {
                        if (!resultUrl || !queryDomain) return false;
                        try {
                            const host = new URL(resultUrl).hostname.toLowerCase();
                            const domain = queryDomain.toLowerCase();
                            return host === domain || host.endsWith('.' + domain);
                        } catch (_) {
                            return false;
                        }
                    };

                    // Find first result where page.apexDomain matches query domain
                    let searchResult = null;
                    let effectiveUrl = '';

                    for (const result of data.results) {
                        const pageUrl = result?.page?.url || '';
                        const taskUrl = result?.task?.url || '';
                        const apexDomain = result?.page?.apexDomain || '';
                        const pageDomain = result?.page?.domain || '';

                        // Use apexDomain for accurate root domain matching
                        if (apexDomain && apexDomain.toLowerCase() === requestedHost.toLowerCase()) {
                            searchResult = result;
                            effectiveUrl = pageUrl || taskUrl;
                            break;
                        }
                        // Fallback: check page.domain for subdomain matches
                        if (pageDomain && requestedHost && (
                            pageDomain.toLowerCase() === requestedHost ||
                            pageDomain.toLowerCase().endsWith('.' + requestedHost)
                        )) {
                            searchResult = result;
                            effectiveUrl = pageUrl || taskUrl;
                            break;
                        }
                    }

                    if (!searchResult) {
                        // Fallback: try broader search with page.url query
                        const fallbackQuery = `page.url:*${requestedHost}*`;
                        const fallbackUrl = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(fallbackQuery)}&size=10`;
                        const fallbackProxyUrl = `https://corsproxy.io/?${encodeURIComponent(fallbackUrl)}`;
                        
                        try {
                            const fallbackResponse = await fetch(fallbackProxyUrl, {
                                headers: {
                                    'API-Key': keys.urlscan,
                                    'Accept': 'application/json'
                                }
                            });
                            if (fallbackResponse.ok) {
                                const fallbackData = await fallbackResponse.json();
                                if (fallbackData.results && fallbackData.results.length > 0) {
                                    // Use first fallback result
                                    searchResult = fallbackData.results[0];
                                    console.log('URLScan fallback found result:', searchResult?._id);
                                }
                            }
                        } catch (e) {
                            console.error('URLScan fallback query failed:', e);
                        }
                        
                        if (!searchResult) {
                            showError('urlscan', `No URLScan result found for domain ${requestedHost}`);
                            return;
                        }
                    }
                    const uuid = searchResult?._id;
                    
                    // Fetch the full result using the UUID
                    // If 413 (payload too large), fallback to search result
                    let fullResult = null;
                    if (uuid) {
                        try {
                            const resultUrl = `https://urlscan.io/api/v1/result/${uuid}/`;
                            const resultProxyUrl = `https://corsproxy.io/?${encodeURIComponent(resultUrl)}`;
                            const resultResponse = await fetch(resultProxyUrl, {
                                headers: {
                                    'API-Key': keys.urlscan,
                                    'Accept': 'application/json'
                                }
                            });
                            if (resultResponse.ok) {
                                fullResult = await resultResponse.json();
                            } else if (resultResponse.status === 413) {
                                console.warn('URLScan full result too large (413), using search result fallback.');
                                fullResult = searchResult; // Use search result directly
                            }
                        } catch (e) {
                            console.error('Error fetching full URLScan result:', e);
                            fullResult = searchResult; // Fallback to search result
                        }
                    }
                    
                    const mergedResult = fullResult || searchResult;
                    currentResults.urlscan = mergedResult;
                    
                    // Safely render with null check
                    const urlscanContainer = document.getElementById('urlscanResults');
                    if (urlscanContainer) {
                        renderURLScan(mergedResult);
                    }
                    
                    // Update combined view safely
                    const combinedContainer = document.getElementById('combinedResults');
                    if (combinedContainer && currentResults.vt) {
                        renderCombined();
                    }
                } else {
                    // Try alternative query with page.url
                    const urlQuery = `page.url:${domain}`;
                    const altUrlscanUrl = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(urlQuery)}&size=1`;
                    const altProxyUrl = `https://corsproxy.io/?${encodeURIComponent(altUrlscanUrl)}`;
                    
                    const altResponse = await fetch(altProxyUrl, {
                        headers: {
                            'API-Key': keys.urlscan,
                            'Accept': 'application/json'
                        }
                    });
                    
                    if (altResponse.ok) {
                        const altData = await altResponse.json();
                        if (altData.results && altData.results.length > 0) {
                            const searchResult = altData.results[0];
                            const uuid = searchResult._id;
                            
                            // Fetch the full result using the UUID
                            let fullResult = null;
                            if (uuid) {
                                try {
                                    const resultUrl = `https://urlscan.io/api/v1/result/${uuid}/`;
                                    const resultProxyUrl = `https://corsproxy.io/?${encodeURIComponent(resultUrl)}`;
                                    const resultResponse = await fetch(resultProxyUrl, {
                                        headers: {
                                            'API-Key': keys.urlscan,
                                            'Accept': 'application/json'
                                        }
                                    });
                                    if (resultResponse.ok) {
                                        fullResult = await resultResponse.json();
                                    }
                                } catch (e) {
                                    console.error('Error fetching full URLScan result:', e);
                                    fullResult = searchResult;
                                }
                            }
                            
                            currentResults.urlscan = fullResult || searchResult;
                            renderURLScan(currentResults.urlscan);
                            
                            const combinedContainer = document.getElementById('combinedResults');
                            if (combinedContainer && currentResults.vt) {
                                renderCombined();
                            }
                        } else {
                            showError('urlscan', 'URLScan data not available.');
                        }
                    } else {
                        showError('urlscan', 'URLScan data not available.');
                    }
                }

            } catch (error) {
                console.error('URLScan Error:', error);
                showError('urlscan', error.message);
            }
        }

        function renderURLScan(data) {
            const container = document.getElementById('urlscanResults');
            
            if (!container) {
                console.warn('URLScan results container not found');
                return;
            }
            
            if (!data) {
                container.innerHTML = '<div class="error-message">URLScan data not available.</div>';
                const emptyEl = document.getElementById('urlscanEmpty');
                if (emptyEl) emptyEl.style.display = 'none';
                return;
            }

            const urlscanEmpty = document.getElementById('urlscanEmpty');
            if (urlscanEmpty) urlscanEmpty.style.display = 'none';

            // Extract key data sections
            const page = data.page || {};
            const task = data.task || {};
            const verdicts = data.verdicts || {};
            const lists = data.lists || {};
            const requests = data.requests || [];
            
            // Get UUID for screenshots
            const uuid = data._id || '';
            const screenshotUrl = uuid ? `https://urlscan.io/screenshots/${uuid}.png` : null;

            // Verdict Information
            const overallVerdict = verdicts.overall || {};
            const isMalicious = overallVerdict.malicious;
            const verdictScore = overallVerdict.score || 0;
            
            // Page Information
            const pageDomain = page.domain || 'N/A';
            const pageIp = page.ip || 'N/A';
            const pageCountry = page.country || 'N/A';
            const pageServer = page.server || 'N/A';
            const pageRedirected = page.redirected || false;
            const pageTitle = page.title || 'N/A';

            // Hosting Info
            const asns = lists.asns || [];
            const asnInfo = asns.length > 0 ? asns[0] : null;
            
            // Task Information
            const scanTime = task.time ? new Date(task.time).toUTCString() : 'N/A';

            // Infrastructure Lists
            const ips = lists.ips || [];
            const domains = lists.domains || [];
            const urls = lists.urls || [];

            // Build the HTML
            let html = '';

            // Header
            const verdictText = isMalicious ? 'Malicious' : (verdictScore > 0 ? 'Suspicious' : 'Clean');
            const verdictColor = isMalicious ? '#f85149' : (verdictScore > 0 ? '#d29922' : '#3fb950');

            html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">`;
            html += `<h3 style="margin: 0 0 16px 0; color: var(--accent-blue); font-size: 16px;"> URLScan Analysis</h3>`;
            
            // ========== SECTION 1: Threat Summary ==========
            html += `<div style="background: ${verdictColor}15; border-left: 4px solid ${verdictColor}; padding: 12px; border-radius: 4px; margin-bottom: 16px;">`;
            html += `<div style="display: flex; align-items: center; gap: 12px;">`;
            html += `<span style="font-size: 24px;">${isMalicious ? '' : ''}</span>`;
            html += `<div>`;
            html += `<div style="font-weight: bold; font-size: 18px; color: ${verdictColor};">Verdict: ${verdictText}</div>`;
            html += `<div style="font-size: 12px; color: var(--text-secondary);">Score: ${verdictScore} / 100</div>`;
            html += `</div></div>`;
            html += `</div>`;

            // Page Information
            html += `<div style="margin-bottom: 16px;">`;
            html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Page Information</h4>`;
            html += `<div style="display: grid; grid-template-columns: 140px 1fr; gap: 8px; font-size: 13px;">`;
            html += `<span style="color: var(--text-secondary);">Domain:</span><span style="color: var(--text-primary);">${pageDomain}</span>`;
            if (pageIp !== 'N/A') {
                html += `<span style="color: var(--text-secondary);">IP Address:</span><span style="color: var(--text-primary);">${pageIp}</span>`;
            }
            if (pageCountry !== 'N/A') {
                html += `<span style="color: var(--text-secondary);">Country:</span><span style="color: var(--text-primary);">${pageCountry}</span>`;
            }
            if (pageServer !== 'N/A') {
                html += `<span style="color: var(--text-secondary);">Server:</span><span style="color: var(--text-primary);">${pageServer}</span>`;
            }
            html += `<span style="color: var(--text-secondary);">Redirected:</span><span style="color: var(--text-primary);">${pageRedirected ? 'true' : 'false'}</span>`;
            if (pageTitle !== 'N/A') {
                html += `<span style="color: var(--text-secondary);">Title:</span><span style="color: var(--text-primary);">${pageTitle}</span>`;
            }
            html += `</div></div>`;

            // Hosting Info
            html += `<div style="margin-bottom: 16px;">`;
            html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Infrastructure</h4>`;
            html += `<div style="display: grid; grid-template-columns: 140px 1fr; gap: 8px; font-size: 13px;">`;
            if (asnInfo) {
                html += `<span style="color: var(--text-secondary);">ASN:</span><span style="color: var(--text-primary);">${asnInfo}</span>`;
            }
            if (page.server) {
                html += `<span style="color: var(--text-secondary);">Provider:</span><span style="color: var(--text-primary);">${pageServer}</span>`;
            }
            html += `</div></div>`;

            // Scan Time
            html += `<div style="margin-bottom: 16px;">`;
            html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Scan Time</h4>`;
            html += `<div style="font-size: 13px; color: var(--text-primary);">${scanTime}</div>`;
            html += `</div>`;

            html += `</div>`;

            // ========== SECTION 2: Screenshot Preview ==========
            if (screenshotUrl) {
                html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">`;
                html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Page Screenshot</h4>`;
                html += `<a href="${screenshotUrl}" target="_blank"><img src="${screenshotUrl}" alt="Page Screenshot" style="max-width: 100%; border-radius: 6px; border: 1px solid var(--border); cursor: pointer;" onerror="this.style.display='none'"></a>`;
                html += `</div>`;
            }

            // ========== SECTION 3: Redirect Chain Viewer ==========
            // Extract redirect chain from requests
            const redirectChain = [];
            let currentUrl = page.url || '';
            
            // Build redirect chain from requests
            if (requests && requests.length > 0) {
                const processedUrls = new Set();
                for (const req of requests) {
                    if (req.url && !processedUrls.has(req.url)) {
                        processedUrls.add(req.url);
                        redirectChain.push({
                            url: req.url,
                            status: req.response && req.response.status ? req.response.status : 'N/A',
                            ip: req.ip || 'N/A'
                        });
                    }
                }
            }
            
            if (redirectChain.length > 1 || pageRedirected) {
                html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">`;
                html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Redirect Chain</h4>`;
                
                // Show initial URL
                html += `<div style="font-size: 13px; margin-bottom: 8px;">`;
                html += `<span style="color: var(--text-secondary);">1 Initial:</span> <span style="color: var(--text-primary); word-break: break-all;">${pageDomain}</span>`;
                html += `</div>`;
                
                // Show redirect steps
                let step = 2;
                for (const chain of redirectChain.slice(0, 10)) {
                    if (chain.url !== page.url && chain.url !== pageDomain) {
                        html += `<div style="font-size: 13px; margin-bottom: 8px; padding-left: 12px; border-left: 2px solid var(--border);">`;
                        html += `<span style="color: var(--text-secondary);"></span> `;
                        html += `<span style="color: var(--text-primary); word-break: break-all;">${chain.url}</span>`;
                        if (chain.status !== 'N/A') {
                            html += ` <span style="color: ${chain.status >= 300 && chain.status < 400 ? 'var(--accent-yellow)' : 'var(--text-muted)'}; font-size: 11px;">[${chain.status}]</span>`;
                        }
                        if (chain.ip !== 'N/A') {
                            html += ` <span style="color: var(--text-muted); font-size: 11px;">IP: ${chain.ip}</span>`;
                        }
                        html += `</div>`;
                        step++;
                    }
                }
                html += `</div>`;
            }

            // ========== SECTION 4: Infrastructure and Network Indicators ==========
            html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">`;
            html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Related Infrastructure</h4>`;
            
            // Domains
            html += `<div style="margin-bottom: 12px;">`;
            html += `<div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">Domains (${domains.length})</div>`;
            if (domains.length > 0) {
                html += `<ul style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--text-primary);">`;
                domains.slice(0, 10).forEach(d => {
                    html += `<li style="margin-bottom: 4px; word-break: break-all;">${d}</li>`;
                });
                if (domains.length > 10) {
                    html += `<li style="color: var(--text-muted);">... and ${domains.length - 10} more</li>`;
                }
                html += `</ul>`;
            } else {
                html += `<span style="font-size: 13px; color: var(--text-muted);">None found</span>`;
            }
            html += `</div>`;
            
            // IPs
            html += `<div style="margin-bottom: 12px;">`;
            html += `<div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">IPs (${ips.length})</div>`;
            if (ips.length > 0) {
                html += `<ul style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--text-primary);">`;
                ips.slice(0, 10).forEach(ip => {
                    html += `<li style="margin-bottom: 4px;">${ip}</li>`;
                });
                if (ips.length > 10) {
                    html += `<li style="color: var(--text-muted);">... and ${ips.length - 10} more</li>`;
                }
                html += `</ul>`;
            } else {
                html += `<span style="font-size: 13px; color: var(--text-muted);">None found</span>`;
            }
            html += `</div>`;
            
            // ASNs
            html += `<div>`;
            html += `<div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">ASNs (${asns.length})</div>`;
            if (asns.length > 0) {
                html += `<ul style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--text-primary);">`;
                asns.forEach(asn => {
                    html += `<li style="margin-bottom: 4px;">${asn}</li>`;
                });
                html += `</ul>`;
            } else {
                html += `<span style="font-size: 13px; color: var(--text-muted);">None found</span>`;
            }
            html += `</div>`;
            html += `</div>`;

            // ========== SECTION 5: Malicious Script Detection ==========
            // Analyze scripts from requests
            const suspiciousScripts = [];
            if (requests && requests.length > 0) {
                const suspiciousPatterns = ['loader', 'stealer', 'payload', 'obfuscation', 'base64', 'eval', 'crypto', 'miner', 'malware', 'phish'];
                
                for (const req of requests) {
                    if (req.url && req.url.match(/\.js($|\?)/i)) {
                        const urlLower = req.url.toLowerCase();
                        const isExternal = pageDomain && !urlLower.includes(pageDomain.toLowerCase());
                        const isSuspicious = suspiciousPatterns.some(p => urlLower.includes(p));
                        
                        if (isExternal || isSuspicious) {
                            suspiciousScripts.push({
                                url: req.url,
                                reason: isExternal ? 'External JS' : 'Suspicious pattern'
                            });
                        }
                    }
                }
            }
            
            html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">`;
            html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> Suspicious Scripts</h4>`;
            if (suspiciousScripts.length > 0) {
                html += `<ul style="margin: 0; padding-left: 20px; font-size: 13px; color: var(--accent-red);">`;
                suspiciousScripts.slice(0, 10).forEach(script => {
                    html += `<li style="margin-bottom: 8px; word-break: break-all;">`;
                    html += `<div style="color: var(--text-primary);">${script.url}</div>`;
                    html += `<div style="color: var(--text-muted); font-size: 11px;">${script.reason}</div>`;
                    html += `</li>`;
                });
                if (suspiciousScripts.length > 10) {
                    html += `<li style="color: var(--text-muted);">... and ${suspiciousScripts.length - 10} more</li>`;
                }
                html += `</ul>`;
            } else {
                html += `<span style="font-size: 13px; color: var(--accent-green);">No suspicious scripts detected</span>`;
            }
            html += `</div>`;

            // ========== SECTION 6: IOC Export Tools ==========
            html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px;">`;
            html += `<h4 style="color: var(--text-primary); font-size: 14px; margin-bottom: 12px;"> IOC Export</h4>`;
            html += `<div style="display: flex; gap: 8px; flex-wrap: wrap;">`;
            html += `<button onclick="copyURLScanIOCs('domains')" style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; color: var(--text-primary); font-size: 12px; cursor: pointer;"> Copy Domains</button>`;
            html += `<button onclick="copyURLScanIOCs('ips')" style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; color: var(--text-primary); font-size: 12px; cursor: pointer;"> Copy IPs</button>`;
            html += `<button onclick="copyURLScanIOCs('urls')" style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; color: var(--text-primary); font-size: 12px; cursor: pointer;"> Copy URLs</button>`;
            html += `</div>`;
            html += `</div>`;

            // ========== SECTION 7: Raw JSON ==========
            html += `<div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 10px; padding: 16px;">`;
            html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">`;
            html += `<h4 style="margin: 0; color: var(--accent-blue); font-size: 14px;"> Raw JSON (Full URLScan API Response)</h4>`;
            html += `<button onclick="copyURLScanJSON()" style="background: var(--accent-blue); border: none; border-radius: 4px; padding: 6px 12px; color: white; font-size: 12px; cursor: pointer;"> Copy JSON</button>`;
            html += `</div>`;
            html += `<pre id="urlscan-raw-json" style="max-height: 500px; overflow: auto; background: #111; color: #ddd; padding: 12px; border-radius: 6px; font-size: 12px; font-family: 'JetBrains Mono', 'Fira Code', monospace; margin: 0; white-space: pre-wrap; word-break: break-all;">${JSON.stringify(data, null, 2)}</pre>`;
            html += `</div>`;

            // Store IOCs for export
            html += `<script>window.urlscanData = ${JSON.stringify({ domains: domains, ips: ips, urls: urls })};</` + `script>`;

            container.innerHTML = html;
        }
        
        // Copy URLScan JSON to clipboard
        function copyURLScanJSON() {
            const raw = document.getElementById('urlscan-raw-json').textContent;
            navigator.clipboard.writeText(raw).then(() => {
                showToast('URLScan JSON copied to clipboard!', 'success');
            }).catch(err => {
                console.error('Failed to copy:', err);
                showToast('Failed to copy JSON', 'error');
            });
        }
        
        // Copy URLScan IOCs to clipboard
        function copyURLScanIOCs(type) {
            const data = window.urlscanData || {};
            const items = data[type] || [];
            const text = items.join('\n');
            
            if (text) {
                navigator.clipboard.writeText(text).then(() => {
                    showToast(`${type.charAt(0).toUpperCase() + type.slice(1)} copied to clipboard!`, 'success');
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    showToast('Failed to copy IOCs', 'error');
                });
            } else {
                showToast(`No ${type} found`, 'info');
            }
        }

        function renderWhois(data) {
            const container = document.getElementById('whoisResults');
            if (!container) {
                console.warn('WHOIS results container not found');
                return;
            }
            
            if (!data || !data.domain_name) {
                container.innerHTML = '<div class="error-message">No WHOIS data available</div>';
                const emptyEl = document.getElementById('whoisEmpty');
                if (emptyEl) emptyEl.style.display = 'none';
                return;
            }

            const emptyEl = document.getElementById('whoisEmpty');
            if (emptyEl) emptyEl.style.display = 'none';

            // Parse dates
            const creationDate = data.creation_date ? new Date(data.creation_date).toLocaleDateString() : 'N/A';
            const expirationDate = data.expiration_date ? new Date(data.expiration_date).toLocaleDateString() : 'N/A';
            const updatedDate = data.updated_date ? new Date(data.updated_date).toLocaleDateString() : 'N/A';

            // Name servers - ensure it's always an array
            const nameServers = Array.isArray(data.name_servers) ? data.name_servers : (data.name_servers ? [data.name_servers] : []);

            // Status - ensure it's always an array
            const status = Array.isArray(data.status) ? data.status : (data.status ? [data.status] : []);

            let html = `<div class="result-section">
                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="var(--accent-blue)">
                                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
                            </svg>
                            Domain Information
                        </h3>
                        <span class="toggle-icon"></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <tr>
                                <th>Field</th>
                                <th>Value</th>
                            </tr>
                            <tr>
                                <td>Domain Name</td>
                                <td>${data.domain_name || 'N/A'}</td>
                            </tr>
                            <tr>
                                <td>Registrar</td>
                                <td>${data.registrar || 'N/A'}</td>
                            </tr>
                            <tr>
                                <td>Creation Date</td>
                                <td>${creationDate}</td>
                            </tr>
                            <tr>
                                <td>Expiration Date</td>
                                <td>${expirationDate}</td>
                            </tr>
                            <tr>
                                <td>Updated Date</td>
                                <td>${updatedDate}</td>
                            </tr>
                            <tr>
                                <td>DNSSEC</td>
                                <td>${data.dnssec || 'N/A'}</td>
                            </tr>
                            <tr>
                                <td>WHOIS Server</td>
                                <td>${data.whois_server || 'N/A'}</td>
                            </tr>
                        </table>
                    </div>
                </div>`;

            // Registrant Info
            if (data.name || data.org || data.address || data.city || data.state || data.country || data.registrant_postal_code) {
                html += `<div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="var(--accent-purple)">
                                <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
                            </svg>
                            Registrant Information
                        </h3>
                        <span class="toggle-icon"></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">`;
                if (data.name) html += `<tr><td>Name</td><td>${data.name}</td></tr>`;
                if (data.org) html += `<tr><td>Organization</td><td>${data.org}</td></tr>`;
                if (data.address) html += `<tr><td>Address</td><td>${data.address}</td></tr>`;
                if (data.city) html += `<tr><td>City</td><td>${data.city}</td></tr>`;
                if (data.state) html += `<tr><td>State</td><td>${data.state}</td></tr>`;
                if (data.country) html += `<tr><td>Country</td><td>${data.country}</td></tr>`;
                if (data.registrant_postal_code) html += `<tr><td>Postal Code</td><td>${data.registrant_postal_code}</td></tr>`;
                html += `</table></div></div>`;
            }

            // Name Servers
            if (nameServers.length > 0) {
                html += `<div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="var(--accent-green)">
                                <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/>
                            </svg>
                            Name Servers (${nameServers.length})
                        </h3>
                        <span class="toggle-icon"></span>
                    </div>
                    <div class="card-body">
                        <ul style="list-style:none; padding:0;">`;
                nameServers.forEach(ns => {
                    html += `<li style="padding:8px 12px; background:var(--bg-primary); margin:4px 0; border-radius:4px; font-family:monospace;">${ns}</li>`;
                });
                html += `</ul></div></div>`;
            }

            // Status
            if (status.length > 0) {
                html += `<div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="var(--accent-yellow)">
                                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                            </svg>
                            Domain Status (${status.length})
                        </h3>
                        <span class="toggle-icon"></span>
                    </div>
                    <div class="card-body">
                        <ul style="list-style:none; padding:0; font-size:12px;">`;
                status.forEach(s => {
                    html += `<li style="padding:8px 12px; background:var(--bg-primary); margin:4px 0; border-radius:4px; word-break:break-all;">${s}</li>`;
                });
                html += `</ul></div></div>`;
            }

            // Emails
            if (data.emails) {
                const emails = Array.isArray(data.emails) ? data.emails : [data.emails];
                html += `<div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="var(--accent-orange)">
                                <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/>
                            </svg>
                            Contact Emails
                        </h3>
                        <span class="toggle-icon"></span>
                    </div>
                    <div class="card-body">
                        <ul style="list-style:none; padding:0;">`;
                emails.forEach(email => {
                    html += `<li style="padding:8px 12px; background:var(--bg-primary); margin:4px 0; border-radius:4px; font-family:monospace;">${email}</li>`;
                });
                html += `</ul></div></div>`;
            }

            html += '</div>';
            container.innerHTML = html;
        }

        function renderAbuseIPDB(data) {
            const container = document.getElementById('abuseipdbResults');
            if (!container || !data) {
                if (container) {
                    container.innerHTML = '<div class="error-message">AbuseIPDB data not available.</div>';
                }
                const emptyEl = document.getElementById('abuseipdbEmpty');
                if (emptyEl) emptyEl.style.display = 'none';
                return;
            }
            
            // Parse abuse confidence score
            const confidence = data.abuseConfidenceScore || 0;
            let confidenceColor = 'var(--accent-green)';
            if (confidence > 50) confidenceColor = 'var(--accent-yellow)';
            if (confidence > 75) confidenceColor = 'var(--accent-red)';

            // Parse date formats
            const lastReportedAt = data.lastReportedAt ? new Date(data.lastReportedAt).toLocaleString() : 'N/A';

            // Hostnames
            const hostnames = data.hostnames || [];
            
            // Categories
            const categories = data.categories || [];
            
            // Reports
            const reports = data.reports || [];

            container.innerHTML = `
                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> IP Check Results</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th style="width: 200px;">Column</th>
                                    <th>Example Value</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr><td>ipAddress</td><td><strong>${data.ipAddress || 'N/A'}</strong></td><td>The IP address checked</td></tr>
                                <tr><td>isPublic</td><td>${data.isPublic !== undefined ? (data.isPublic ? 'True' : 'False') : 'N/A'}</td><td>Whether the IP is publicly routable</td></tr>
                                <tr><td>ipVersion</td><td>${data.ipVersion || 'N/A'}</td><td>IP version (IPv4 or IPv6)</td></tr>
                                <tr><td>isWhitelisted</td><td>${data.isWhitelisted ? 'True' : 'False'}</td><td>Indicates if the IP is marked as whitelisted</td></tr>
                                <tr><td>abuseConfidenceScore</td><td><span style="color: ${confidenceColor}; font-weight: bold;">${confidence}%</span></td><td>Score indicating the likelihood of abuse (0100)</td></tr>
                                <tr><td>countryCode</td><td>${data.countryCode || 'N/A'}</td><td>2-letter ISO country code</td></tr>
                                <tr><td>usageType</td><td>${data.usageType || 'N/A'}</td><td>Type of usage (e.g., Reserved, Fixed Line ISP, Government)</td></tr>
                                <tr><td>isp</td><td>${data.isp || 'N/A'}</td><td>Internet Service Provider name</td></tr>
                                <tr><td>domain</td><td>${data.domain || 'N/A'}</td><td>Associated domain, if any</td></tr>
                                <tr><td>hostnames</td><td>${hostnames.length > 0 ? hostnames.join(', ') : 'N/A'}</td><td>Resolved hostnames for the IP</td></tr>
                                <tr><td>isTor</td><td>${data.isTor ? 'True' : 'False'}</td><td>True if the IP is part of the Tor network</td></tr>
                                <tr><td>totalReports</td><td>${data.totalReports || 0}</td><td>Total number of abuse reports received</td></tr>
                                <tr><td>numDistinctUsers</td><td>${data.numDistinctUsers || 0}</td><td>Number of distinct users who reported this IP</td></tr>
                                <tr><td>lastReportedAt</td><td>${lastReportedAt}</td><td>Date/time of the most recent abuse report</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                ${categories.length > 0 ? `
                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Threat Categories</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <thead><tr><th>Category ID</th><th>Category Name</th></tr></thead>
                            <tbody>
                                ${categories.map(cat => `
                                    <tr>
                                        <td>${cat}</td>
                                        <td>${getCategoryName(cat)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                ` : ''}

                ${reports.length > 0 ? `
                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Reported Attacks (${reports.length})</h3>
                        <span></span>
                    </div>
                    <div class="card-body">
                        <table class="data-table">
                            <thead><tr><th>Date</th><th>Reporter ID</th><th>Categories</th><th>Comment</th></tr></thead>
                            <tbody>
                                ${reports.slice(0, 20).map(r => `
                                    <tr>
                                        <td>${r.reportedAt ? new Date(r.reportedAt).toLocaleString() : '-'}</td>
                                        <td>${r.reporterId || '-'}</td>
                                        <td>${r.categories ? r.categories.map(c => getCategoryName(c)).join(', ') : '-'}</td>
                                        <td>${r.comment ? (r.comment.length > 50 ? r.comment.substring(0, 50) + '...' : r.comment) : '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                        ${reports.length > 20 ? `<p style="color: var(--text-muted); margin-top: 8px;">... and ${reports.length - 20} more reports</p>` : ''}
                    </div>
                </div>
                ` : ''}

                <div class="result-card">
                    <div class="card-header" onclick="toggleCard(this)">
                        <h3> Raw JSON Data</h3>
                        <div style="display:flex;align-items:center;gap:8px;">
                            <button class="copy-btn-small" onclick="event.stopPropagation();copyRawJSON('abuse')">Copy JSON</button>
                            <span></span>
                        </div>
                    </div>
                    <div class="card-body">
                        <pre class="json-view" id="rawJsonAbuse">${JSON.stringify(data, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        function getCategoryName(categoryId) {
            const categories = {
                1: 'DNS Compromise',
                2: 'DNS Poisoning',
                3: 'Fraud Orders',
                4: 'DDoS Attack',
                5: 'FTP Brute-Force',
                6: 'Ping of Death',
                7: 'Phishing',
                8: 'Fraud VoIP',
                9: 'Open Proxy',
                10: 'Web Spam',
                11: 'Email Spam',
                12: 'Blog Spam',
                13: 'VPN IP',
                14: 'Port Scan',
                15: 'Hacking',
                16: 'SQL Injection',
                17: 'Spoofing',
                18: 'Brute-Force',
                19: 'Bad Web Bot',
                20: 'Exploited Host',
                21: 'Web App Attack',
                22: 'SSH',
                23: 'IoT Targeted'
            };
            return categories[categoryId] || `Category ${categoryId}`;
        }
        
        // Copy IOC to Clipboard
        function copyIOC() {
            if (!currentResults.ioc) {
                showToast('No IOC to copy', 'warning');
                return;
            }
            navigator.clipboard.writeText(currentResults.ioc).then(function() {
                showToast('IOC copied to clipboard!', 'success');
            }).catch(function() {
                showToast('Failed to copy IOC', 'error');
            });
        }

        // Copy Combined Results to Clipboard - SOC Report Format
        function copyCombinedResults() {
            if (!currentResults.ioc) {
                showToast('No results to copy', 'warning');
                return;
            }
            
            const ioc = currentResults.ioc;
            const type = currentResults.type || 'N/A';
            
            // Calculate threat intelligence
            let vtMalicious = 0;
            let vtTotal = 0;
            let vtResult = 'No security vendors flagged the indicator as malicious';
            if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                const stats = currentResults.vt.data.attributes.last_analysis_stats;
                vtTotal = Object.values(stats).reduce((a, b) => a + b, 0);
                vtMalicious = stats.malicious + stats.suspicious;
                if (vtMalicious > 0) {
                    vtResult = vtMalicious + ' security vendors flagged the indicator as malicious';
                }
            }
            
            let abuseResult = 'No abuse reports were identified';
            let abuseConfidence = 0;
            let isWhitelisted = false;
            if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
                abuseConfidence = currentResults.abuseipdb.abuseConfidenceScore || 0;
                const totalReports = currentResults.abuseipdb.totalReports || 0;
                isWhitelisted = currentResults.abuseipdb.isWhitelisted || false;
                if (isWhitelisted) {
                    abuseResult = 'No abuse reports were identified and the IP is listed as whitelisted';
                } else if (totalReports > 0) {
                    abuseResult = totalReports + ' abuse reports were identified';
                }
            }
            
            // Determine threat reputation
            let threatReputation = 'Inconclusive';
            if (vtMalicious > 10 || abuseConfidence > 75) threatReputation = 'Malicious';
            else if (vtMalicious > 0 || abuseConfidence > 50) threatReputation = 'Suspicious';
            else if (vtMalicious === 0 && abuseConfidence === 0) threatReputation = 'Clean';
            
            // Domain age analysis
            let domainAge = 'N/A';
            let ageClassification = 'N/A';
            let creationDate = null;
            if (currentResults.whois && currentResults.whois.creation_date) {
                creationDate = new Date(currentResults.whois.creation_date);
                const ageMs = new Date() - creationDate;
                const ageMonths = Math.floor(ageMs / (30.44 * 24 * 60 * 60 * 1000));
                const ageYears = (ageMonths / 12).toFixed(1);
                
                if (ageMonths < 6) {
                    ageClassification = 'Suspicious';
                    domainAge = ageMonths + ' months';
                } else if (ageMonths < 12) {
                    ageClassification = 'Medium Suspicion';
                    domainAge = ageMonths + ' months';
                } else if (ageMonths < 24) {
                    ageClassification = 'Low Risk';
                    domainAge = ageYears + ' years';
                } else {
                    ageClassification = 'Low Risk / Neutral';
                    domainAge = ageYears + ' years';
                }
            }
            
            // Infrastructure
            let ipAddress = 'N/A';
            let hostingProvider = 'N/A';
            let asn = 'N/A';
            let country = 'N/A';
            let infraObservations = 'No infrastructure data available';
            
            if (currentResults.abuseipdb && currentResults.abuseipdb.ipAddress) {
                ipAddress = currentResults.abuseipdb.ipAddress;
                hostingProvider = currentResults.abuseipdb.isp || currentResults.abuseipdb.hostname || 'N/A';
                asn = currentResults.abuseipdb.asn || 'N/A';
                country = currentResults.abuseipdb.countryName || 'N/A';
                
                // Determine infrastructure assessment
                const hostingLower = hostingProvider.toLowerCase();
                if (hostingLower.includes('amazon') || hostingLower.includes('aws') || 
                    hostingLower.includes('google') || hostingLower.includes('cloud') ||
                    hostingLower.includes('azure') || hostingLower.includes('microsoft')) {
                    infraObservations = ' Hosted on major cloud provider\n Cloud and internet service provider\n No suspicious infrastructure indicators observed';
                } else if (hostingLower.includes('ovh') || hostingLower.includes('digitalocean') || hostingLower.includes('linode')) {
                    infraObservations = ' Hosted on cloud/virtualization platform\n Could be legitimate or malicious use\n Further investigation recommended';
                } else {
                    infraObservations = ' Hosting provider identified\n Standard hosting profile\n No obvious suspicious indicators';
                }
            }
            
            // Determine infrastructure assessment
            let infraAssessment = 'Unable to assess';
            if (ipAddress !== 'N/A') {
                if (threatReputation === 'Clean') infraAssessment = 'Legitimate';
                else if (threatReputation === 'Malicious') infraAssessment = 'Potentially Suspicious - associated with malicious activity';
                else infraAssessment = 'Further investigation needed';
            }
            
            // Final verdict
            let finalRiskRating = 'Medium Risk';
            let conclusion = '';
            
            if (threatReputation === 'Malicious' || ageClassification === 'Suspicious') {
                finalRiskRating = 'High Risk';
                conclusion = 'Multiple indicators suggest malicious activity. Domain age is concerning and threat intelligence sources report malicious activity.';
            } else if (threatReputation === 'Suspicious' || ageClassification === 'Medium Suspicion') {
                finalRiskRating = 'Medium Risk';
                conclusion = 'Some indicators require attention. Further investigation recommended before making security decisions.';
            } else if (threatReputation === 'Clean' && ageClassification === 'Low Risk / Neutral') {
                finalRiskRating = 'Low Risk';
                conclusion = 'No malicious indicators were identified across WHOIS data, threat intelligence sources, or infrastructure analysis.';
            } else {
                finalRiskRating = 'Low Risk';
                conclusion = 'No malicious indicators were identified.';
            }
            
            // Build report
            let report = '';
            report += 'Indicator: ' + ioc + '\n';
            report += 'Investigation Type: Threat Intelligence / Infrastructure Analysis\n';
            report += '\n';
            report += '--------------------------------------------------\n';
            report += '\n';
            report += '1. Domain Age Analysis (WHOIS)\n';
            report += '\n';
            if (creationDate) {
                report += 'The domain ' + ioc + ' was registered on ' + creationDate.toLocaleDateString('en-GB') + '. At the time of investigation, the domain age is approximately ' + domainAge + '.\n';
            } else {
                report += 'WHOIS data not available for this indicator.\n';
            }
            report += '\n';
            report += 'Domain Age Risk Classification:\n';
            report += ' < 6 months  Suspicious\n';
            report += ' 612 months  Medium Suspicion\n';
            report += ' > 12 months  Low Risk / Neutral\n';
            report += '\n';
            report += 'Assessment:\n';
            report += 'Domain age classification: ' + ageClassification + '.\n';
            report += '\n';
            report += '--------------------------------------------------\n';
            report += '\n';
            report += '2. Threat Intelligence Correlation\n';
            report += '\n';
            report += 'VirusTotal:\n';
            report += vtResult + '.\n';
            report += '\n';
            report += 'AbuseIPDB:\n';
            report += abuseResult + '.\n';
            report += '\n';
            report += 'Assessment:\n';
            report += 'Threat intelligence reputation is assessed as ' + threatReputation + '.\n';
            report += '\n';
            report += '--------------------------------------------------\n';
            report += '\n';
            report += '3. Infrastructure Analysis (ASN / Hosting)\n';
            report += '\n';
            report += 'IP Address: ' + ipAddress + '\n';
            report += 'Hosting Provider / Organization: ' + hostingProvider + '\n';
            report += 'ASN: ' + asn + '\n';
            report += 'Country: ' + country + '\n';
            report += '\n';
            report += 'Infrastructure Observations:\n';
            report += infraObservations + '\n';
            report += '\n';
            report += 'Assessment:\n';
            report += 'Infrastructure appears ' + infraAssessment + '.\n';
            report += '\n';
            report += '--------------------------------------------------\n';
            report += '\n';
            report += '4. Final Verdict\n';
            report += '\n';
            report += 'Final Risk Rating: ' + finalRiskRating + '\n';
            report += '\n';
            report += 'Conclusion:\n';
            report += 'Based on the analysis of domain age, threat intelligence reputation, and infrastructure context, ' + ioc + ' is assessed as ' + finalRiskRating + '. ' + conclusion + '\n';
            report += '\n';
            report += '--------------------------------------------------\n';
            report += '\n';
            report += '5. Analyst Reference Links\n';
            report += '\n';
            if (currentResults.abuseipdb && currentResults.abuseipdb.ipAddress) {
                report += 'AbuseIPDB:\n';
                report += 'https://www.abuseipdb.com/check/' + currentResults.abuseipdb.ipAddress + '\n';
            }
            report += 'VirusTotal:\n';
            if (type === 'ip') {
                report += 'https://www.virustotal.com/gui/ip-address/' + ioc + '\n';
            } else if (type === 'domain') {
                report += 'https://www.virustotal.com/gui/domain/' + ioc + '\n';
            } else {
                report += 'https://www.virustotal.com/gui/search/' + ioc + '\n';
            }
            report += 'WHOIS Lookup:\n';
            report += 'https://www.whois.com/whois/' + ioc + '\n';
            
            navigator.clipboard.writeText(report).then(function() {
                showToast('Report copied to clipboard!', 'success');
            }).catch(function() {
                showToast('Failed to copy report', 'error');
            });
        }

        // Combined view wrapper (implemented in ui-panels.js)
        function renderCombined() {
            const combinedContainer = document.getElementById('combinedResults');
            if (!combinedContainer) {
                console.warn('Combined results container not found');
                return;
            }
            return renderCombinedPanel();
        }

        

        // Toggle card wrapper (implemented in ui-panels.js)
        function toggleCard(header) {
            return toggleCardPanel(header);
        }

        // Toggle SOC card wrapper (implemented in ui-panels.js)
        function toggleSocCard(cardId) {
            return toggleSocCardPanel(cardId);
        }

        // Export Functions - Clean CSV format
        function exportCSV() {
            let csv = '';
            
            // If it's an IP and we have AbuseIPDB data, use the clean format
            if (currentResults.type === 'ip' && currentResults.abuseipdb) {
                const a = currentResults.abuseipdb;
                csv += 'ipAddress,abuseConfidenceScore,totalReports,isp,domain,countryCode,hostnames,isPublic,isWhitelisted,usageType,ipVersion,numDistinctUsers,lastReportedAt,isTor\n';
                
                const hostnames = a.hostnames ? JSON.stringify(a.hostnames) : '[]';
                csv += `${a.ipAddress || ''},${a.abuseConfidenceScore || 0},${a.totalReports || 0},${a.isp || ''},${a.domain || ''},${a.countryCode || ''},${hostnames},${a.isPublic ? 'TRUE' : 'FALSE'},${a.isWhitelisted ? 'TRUE' : ''},${a.usageType || ''},${a.ipVersion || 4},${a.numDistinctUsers || 0},${a.lastReportedAt || ''},${a.isTor ? 'TRUE' : 'FALSE'}\n`;
            }
            
            // Add WHOIS data if available
            if (currentResults.whois && currentResults.whois.domain_name) {
                csv += '\nWHOIS Info\n';
                csv += `domain_name,registrar,creation_date,expiration_date,updated_date,dnssec,name_servers,emails\n`;
                const w = currentResults.whois;
                const nameServers = w.name_servers ? JSON.stringify(w.name_servers) : '[]';
                const emails = w.emails ? (Array.isArray(w.emails) ? JSON.stringify(w.emails) : w.emails) : '';
                csv += `${w.domain_name || ''},${w.registrar || ''},${w.creation_date || ''},${w.expiration_date || ''},${w.updated_date || ''},${w.dnssec || ''},${nameServers},${emails}\n`;
            }
            
            // Add VirusTotal data
            csv += '\nIP,VTReports\n,';
            if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                const stats = currentResults.vt.data.attributes.last_analysis_stats;
                const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
                csv += `${malicious}\n`;
            } else {
                csv += '\n';
            }
            
            downloadFile(csv, 'OSINT-Results.csv', 'text/csv');
            txt += '  and should NOT be used as the sole basis for security decisions.\n';
            txt += '  False positives are possible. Always verify with additional context\n';
            txt += '  and manual analysis. The expertise of a trained analyst is\n';
            txt += '  strongly recommended before taking any action.\n\n';

            // SUMMARY
            txt += 'SUMMARY\n';
            
            if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                const stats = currentResults.vt.data.attributes.last_analysis_stats;
                const total = Object.values(stats).reduce((a, b) => a + b, 0);
                const malicious = stats.malicious + stats.suspicious;
                const severity = malicious > 10 ? 'HIGH' : malicious > 0 ? 'MEDIUM' : 'LOW';
                txt += `  VirusTotal: ${malicious}/${total} detections (${severity} RISK)\n`;
            }
            
            if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
                txt += `  AbuseIPDB Confidence: ${currentResults.abuseipdb.abuseConfidenceScore}%\n`;
                txt += `  AbuseIPDB Total Reports: ${currentResults.abuseipdb.totalReports || 0}\n`;
            }
            
            // WHOIS Summary
            if (currentResults.whois && currentResults.whois.domain_name) {
                txt += `  WHOIS Domain: ${currentResults.whois.domain_name}\n`;
                txt += `  WHOIS Registrar: ${currentResults.whois.registrar || 'N/A'}\n`;
                txt += `  WHOIS Creation: ${currentResults.whois.creation_date || 'N/A'}\n`;
                txt += `  WHOIS Expiration: ${currentResults.whois.expiration_date || 'N/A'}\n`;
            }
            txt += '\n';

            // EVIDENCE & ANALYSIS
            txt += 'EVIDENCE & ANALYSIS\n';
            
            // Evidence
            txt += '--- Evidence ---\n';
            if (currentResults.abuseipdb && currentResults.abuseipdb.ipAddress) {
                txt += `  IP Address: ${currentResults.abuseipdb.ipAddress}`;
                if (currentResults.abuseipdb.abuseConfidenceScore > 0) {
                    txt += ` (${currentResults.abuseipdb.abuseConfidenceScore}% abuse confidence)`;
                }
                txt += '\n';
            }
            
            if (currentResults.abuseipdb && currentResults.abuseipdb.totalReports > 0) {
                txt += `  Total Reports: ${currentResults.abuseipdb.totalReports} abuse reports from ${currentResults.abuseipdb.numDistinctUsers} distinct users\n`;
            }
            
            if (currentResults.abuseipdb && currentResults.abuseipdb.categories && currentResults.abuseipdb.categories.length > 0) {
                const catNames = currentResults.abuseipdb.categories.map(c => getCategoryName(c)).join(', ');
                txt += `  Threat Categories: ${catNames}\n`;
            }
            
            // WHOIS Evidence
            if (currentResults.whois && currentResults.whois.domain_name) {
                txt += '\n--- WHOIS Information ---\n';
                txt += `  Domain: ${currentResults.whois.domain_name}\n`;
                txt += `  Registrar: ${currentResults.whois.registrar || 'N/A'}\n`;
                txt += `  Creation Date: ${currentResults.whois.creation_date || 'N/A'}\n`;
                txt += `  Expiration Date: ${currentResults.whois.expiration_date || 'N/A'}\n`;
                txt += `  Updated Date: ${currentResults.whois.updated_date || 'N/A'}\n`;
                txt += `  DNSSEC: ${currentResults.whois.dnssec || 'N/A'}\n`;
                if (currentResults.whois.name_servers && currentResults.whois.name_servers.length > 0) {
                    txt += `  Name Servers: ${currentResults.whois.name_servers.join(', ')}\n`;
                }
                if (currentResults.whois.emails) {
                    const emails = Array.isArray(currentResults.whois.emails) ? currentResults.whois.emails : [currentResults.whois.emails];
                    txt += `  Emails: ${emails.join(', ')}\n`;
                }
            }
            
            if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                const stats = currentResults.vt.data.attributes.last_analysis_stats;
                const malicious = stats.malicious + stats.suspicious;
                if (malicious > 0) {
                    txt += `  VirusTotal: ${malicious} engines flagged as malicious/suspicious out of ${Object.values(stats).reduce((a, b) => a + b, 0)} total\n`;
                }
                
                if (currentResults.vt.data.attributes.threat_labels && currentResults.vt.data.attributes.threat_labels.length > 0) {
                    txt += `  Threat Labels: ${currentResults.vt.data.attributes.threat_labels.join(', ')}\n`;
                }
            }
            
            // Analysis
            txt += '\n--- Analysis ---\n';
            let analysisText = '';
            if (verdict === 'HIGH RISK - MALICIOUS') {
                if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore > 75) {
                    analysisText += `The IP address ${currentResults.ioc} has been reported multiple times for malicious activity with a high abuse confidence score of ${currentResults.abuseipdb.abuseConfidenceScore}%. `;
                }
                if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                    const stats = currentResults.vt.data.attributes.last_analysis_stats;
                    const malicious = stats.malicious + stats.suspicious;
                    if (malicious > 10) {
                        analysisText += `VirusTotal shows ${malicious} security vendors flagged this indicator as malicious or suspicious. `;
                    }
                }
                analysisText += 'This indicator shows strong indicators of being involved in malicious activity. ';
            } else if (verdict === 'SUSPICIOUS') {
                if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore > 0) {
                    analysisText += `The IP address ${currentResults.ioc} has a moderate abuse confidence score of ${currentResults.abuseipdb.abuseConfidenceScore}%. `;
                }
                if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
                    const stats = currentResults.vt.data.attributes.last_analysis_stats;
                    const malicious = stats.malicious + stats.suspicious;
                    if (malicious > 0) {
                        analysisText += `Some security vendors (${malicious}) flagged this indicator. `;
                    }
                }
                analysisText += 'This indicator shows some suspicious characteristics but requires further investigation. ';
            } else if (verdict === 'LOW RISK - CLEAN') {
                analysisText += `The IP address ${currentResults.ioc} has not been reported for abuse and shows no malicious indicators in VirusTotal. `;
                if (currentResults.abuseipdb && currentResults.abuseipdb.isWhitelisted) {
                    analysisText += 'This IP is also on the AbuseIPDB whitelist. ';
                }
            } else {
                analysisText = 'Not enough data available to make a determination. Additional investigation recommended.';
            }
            txt += `  ${analysisText}\n`;
            txt += '\n';

            // RECOMMENDATION
            txt += 'RECOMMENDATION / NEXT STEPS\n';
            
            if (verdict === 'HIGH RISK - MALICIOUS') {
                txt += '  1. Block the IP address at firewall/IPS level\n';
                txt += '  2. Check internal logs for any connections to this IP\n';
                txt += '  3. Scan affected systems for indicators of compromise\n';
                txt += '  4. Report to relevant abuse email (ISP/hosting provider)\n';
                txt += '  5. Consider adding to blocklists\n';
            } else if (verdict === 'SUSPICIOUS') {
                txt += '  1. Monitor connections to this IP\n';
                txt += '  2. Review logs for any recent activity\n';
                txt += '  3. Consider blocking if activity persists\n';
                txt += '  4. Further investigate context of connection\n';
            } else if (verdict === 'LOW RISK - CLEAN') {
                txt += '  1. No immediate action required\n';
                txt += '  2. Continue monitoring as normal\n';
                txt += '  3. Whitelist if false positives occur\n';
            } else {
                txt += '  1. Gather more context about the indicator\n';
                txt += '  2. Check additional threat intelligence sources\n';
                txt += '  3. Review the circumstances of the indicator\n';
                txt += '  4. Consult with senior analyst if needed\n';
            }
            txt += '\n';

            // REFERENCES
            txt += 'REFERENCES\n';
            if (currentResults.abuseipdb && currentResults.abuseipdb.ipAddress) {
                txt += `   AbuseIPDB: https://www.abuseipdb.com/check/${currentResults.abuseipdb.ipAddress}\n`;
            }
            if (currentResults.whois && currentResults.whois.whois_server) {
                txt += `   WHOIS Server: ${currentResults.whois.whois_server}\n`;
            }
            if (currentResults.ioc) {
                txt += `   VirusTotal: https://www.virustotal.com/gui/ip-address/${currentResults.ioc}\n`;
            }

            txt += '\nEND OF REPORT\n';

            downloadFile(txt, `threatscan_${currentResults.ioc}_${Date.now()}.txt`, 'text/plain');
        }

        function downloadFile(content, filename, type) {
            const blob = new Blob([content], { type });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        // FAQs Modal
        function openFAQs() {
            const faqContent = `
                <div style="max-height: 70vh; overflow-y: auto; color: var(--text-primary);">
                    <h2 style="margin-bottom: 20px; color: var(--accent-blue);"> Frequently Asked Questions & Limitations</h2>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-yellow); margin-top: 16px;"> API Rate Limits</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>VirusTotal:</strong> Free tier: 4 requests/minute, 1,000,000 requests/month</li>
                            <li><strong>AbuseIPDB:</strong> Free tier: 2,000 requests/day</li>
                            <li><strong>WHOIS (APILayer):</strong> Subscription-based limits</li>
                            <li><strong>Impact:</strong> Bulk scanning may be slower due to rate limiting</li>
                        </ul>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-red); margin-top: 16px;"> Network & CORS Issues</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>CORS Proxy:</strong> This tool uses corsproxy.io to bypass browser CORS restrictions</li>
                            <li><strong>Possible Blockage:</strong> Corporate firewalls, VPNs, or ad blockers may block the proxy</li>
                            <li><strong>Error 400:</strong> Invalid domain format or proxy rate limiting</li>
                            <li><strong>Error 403:</strong> Access denied - proxy may be temporarily blocked</li>
                            <li><strong>Error 429:</strong> Too many requests - rate limit exceeded</li>
                            <li><strong>Solutions:</strong> Try again later, disable ad blocker, or use a different network</li>
                            <li><strong>Production Use:</strong> For continuous use, host this tool on your own server</li>
                        </ul>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> How to Use</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>Single IOC Mode:</strong> Enter one IOC for detailed analysis with all sources</li>
                            <li><strong>Bulk IOCs:</strong> Enter multiple IOCs (one per line, max 100) for batch scanning</li>
                            <li><strong>Auto-detect:</strong> Leave type as "Auto-detect" to automatically identify IOC type</li>
                            <li><strong>WHOIS:</strong> Works only with domains, not IP addresses</li>
                        </ul>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-green); margin-top: 16px;"> Use Cases</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>Threat Intelligence:</strong> Investigate IPs/domains found in logs or emails</li>
                            <li><strong>Incident Response:</strong> Quick lookup during security incidents</li>
                            <li><strong>Threat Hunting:</strong> Enrich IOCs with multiple intelligence sources</li>
                            <li><strong>Research:</strong> Analyze threat patterns and actor infrastructure</li>
                            <li><strong>Due Diligence:</strong> Check reputation of new domains/URLs</li>
                        </ul>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> Supported IOC Types</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>IP Addresses:</strong> IPv4 (e.g., 8.8.8.8) and IPv6</li>
                            <li><strong>Domains:</strong> Full domain names (e.g., google.com, example.org)</li>
                            <li><strong>URLs:</strong> Full URLs with http/https (e.g., https://example.com/malware)</li>
                            <li><strong>File Hashes:</strong> MD5, SHA1, SHA256</li>
                        </ul>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--text-muted); margin-top: 16px;"> Accuracy Disclaimer</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            Threat intelligence data is dynamically updated and may contain false positives or negatives. 
                            Always verify findings with additional context before making security decisions. 
                            This tool is intended to assist analysts, not replace human judgment.
                        </p>
                    </div>
                </div>
            `;
            
            // Update modal content
            document.querySelector('#settingsModal .modal-header h2').textContent = ' FAQs & Limitations';
            document.querySelector('#settingsModal .modal-body').innerHTML = faqContent;
            document.querySelector('#settingsModal .modal-footer').style.display = 'none';
            document.getElementById('settingsModal').classList.add('active');
        }
        
        // Close FAQs and restore settings modal
        function closeSettings() {
            document.getElementById('settingsModal').classList.remove('active');
            // Restore settings modal after FAQs
            setTimeout(() => {
                document.querySelector('#settingsModal .modal-header h2').textContent = 'API Settings';
                document.querySelector('#settingsModal .modal-body').innerHTML = `
                    <div class="input-group">
                        <label>VirusTotal API Key</label>
                        <input type="password" id="vtApiKey" placeholder="Enter your VirusTotal API key">
                        <small style="color: var(--text-muted);">Get your key from <a href="https://www.virustotal.com/gui/join-us" target="_blank" style="color: var(--accent-blue);">virustotal.com</a></small>
                    </div>
                    <div class="input-group">
                        <label>AbuseIPDB API Key</label>
                        <input type="password" id="abuseipdbApiKey" placeholder="Enter your AbuseIPDB API key">
                        <small style="color: var(--text-muted);">Get your key from <a href="https://www.abuseipdb.com/account/api" target="_blank" style="color: var(--accent-blue);">abuseipdb.com</a></small>
                    </div>
                    <div class="input-group">
                        <label>APILayer WHOIS API Key</label>
                        <input type="password" id="whoisApiKey" placeholder="Enter your APILayer WHOIS API key">
                        <small style="color: var(--text-muted);">Get your key from <a href="https://apilayer.com/marketplace/whois-api" target="_blank" style="color: var(--accent-blue);">apilayer.com</a></small>
                    </div>
                `;
                document.querySelector('#settingsModal .modal-footer').style.display = 'flex';
                loadKeys();
            }, 300);
        }

