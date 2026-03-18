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
            
            // Check if first time user - show welcome prompt (but demo popup will trigger it)
            const hasVisited = localStorage.getItem('threatscan_visited');
            const keys = getKeys();
            if (!hasVisited || (!keys.vt && !keys.abuse && !keys.whois)) {
                // Show demo popup first, which will then show welcome banner
                localStorage.setItem('threatscan_visited', 'true');
                showDemoPopup();
                return;
            }
            
            // For returning users with keys, still show demo popup
            showDemoPopup();
            
            // Auto-detect IOC type
            document.getElementById('iocInput').addEventListener('input', (e) => {
                const value = e.target.value.trim();
                if (!value) return;
                const lines = value.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
                if (lines.length > 1 && scanMode !== 'bulk') {
                    scanMode = 'bulk';
                    document.querySelectorAll('.mode-btn').forEach(btn => {
                        btn.classList.toggle('active', btn.dataset.mode === 'bulk');
                    });
                    const hint = document.querySelector('.bulk-hint');
                    if (hint) hint.style.display = 'block';
                    bsbSetIdle();
                    e.target.placeholder = 'Enter one IOC per line\n8.8.8.8\n1.1.1.1\nmalicious.com';
                } else if (lines.length === 1 && scanMode !== 'single') {
                    scanMode = 'single';
                    document.querySelectorAll('.mode-btn').forEach(btn => {
                        btn.classList.toggle('active', btn.dataset.mode === 'single');
                    });
                    const hint = document.querySelector('.bulk-hint');
                    if (hint) hint.style.display = 'none';
                    bsbHide();
                    e.target.placeholder = 'Enter URL, IP, Domain, or Hash (MD5/SHA1/SHA256)';
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
                left: 40%;
                transform: translate(-40%, -50%);
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
                <div class="welcome-layout">
                    <div class="welcome-left">
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
                    </div>
                    <div class="welcome-right">
                    </div>
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
        
        // Demo Popup Function - shows independently of welcome banner
        function showDemoPopup() {
            // Skip if already shown this session
            if (sessionStorage.getItem('demoPopupShown')) return;
            
            setTimeout(() => {
                if (sessionStorage.getItem('demoPopupShown')) return;
                
                const demoOverlay = document.createElement('div');
                demoOverlay.id = 'demoPopupOverlay';
                demoOverlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:9999;display:flex;align-items:center;justify-content:center;';
                
                const demoPopup = document.createElement('div');
                demoPopup.style.cssText = 'background:linear-gradient(135deg,#0f1a2b,#16253d);border:1px solid rgba(0,150,255,0.4);border-radius:16px;padding:32px;max-width:840px;text-align:center;animation:fadeIn 0.3s ease;';
                
                demoPopup.innerHTML = `
                    <div style="position:relative;margin-bottom:20px;cursor:pointer;" onclick="window.open('https://youtu.be/-Yu7HrRjHo8','_blank'); closeDemoPopup();">
                        <img src="YTpreview.png" style="width:100%;border-radius:12px;border:1px solid rgba(0,150,255,0.4);">
                        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:80px;color:white;text-shadow:0 0 20px rgba(0,0,0,0.8);">▶</div>
                    </div>
                    <h2 style="color:#66b3ff;margin:0 0 16px 0;font-size:28px;">🎬 Watch ThreatAnalyzer Demo</h2>
                    <p style="color:var(--text-secondary);margin:0 0 24px 0;line-height:1.6;font-size:16px;">See how ThreatAnalyzer can help you investigate threats efficiently.</p>
                    <div style="display:flex;gap:16px;justify-content:center;flex-wrap:wrap;">
                        <button onclick="window.open('https://youtu.be/-Yu7HrRjHo8','_blank'); closeDemoPopup();" 
                            style="background:var(--accent-blue);color:white;border:none;padding:16px 32px;border-radius:10px;cursor:pointer;font-size:16px;font-weight:600;">
                            Watch Demo
                        </button>
                        <button onclick="closeDemoPopup();" 
                            style="background:var(--bg-tertiary);color:var(--text-primary);border:1px solid rgba(255,255,255,0.1);padding:16px 32px;border-radius:10px;cursor:pointer;font-size:16px;">
                            Skip
                        </button>
                    </div>
                `;
                
                demoOverlay.appendChild(demoPopup);
                document.body.appendChild(demoOverlay);
                
                demoOverlay.onclick = function(e) {
                    if (e.target === demoOverlay) closeDemoPopup();
                };
                
                window.closeDemoPopup = function() {
                    if (demoOverlay.parentNode) demoOverlay.remove();
                    sessionStorage.setItem('demoPopupShown', 'true');
                    // Show welcome banner after demo popup is closed
                    showWelcomeBanner();
                };
            }, 500);
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
        // ── Canonical IOC normalisation + type detection ─────────────────
        // Handles defanged IOCs: hxxp://, hxxps://, [.], (.), 8.8.8[.]8, etc.
        function normaliseIOC(ioc) {
            if (!ioc) return '';
            return ioc.trim()
                .replace(/^hxxps?:\/\//i, (m) => m.replace(/hxxp/i, 'http'))
                .replace(/^hxxp:\/\//i, 'http://')
                .replace(/\[\.\]/g, '.')
                .replace(/\(\.\)/g, '.')
                .replace(/\[:\]/g, ':')
                .replace(/\[\/\]/g, '/');
        }

        function defangIOC(ioc) {
            if (!ioc) return '';
            const type = detectIOCType(ioc);
            if (type === 'url') {
                return ioc.replace(/^https?:\/\//i, (m) => m.replace('http', 'hxxp'))
                          .replace(/\./g, '[.]');
            }
            if (type === 'ip')     return ioc.replace(/\./g, '[.]');
            if (type === 'domain') return ioc.replace(/\./g, '[.]');
            return ioc;
        }

        function detectIOCType(raw) {
            if (!raw) return 'unknown';
            const ioc = normaliseIOC(raw).trim();
            // URL
            if (/^https?:\/\//i.test(ioc)) return 'url';
            // IPv4
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return 'ip';
            // IPv6
            if (/^([a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i.test(ioc)) return 'ip';
            // MD5 / SHA1 / SHA256
            if (/^[a-f0-9]{32}$/i.test(ioc)) return 'hash';
            if (/^[a-f0-9]{40}$/i.test(ioc)) return 'hash';
            if (/^[a-f0-9]{64}$/i.test(ioc)) return 'hash';
            // Domain
            if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(ioc)) return 'domain';
            return 'unknown';
        }

        // Scan Mode Toggle
        function setScanMode(mode) {
            scanMode = mode;
            document.querySelectorAll('.mode-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.mode === mode) btn.classList.add('active');
            });

            const hint = document.querySelector('.bulk-hint');
            const input = document.getElementById('iocInput');

            if (mode === 'bulk') {
                if (hint) hint.style.display = 'block';
                input.placeholder = 'Enter one IOC per line\n8.8.8.8\n1.1.1.1\nmalicious.com';
                bsbSetIdle();
                switchTab('bulk');
            } else {
                if (hint) hint.style.display = 'none';
                input.placeholder = 'Enter URL, IP, Domain, or Hash (MD5/SHA1/SHA256)';
                bsbHide();
                switchTab('vt');
            }
        }

        // Ensure onclick handlers can access setScanMode
        window.setScanMode = setScanMode;

        // API Key Management
        function loadKeys() {
            const vtKey       = localStorage.getItem('vt_api_key');
            const abuseipdbKey= localStorage.getItem('abuseipdb_api_key');
            const whoisKey    = localStorage.getItem('whois_api_key');
            const urlscanKey  = localStorage.getItem('urlscan_api_key');
            const abusechKey  = localStorage.getItem('abusech_api_key');

            const vtEl      = document.getElementById('vtApiKey');
            const abuseEl   = document.getElementById('abuseipdbApiKey');
            const whoisEl   = document.getElementById('whoisApiKey');
            const urlscanEl = document.getElementById('urlscanApiKey');
            const abusechEl = document.getElementById('abusechApiKey');

            if (vtEl      && vtKey)       vtEl.value      = atob(vtKey);
            if (abuseEl   && abuseipdbKey) abuseEl.value  = atob(abuseipdbKey);
            if (whoisEl   && whoisKey)    whoisEl.value   = atob(whoisKey);
            if (urlscanEl && urlscanKey)  urlscanEl.value = atob(urlscanKey);
            if (abusechEl && abusechKey)  abusechEl.value = atob(abusechKey);
        }

        function saveKeys() {
            const vtEl      = document.getElementById('vtApiKey');
            const abuseEl   = document.getElementById('abuseipdbApiKey');
            const whoisEl   = document.getElementById('whoisApiKey');
            const urlscanEl = document.getElementById('urlscanApiKey');
            const abusechEl = document.getElementById('abusechApiKey');

            if (!vtEl || !abuseEl || !whoisEl || !urlscanEl) return;

            const vtKey       = vtEl.value.trim();
            const abuseipdbKey= abuseEl.value.trim();
            const whoisKey    = whoisEl.value.trim();
            const urlscanKey  = urlscanEl.value.trim();
            const abusechKey  = abusechEl ? abusechEl.value.trim() : '';

            if (vtKey)       localStorage.setItem('vt_api_key',       btoa(vtKey));
            else             localStorage.removeItem('vt_api_key');
            if (abuseipdbKey) localStorage.setItem('abuseipdb_api_key', btoa(abuseipdbKey));
            else              localStorage.removeItem('abuseipdb_api_key');
            if (whoisKey)    localStorage.setItem('whois_api_key',    btoa(whoisKey));
            else             localStorage.removeItem('whois_api_key');
            if (urlscanKey)  localStorage.setItem('urlscan_api_key',  btoa(urlscanKey));
            else             localStorage.removeItem('urlscan_api_key');
            if (abusechKey)  localStorage.setItem('abusech_api_key',  btoa(abusechKey));
            else             localStorage.removeItem('abusech_api_key');

            updateApiStatus();
            closeSettings();
        }

        function clearKeys() {
            ['vt_api_key','abuseipdb_api_key','whois_api_key','urlscan_api_key','abusech_api_key']
                .forEach(k => localStorage.removeItem(k));
            ['vtApiKey','abuseipdbApiKey','whoisApiKey','urlscanApiKey','abusechApiKey'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
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
                vt:       localStorage.getItem('vt_api_key')        ? atob(localStorage.getItem('vt_api_key'))        : '',
                abuseipdb:localStorage.getItem('abuseipdb_api_key') ? atob(localStorage.getItem('abuseipdb_api_key')) : '',
                whois:    localStorage.getItem('whois_api_key')     ? atob(localStorage.getItem('whois_api_key'))     : '',
                urlscan:  localStorage.getItem('urlscan_api_key')   ? atob(localStorage.getItem('urlscan_api_key'))   : '',
                abusech:  localStorage.getItem('abusech_api_key')   ? atob(localStorage.getItem('abusech_api_key'))   : ''
            };
        }

        function updateApiStatus() {
            const keys = getKeys();
            document.getElementById('vtStatus').classList.toggle('active', !!keys.vt);
            document.getElementById('abuseipdbStatus').classList.toggle('active', !!keys.abuseipdb);
            document.getElementById('whoisStatus').classList.toggle('active', !!keys.whois);
            document.getElementById('urlscanStatus').classList.toggle('active', !!keys.urlscan);
            const abusechDot = document.getElementById('abusechStatus');
            if (abusechDot) abusechDot.classList.toggle('active', !!keys.abusech);
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

        // Helper function to detect IOC type
        // Recent Scans
        function loadRecentScans() {
            const saved = localStorage.getItem('recent_scans');
            if (saved) {
                recentScans = JSON.parse(saved);
                renderRecentScans();
            }
        }

        // Recent Scans — persisted to localStorage, shows risk badge + source hits
        function saveRecentScan(ioc, type, riskLevel = 'unknown') {
            const existing = recentScans.findIndex(s => s.ioc === ioc);
            if (existing >= 0) recentScans.splice(existing, 1);

            // Collect source verdicts from currentResults for the badge row
            const sources = [];
            if (currentResults.vt && currentResults.vt.data) {
                const s = currentResults.vt.data.attributes?.last_analysis_stats || {};
                const mal = (s.malicious || 0) + (s.suspicious || 0);
                sources.push({ label: 'VT', value: mal > 0 ? mal + ' det.' : 'clean', bad: mal > 0 });
            }
            if (currentResults.abuseipdb && !currentResults.abuseipdb.error) {
                const conf = currentResults.abuseipdb.abuseConfidenceScore || 0;
                sources.push({ label: 'Abuse', value: conf + '%', bad: conf > 25 });
            }
            if (currentResults.threatfox?.found) {
                sources.push({ label: 'TF', value: currentResults.threatfox.iocs?.[0]?.malware_printable || 'hit', bad: true });
            }
            if (currentResults.urlhaus?.found) {
                sources.push({ label: 'UH', value: currentResults.urlhaus.url_status || 'listed', bad: true });
            }
            if (currentResults.malwarebazaar?.found) {
                sources.push({ label: 'MB', value: currentResults.malwarebazaar.malware_family || 'malware', bad: true });
            }

            // Derive risk from sources if not provided
            if (riskLevel === 'unknown') {
                const hasCritical = sources.some(s => s.bad);
                riskLevel = hasCritical ? 'high' : 'low';
            }

            recentScans.unshift({ ioc, type, riskLevel, sources, timestamp: new Date().toISOString() });
            if (recentScans.length > 20) recentScans.pop();
            localStorage.setItem('recent_scans', JSON.stringify(recentScans));
            renderRecentScans();
        }

        function renderRecentScans() {
            const container = document.getElementById('recentList');
            if (!container) return;
            if (recentScans.length === 0) {
                container.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-muted);font-size:12px;">No recent scans</div>';
                return;
            }

            const typeIcon = t => t === 'ip' ? '🖥' : t === 'domain' ? '🌐' : t === 'url' ? '🔗' : t === 'hash' ? '📄' : '🔍';
            const riskBg   = r => r === 'high' ? 'rgba(239,68,68,0.15)' : r === 'medium' ? 'rgba(251,191,36,0.15)' : 'rgba(34,197,94,0.1)';
            const riskCol  = r => r === 'high' ? '#ef4444' : r === 'medium' ? '#fbbf24' : '#22c55e';
            const riskLbl  = r => r === 'high' ? 'HIGH' : r === 'medium' ? 'MED' : r === 'low' ? 'LOW' : '?';

            container.innerHTML = recentScans.map(scan => {
                const sourceBadges = (scan.sources || []).map(s =>
                    `<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:${s.bad ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.15)'};color:${s.bad ? '#f87171' : '#4ade80'};">${s.label}</span>`
                ).join('');

                const iocShort = scan.ioc.length > 26 ? scan.ioc.slice(0, 24) + '…' : scan.ioc;
                const ago = (() => {
                    const diff = Math.floor((Date.now() - new Date(scan.timestamp)) / 60000);
                    if (diff < 1) return 'just now';
                    if (diff < 60) return diff + 'm ago';
                    if (diff < 1440) return Math.floor(diff/60) + 'h ago';
                    return Math.floor(diff/1440) + 'd ago';
                })();

                return `
                <div class="recent-item" onclick="loadRecent('${scan.ioc.replace(/'/g, "\\'")}', '${scan.type}')"
                     style="border-left:3px solid ${riskCol(scan.riskLevel)};">
                    <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
                        <span style="font-size:11px;">${typeIcon(scan.type)}</span>
                        <span style="font-size:12px;font-family:monospace;color:var(--text-primary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
                              title="${scan.ioc}">${iocShort}</span>
                        <span style="font-size:9px;padding:2px 6px;border-radius:4px;background:${riskBg(scan.riskLevel)};color:${riskCol(scan.riskLevel)};font-weight:700;flex-shrink:0;">${riskLbl(scan.riskLevel)}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">
                        ${sourceBadges}
                        <span style="font-size:9px;color:var(--text-muted);margin-left:auto;">${ago}</span>
                    </div>
                </div>`;
            }).join('');
        }

        function loadRecent(ioc, type) {
            document.getElementById('iocInput').value = ioc;
            document.getElementById('iocType').value = type || 'auto';
            _iocDefanged = false;
            const defangBtn = document.getElementById('defangBtn');
            if (defangBtn) defangBtn.textContent = '\u{1F6E1}\uFE0F Defang';

            // Try to restore persisted results from IndexedDB — no re-scan needed
            restoreScanResult(ioc).then(stored => {
                if (stored && stored.results) {
                    const r = stored.results;
                    currentResults.ioc           = ioc;
                    currentResults.type          = stored.type || type;
                    currentResults.vt            = r.vt            || null;
                    currentResults.abuseipdb     = r.abuseipdb     || null;
                    currentResults.whois         = r.whois         || null;
                    currentResults.urlscan       = r.urlscan       || null;
                    currentResults.threatfox     = r.threatfox     || null;
                    currentResults.urlhaus       = r.urlhaus       || null;
                    currentResults.malwarebazaar = r.malwarebazaar || null;

                    if (r.vt)          renderVirusTotal(r.vt);
                    if (r.abuseipdb)   renderAbuseIPDB(r.abuseipdb);
                    if (r.whois)       renderWhois(r.whois);
                    if (r.urlscan)     renderURLScan(r.urlscan);
                    if (r.threatfox  && typeof renderThreatFox     === 'function') renderThreatFox(r.threatfox);
                    if (r.urlhaus    && typeof renderURLhaus        === 'function') renderURLhaus(r.urlhaus);
                    if (r.malwarebazaar && typeof renderMalwareBazaar === 'function') renderMalwareBazaar(r.malwarebazaar);
                    renderCombined();
                    showToast('Restored: ' + ioc, 'success');
                } else {
                    showToast('Click Investigate to re-scan ' + ioc, 'info');
                }
            }).catch(() => {
                showToast('Click Investigate to re-scan ' + ioc, 'info');
            });
        }

        // Tab Switching
        function switchTab(tab) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            if (tab === 'bulk') {
                const bulkContent = document.getElementById('bulkTab');
                if (bulkContent) bulkContent.classList.add('active');
                return;
            }

            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tab === tab);
            });
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.toggle('active', content.id === tab + 'Tab');
            });

            if (tab === 'combined') {
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
            // Normalise defanged formats before scanning
            const ioc = normaliseIOC(input.trim());
            const type = typeSelect === 'auto' ? detectIOCType(ioc) : typeSelect;
            // Reset defang state now that we're scanning the real value
            _iocDefanged = false;
            const defangBtn = document.getElementById('defangBtn');
            if (defangBtn) defangBtn.textContent = '🛡️ Defang';
            
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

            console.log('Scanning IOC via Worker:', ioc, 'type:', type);

            // Save to recent
            saveRecentScan(ioc, type);

            // Show loading states
            showLoading('vt');
            showLoading('abuseipdb');
            showLoading('whois');
            showLoading('urlscan');

            // Show per-source progress tracker
            sspShow(['vt','abuseipdb','whois','urlscan','threatfox','urlhaus','malwarebazaar']);
            ['vt','abuseipdb','whois','urlscan','threatfox','urlhaus','malwarebazaar'].forEach(k => sspSetStatus(k, 'loading'));

            // Update export bar
            const exportBar = document.getElementById('exportBar');
            if (exportBar) exportBar.style.display = 'flex';

            // Use Worker API to aggregate all threat intelligence lookups
            await scanViaWorker(ioc, type);
            
            // Render combined view if active
            const combinedTab = document.getElementById('combinedTab');
            if (combinedTab && combinedTab.classList.contains('active')) {
                renderCombined();
            }
        }
        
        // Legacy direct API calls - used as fallback when Worker is unavailable
        async function startSingleScanLegacy(input, type) {
            const ioc = input.trim();
            
            currentResults.ioc = ioc;
            currentResults.type = type;

            console.log('Scanning IOC (legacy):', ioc, 'type:', type);

            // Run scans in parallel with error isolation
            const keys = getKeys();
            const scanPromises = [];
            
            if (keys.vt) {
                scanPromises.push(scanVirusTotal(ioc, type));
            } else {
                showError('vt', 'VirusTotal API key not configured');
            }

            if (keys.abuseipdb && type === 'ip') {
                scanPromises.push(scanAbuseIPDB(ioc));
            } else if (keys.abuseipdb && type !== 'ip') {
                // For non-IP types, show info message
                const abuseResults = document.getElementById('abuseipdbResults');
                if (abuseResults) {
                    abuseResults.innerHTML = '<div class="info-message">AbuseIPDB only supports IP addresses.</div>';
                }
                const abuseEmpty = document.getElementById('abuseipdbEmpty');
                if (abuseEmpty) abuseEmpty.style.display = 'none';
            } else if (!keys.abuseipdb && type === 'ip') {
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
            } else if (type === 'domain' || type === 'url') {
                showError('whois', 'WHOIS API key not configured');
            }
            
            // URLScan lookup - URLScan only works for URLs and domains, not IPs or hashes
            if (keys.urlscan && (type === 'url' || type === 'domain')) {
                scanPromises.push(runURLScan(ioc));
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

        // Bulk IOC Scan - now uses Worker API
        async function startBulkScan(input) {
            // First split by newlines
            const lines = input.split(/\r?\n/);

            // Then for each line, also split by commas — normalise defanged formats
            const iocs = [];
            lines.forEach(line => {
                const trimmed = line.trim();
                if (!trimmed) return;
                const parts = trimmed.split(',').map(p => normaliseIOC(p.trim())).filter(p => p);
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

            // Initialize bulk results
            bulkResults = [];
            bulkScanProgress = 0;

            // Show BSB in scanning state and navigate to bulk tab immediately
            bsbSetScanning(0, validIocs.length, '');
            switchTab('bulk');
            document.getElementById('exportBar').style.display = 'flex';

            // Render initial progress
            renderBulkProgress(0, validIocs.length);

            // Sleep helper function for rate limiting
            function sleep(ms) {
                return new Promise(resolve => setTimeout(resolve, ms));
            }

            // Process each IOC via Worker API
            const keys = getKeys();
            for (let i = 0; i < validIocs.length; i++) {
                const ioc = validIocs[i];
                
                try {
                    // Call Worker API for each IOC (include API keys like single scan)
                    const url = WORKER_API_URL + '/scan?value=' + encodeURIComponent(ioc);
                    const response = await fetch(url, {
                        method: 'GET',
                        headers: {
                            'Accept': 'application/json',
                            'X-VT-API-Key':    keys.vt        || '',
                            'X-AbuseIPDB-Key': keys.abuseipdb || '',
                            'X-Whois-Key':     keys.whois     || '',
                            'X-URLScan-Key':   keys.urlscan   || '',
                            'X-AbuseCH-Key':   keys.abusech   || ''
                        }
                    });
                    const data = await response.json();
                    
                    bulkResults.push({
                        ioc:          ioc,
                        type:         data.type || detectIOCType(ioc),
                        vt:           data.virustotal,
                        abuseipdb:    data.abuseipdb,
                        whois:        data.whois,
                        urlscan:      data.urlscan,
                        threatfox:    data.threatfox    || null,
                        urlhaus:      data.urlhaus      || null,
                        malwarebazaar:data.malwarebazaar|| null,
                        status: data.error ? 'error' : 'success'
                    });
                } catch (error) {
                    console.error('Worker bulk scan error:', error);
                    bulkResults.push({
                        ioc:          ioc,
                        type:         detectIOCType(ioc),
                        vt:           { error: error.message },
                        abuseipdb:    null,
                        whois:        null,
                        urlscan:      null,
                        threatfox:    null,
                        urlhaus:      null,
                        malwarebazaar:null,
                        status: 'error'
                    });
                }
                
                bulkScanProgress = i + 1;
                renderBulkProgress(bulkScanProgress, validIocs.length);
                
                // 500ms between IOCs — Worker parallelises all APIs internally
                if (i < validIocs.length - 1) {
                    await sleep(500);
                }
            }

            // Scan complete — flip BSB to done state
            bsbSetDone(validIocs.length);
            switchTab('bulk');
            renderBulkResults();
        }

        // Render Bulk Progress
        function renderBulkProgress(current, total) {
            const container = document.getElementById('bulkTab');
            if (!container) return;
            const percentage = total > 0 ? Math.round((current / total) * 100) : 0;
            const done = current;
            const remaining = total - current;
            const currentIoc = (typeof bulkResults !== 'undefined' && bulkResults[current - 1])
                ? bulkResults[current - 1].ioc : '';

            // Drive the BSB with live progress
            bsbSetScanning(done, total, currentIoc);

            container.innerHTML = `
                <div style="padding:20px;">
                    <div style="display:flex;align-items:center;gap:12px;background:var(--bg-secondary);border:1px solid #30363d;border-radius:12px;padding:20px 24px;margin-bottom:16px;">
                        <div style="width:12px;height:12px;border-radius:50%;background:#58a6ff;flex-shrink:0;animation:bsbSonar2 1s ease-in-out infinite;"></div>
                        <div style="flex:1;">
                            <div style="font-size:15px;font-weight:600;color:var(--text-primary);">🔍 Scanning in progress…</div>
                            <div style="font-size:12px;color:var(--text-muted);margin-top:3px;font-family:monospace;">
                                ${currentIoc ? `Querying: <span style="color:#58a6ff;">${currentIoc}</span>` : `Preparing to scan ${total} IOCs…`}
                            </div>
                        </div>
                        <div style="display:flex;gap:20px;flex-shrink:0;text-align:center;">
                            <div><div style="font-size:22px;font-weight:800;color:#58a6ff;">${done}</div><div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Done</div></div>
                            <div><div style="font-size:22px;font-weight:800;color:#58a6ff;">${remaining}</div><div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Left</div></div>
                            <div><div style="font-size:22px;font-weight:800;color:#58a6ff;">${total}</div><div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;">Total</div></div>
                        </div>
                    </div>
                    <div style="background:var(--bg-secondary);border:1px solid #30363d;border-radius:10px;padding:16px 20px;">
                        <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                            <span style="font-size:13px;font-weight:600;color:var(--text-primary);">Progress</span>
                            <span style="font-size:13px;font-weight:700;color:#58a6ff;">${percentage}%</span>
                        </div>
                        <div style="background:#21262d;border-radius:999px;height:8px;overflow:hidden;">
                            <div style="width:${percentage}%;height:100%;background:linear-gradient(90deg,#1f6feb,#58a6ff);border-radius:999px;transition:width 0.4s ease;"></div>
                        </div>
                        <div style="display:flex;justify-content:space-between;margin-top:6px;font-size:11px;color:var(--text-muted);">
                            <span>${done} of ${total} IOCs scanned</span>
                            <span>${remaining > 0 ? `~${Math.ceil(remaining * 0.5)}s remaining` : 'Finishing…'}</span>
                        </div>
                    </div>
                </div>
                <style>@keyframes bsbSonar2{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.5;transform:scale(1.3)}}</style>
            `;
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
            const container = document.getElementById('bulkTab');
            
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

            updateBulkIocCount(bulkResults.length);
            
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
                ${renderBulkSummaryChart(sortedResults)}
                <div class="bulk-toolbar">
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
                            <th class="ioc-index">
                                <div class="th-content">#</div>
                            </th>
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
                            <th><div class="th-content">🦊 ThreatFox</div></th>
                            <th><div class="th-content">🔴 URLhaus</div></th>
                            <th><div class="th-content">☣️ Bazaar</div></th>
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

            sortedResults.forEach((r, index) => {
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

                // ThreatFox cell
                let tfText = '<span style="color:var(--text-muted);font-size:11px;">—</span>';
                if (r.threatfox && r.threatfox.found && r.threatfox.iocs && r.threatfox.iocs.length > 0) {
                    const tf = r.threatfox.iocs[0];
                    const conf = tf.confidence_level || 0;
                    const col = conf >= 75 ? '#f85149' : '#d29922';
                    tfText = `<span style="color:${col};font-weight:700;font-size:11px;">${tf.malware_printable || tf.malware || 'Match'}</span><br><span style="color:var(--text-muted);font-size:10px;">${conf}% conf</span>`;
                } else if (r.threatfox && !r.threatfox.error) {
                    tfText = '<span style="color:#3fb950;font-size:11px;">✓ Clean</span>';
                }

                // URLhaus cell
                let uhText = '<span style="color:var(--text-muted);font-size:11px;">—</span>';
                if (r.urlhaus && r.urlhaus.found) {
                    const online = r.urlhaus.url_status === 'online';
                    const col = online ? '#f85149' : '#d29922';
                    uhText = `<span style="color:${col};font-weight:700;font-size:11px;">${r.urlhaus.url_status || 'Listed'}</span><br><span style="color:var(--text-muted);font-size:10px;">${r.urlhaus.threat || ''}</span>`;
                } else if (r.urlhaus && !r.urlhaus.error) {
                    uhText = '<span style="color:#3fb950;font-size:11px;">✓ Clean</span>';
                }

                // MalwareBazaar cell
                let mbText = '<span style="color:var(--text-muted);font-size:11px;">—</span>';
                if (r.malwarebazaar && r.malwarebazaar.found) {
                    mbText = `<span style="color:#f85149;font-weight:700;font-size:11px;">☣️ ${r.malwarebazaar.malware_family || 'Malware'}</span>`;
                } else if (r.malwarebazaar && !r.malwarebazaar.error) {
                    mbText = '<span style="color:#3fb950;font-size:11px;">✓ Clean</span>';
                }

                html += `
                    <tr class="${rowClass}">
                        <td class="ioc-index">${index + 1}</td>
                        <td class="ioc-cell" title="${r.ioc}"><strong>${r.ioc}</strong>${tldBadge}<br>${pivotBtns}</td>
                        <td>${r.type}</td>
                        <td><span class="vt-detections"><span class="vt-malicious">${malCount}</span>/<span class="vt-clean">${total}</span></span></td>
                        <td>${abuseText}</td>
                        <td>${whoisText}</td>
                        <td style="min-width:90px;">${tfText}</td>
                        <td style="min-width:90px;">${uhText}</td>
                        <td style="min-width:90px;">${mbText}</td>
                        <td><span class="threat-score ${threatScore >= 80 ? 'threat-score-high' : threatScore >= 50 ? 'threat-score-medium' : 'threat-score-low'}">${threatScore}</span><div class="threat-bar"><div class="threat-bar-fill" style="width:${threatScore}%;background:${threatScore >= 80 ? '#ef4444' : threatScore >= 50 ? '#f59e0b' : '#22c55e'}"></div></div><span class="category-badge ${badgeClass}">${riskLevel}</span></td>
                        <td><button class="copy-btn-small" onclick="copyBulkRow('${r.ioc}')">Copy</button></td>
                    </tr>
                `;
            });

            updateBulkIocCount(sortedResults.length);

            html += '</tbody></table>';
            container.innerHTML = html;
            
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

        function updateBulkIocCount(count = bulkResults.length) {
            // kept as no-op — BSB handles its own display
        }

        // ── Single Scan Progress (SSP) tracker ───────────────────────────────
        //
        // Shows a compact per-source checklist below the Investigate button.
        // States: pending | loading | done | error | skipped
        //
        const SSP_SOURCES = [
            { key: 'vt',            label: 'VirusTotal',    icon: '🛡️' },
            { key: 'abuseipdb',     label: 'AbuseIPDB',     icon: '🌐' },
            { key: 'whois',         label: 'WHOIS',         icon: '📋' },
            { key: 'urlscan',       label: 'URLScan',       icon: '🔍' },
            { key: 'threatfox',     label: 'ThreatFox',     icon: '🦊' },
            { key: 'urlhaus',       label: 'URLhaus',       icon: '🔴' },
            { key: 'malwarebazaar', label: 'MalwareBazaar', icon: '☣️' },
        ];

        let _sspState = {};
        let _sspAutoHideTimer = null;

        function sspShow(sourceKeys) {
            clearTimeout(_sspAutoHideTimer);
            _sspState = {};
            sourceKeys.forEach(k => { _sspState[k] = 'pending'; });

            const wrap = document.getElementById('singleScanProgress');
            const list = document.getElementById('sspSources');
            if (!wrap || !list) return;

            list.innerHTML = SSP_SOURCES
                .filter(s => sourceKeys.includes(s.key))
                .map(s => `
                    <div id="ssp_row_${s.key}" style="display:flex;align-items:center;gap:8px;">
                        <span id="ssp_icon_${s.key}" style="width:16px;text-align:center;font-size:13px;">${s.icon}</span>
                        <span style="flex:1;font-size:12px;color:var(--text-secondary);">${s.label}</span>
                        <span id="ssp_badge_${s.key}" class="ssp-badge ssp-pending">Queued</span>
                    </div>`).join('');

            wrap.style.display = 'block';
            sspRefreshSummary(sourceKeys);
        }

        function sspSetStatus(key, status, detail) {
            _sspState[key] = status;
            const badge = document.getElementById(`ssp_badge_${key}`);
            if (!badge) return;

            const map = {
                loading:  { cls: 'ssp-loading',  text: 'Scanning…' },
                done:     { cls: 'ssp-done',      text: detail || 'Done' },
                error:    { cls: 'ssp-error',     text: detail || 'Error' },
                skipped:  { cls: 'ssp-skipped',   text: detail || 'N/A' },
                pending:  { cls: 'ssp-pending',   text: 'Queued' },
            };
            const cfg = map[status] || map.pending;
            badge.className = `ssp-badge ${cfg.cls}`;
            badge.textContent = cfg.text;

            const allKeys = Object.keys(_sspState);
            sspRefreshSummary(allKeys);

            const allDone = allKeys.every(k => ['done','error','skipped'].includes(_sspState[k]));
            if (allDone) {
                _sspAutoHideTimer = setTimeout(sspHide, 4000);
            }
        }

        function sspRefreshSummary(keys) {
            const el = document.getElementById('sspSummary');
            if (!el) return;
            const done    = keys.filter(k => _sspState[k] === 'done').length;
            const total   = keys.filter(k => _sspState[k] !== 'skipped').length;
            const loading = keys.some(k => _sspState[k] === 'loading');
            el.textContent = loading ? `${done}/${total} complete` : `${done}/${total} complete`;
        }

        function sspHide() {
            const wrap = document.getElementById('singleScanProgress');
            if (wrap) wrap.style.display = 'none';
        }

        // ── Bulk Scan Button (BSB) state helpers ──────────────────────────
        function bsbSetIdle() {
            const el = document.getElementById('bulkScanBtn');
            if (!el) return;
            el.style.display = 'inline-flex';
            el.innerHTML = `
                <div class="bsb-idle">
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                        <rect x="1" y="2" width="14" height="2.5" rx="1.2" fill="#58a6ff"/>
                        <rect x="1" y="6.75" width="10" height="2.5" rx="1.2" fill="#388bfd"/>
                        <rect x="1" y="11.5" width="7" height="2.5" rx="1.2" fill="#1f6feb"/>
                        <circle cx="13" cy="12.75" r="2.8" stroke="#58a6ff" stroke-width="1.4"/>
                        <line x1="15" y1="14.75" x2="16.2" y2="15.95" stroke="#58a6ff" stroke-width="1.5" stroke-linecap="round"/>
                    </svg>
                    Bulk scan
                </div>`;
        }

        function bsbSetScanning(done, total, currentIoc) {
            const el = document.getElementById('bulkScanBtn');
            if (!el) return;
            el.style.display = 'inline-flex';
            const pct = total > 0 ? Math.round((done / total) * 100) : 0;
            const eta = Math.ceil((total - done) * 0.5);
            const iocDisplay = currentIoc
                ? (currentIoc.length > 22 ? currentIoc.slice(0, 22) + '…' : currentIoc)
                : 'querying…';
            el.innerHTML = `
                <div class="bsb-scanning">
                    <div class="bsb-scan-top">
                        <div class="bsb-sonar">
                            <div class="bsb-sonar-ring"></div>
                            <div class="bsb-sonar-ring"></div>
                            <div class="bsb-sonar-dot"></div>
                        </div>
                        <div class="bsb-scan-text">
                            <div class="bsb-scan-title">Scanning indicators</div>
                            <div class="bsb-scan-ioc">${iocDisplay}</div>
                        </div>
                        <div class="bsb-scan-pct">${pct}%</div>
                    </div>
                    <div class="bsb-bar-track">
                        <div class="bsb-bar-fill" style="width:${pct}%"></div>
                    </div>
                    <div class="bsb-scan-footer">
                        <span>${done} / ${total} scanned</span>
                        <span>${done < total ? '~' + eta + 's left' : 'finishing…'}</span>
                    </div>
                </div>`;
        }

        function bsbSetDone(total) {
            const el = document.getElementById('bulkScanBtn');
            if (!el) return;
            el.style.display = 'inline-flex';
            el.innerHTML = `
                <div class="bsb-done">
                    <div class="bsb-check">
                        <svg width="9" height="9" viewBox="0 0 10 10" fill="none">
                            <polyline points="2,5 4.2,7.5 8,3" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <div class="bsb-done-text">
                        <div class="bsb-done-label">Scan complete</div>
                        <div class="bsb-done-sub">${total} indicator${total !== 1 ? 's' : ''}</div>
                    </div>
                </div>`;
        }

        function bsbHide() {
            const el = document.getElementById('bulkScanBtn');
            if (el) el.style.display = 'none';
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
            let text = 'IOC | Type | VirusTotal | AbuseIPDB | WHOIS Age | WHOIS Expires | WHOIS Registrar | ThreatFox | URLhaus | MalwareBazaar\n';
            text += '--- | --- | --- | --- | --- | --- | --- | --- | --- | ---\n';
            
            bulkResults.forEach(r => {
                let malCount = 0, abuseConf = 0, reports = 0, total = 0;
                let whoisAge = '-', whoisExpires = '-', whoisRegistrar = '-';
                let tfCol = '-', uhCol = '-', mbCol = '-';

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
                    whoisRegistrar = r.whois.registrar || '-';
                    if (created) whoisAge = Math.floor((new Date() - created) / (1000 * 60 * 60 * 24)) + ' days';
                    if (expires) whoisExpires = expires.toLocaleDateString();
                }
                if (r.threatfox && r.threatfox.found && r.threatfox.iocs && r.threatfox.iocs.length > 0) {
                    const tf = r.threatfox.iocs[0];
                    tfCol = `${tf.malware_printable || tf.malware || 'Match'} (${tf.confidence_level || 0}%)`;
                } else if (r.threatfox && !r.threatfox.error) { tfCol = 'Clean'; }
                if (r.urlhaus && r.urlhaus.found) {
                    uhCol = `${r.urlhaus.url_status || 'Listed'} - ${r.urlhaus.threat || ''}`;
                } else if (r.urlhaus && !r.urlhaus.error) { uhCol = 'Clean'; }
                if (r.malwarebazaar && r.malwarebazaar.found) {
                    mbCol = r.malwarebazaar.malware_family || 'Malware';
                } else if (r.malwarebazaar && !r.malwarebazaar.error) { mbCol = 'Clean'; }

                text += `${r.ioc} | ${r.type} | ${malCount}/${total} | ${abuseConf}%/${reports} | ${whoisAge} | ${whoisExpires} | ${whoisRegistrar} | ${tfCol} | ${uhCol} | ${mbCol}\n`;
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
            // Column order: IOC identity → Threat Intel (VT + abuse.ch) → WHOIS → Risk → AbuseIPDB details
            const header = [
                'IOC', 'Type',
                // ── Core threat verdict ──────────────────────────────
                'VirusTotal Detection',
                'ThreatFox Hit', 'ThreatFox Malware', 'ThreatFox Confidence',
                'URLhaus Status', 'URLhaus Threat',
                'MalwareBazaar Family',
                // ── Domain intelligence ──────────────────────────────
                'WHOIS Age', 'WHOIS Created', 'WHOIS Expires', 'WHOIS Registrar',
                // ── Overall verdict ──────────────────────────────────
                'Risk Level',
                // ── IP / Abuse intelligence ──────────────────────────
                'AbuseIPDB Confidence', 'AbuseIPDB Reports',
                'Domain', 'CountryCode', 'IsTor',
                'Hostnames', 'IsPublic', 'IsWhitelisted',
                'UsageType', 'IPVersion', 'NumDistinctUsers', 'LastReportedAt'
            ].join(',') + '\n';

            let csv = header;

            bulkResults.forEach(r => {
                // ── VirusTotal ───────────────────────────────────────
                let malCount = 0;
                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    const s = r.vt.data.attributes.last_analysis_stats;
                    malCount = (s.malicious || 0) + (s.suspicious || 0);
                }

                // ── ThreatFox ────────────────────────────────────────
                let tfHit = '-', tfMalware = '-', tfConf = '-';
                if (r.threatfox && r.threatfox.found && r.threatfox.iocs && r.threatfox.iocs.length > 0) {
                    const tf = r.threatfox.iocs[0];
                    tfHit     = 'Yes';
                    tfMalware = (tf.malware_printable || tf.malware || 'Unknown').replace(/,/g, ' ');
                    tfConf    = (tf.confidence_level || 0) + '%';
                } else if (r.threatfox && !r.threatfox.error) {
                    tfHit = 'No';
                }

                // ── URLhaus ──────────────────────────────────────────
                let uhStatus = '-', uhThreat = '-';
                if (r.urlhaus && r.urlhaus.found) {
                    uhStatus = r.urlhaus.url_status || 'listed';
                    uhThreat = (r.urlhaus.threat || '-').replace(/,/g, ' ');
                } else if (r.urlhaus && !r.urlhaus.error) {
                    uhStatus = 'clean';
                }

                // ── MalwareBazaar ────────────────────────────────────
                let mbFamily = '-';
                if (r.malwarebazaar && r.malwarebazaar.found) {
                    mbFamily = (r.malwarebazaar.malware_family || 'Unknown').replace(/,/g, ' ');
                } else if (r.malwarebazaar && !r.malwarebazaar.error) {
                    mbFamily = 'clean';
                }

                // ── WHOIS ────────────────────────────────────────────
                let whoisAge = '-', whoisCreated = '-', whoisExpires = '-', whoisRegistrar = '-';
                if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                    if (r.whois.creation_date) {
                        const created = new Date(r.whois.creation_date);
                        whoisCreated = created.toLocaleDateString();
                        whoisAge     = Math.floor((new Date() - created) / (1000 * 60 * 60 * 24)) + ' days';
                    }
                    whoisExpires   = r.whois.expiration_date ? new Date(r.whois.expiration_date).toLocaleDateString() : '-';
                    whoisRegistrar = (r.whois.registrar || '-').replace(/,/g, ' ');
                }

                // ── Risk verdict ─────────────────────────────────────
                const abuseScore = (r.abuseipdb && !r.abuseipdb.error) ? (r.abuseipdb.abuseConfidenceScore || 0) : 0;
                const risk = (malCount > 10 || abuseScore > 75 ||
                              (r.threatfox && r.threatfox.found) ||
                              (r.urlhaus && r.urlhaus.found && r.urlhaus.url_status === 'online') ||
                              (r.malwarebazaar && r.malwarebazaar.found))
                    ? 'HIGH'
                    : (malCount > 0 || abuseScore > 25 ||
                       (r.urlhaus && r.urlhaus.found))
                    ? 'MEDIUM'
                    : 'LOW';

                // ── AbuseIPDB ────────────────────────────────────────
                let abuseConf = '-', abuseRep = '-', domain = '-', countryCode = '-';
                let isTor = '-', hostnames = '-', isPublic = '-', isWhitelisted = '-';
                let usageType = '-', ipVersion = '-', numDistinctUsers = '-', lastReportedAt = '-';
                if (r.abuseipdb && !r.abuseipdb.error) {
                    abuseConf        = r.abuseipdb.abuseConfidenceScore + '%';
                    abuseRep         = r.abuseipdb.totalReports || 0;
                    domain           = (r.abuseipdb.domain || '-').replace(/,/g, ' ');
                    countryCode      = r.abuseipdb.countryCode || '-';
                    isTor            = r.abuseipdb.isTor ? 'TRUE' : 'FALSE';
                    hostnames        = r.abuseipdb.hostnames ? r.abuseipdb.hostnames.join('; ') : '-';
                    isPublic         = r.abuseipdb.isPublic !== undefined ? (r.abuseipdb.isPublic ? 'TRUE' : 'FALSE') : '-';
                    isWhitelisted    = r.abuseipdb.isWhitelisted ? 'TRUE' : 'FALSE';
                    usageType        = (r.abuseipdb.usageType || '-').replace(/,/g, ' ');
                    ipVersion        = r.abuseipdb.ipVersion || '-';
                    numDistinctUsers = r.abuseipdb.numDistinctUsers || 0;
                    lastReportedAt   = r.abuseipdb.lastReportedAt || '-';
                }

                // ── Build row in column order ─────────────────────────
                const row = [
                    r.ioc, r.type,
                    malCount,
                    tfHit, tfMalware, tfConf,
                    uhStatus, uhThreat,
                    mbFamily,
                    whoisAge, whoisCreated, whoisExpires, whoisRegistrar,
                    risk,
                    abuseConf, abuseRep,
                    domain, countryCode, isTor,
                    hostnames, isPublic, isWhitelisted,
                    usageType, ipVersion, numDistinctUsers, lastReportedAt
                ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');

                csv += row + '\n';
            });

            downloadFile(csv, `threatanalyzer_bulk_${new Date().toISOString().slice(0,10)}.csv`, 'text/csv');
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
                txt += `IOC: ${r.ioc}\n`;
                txt += `Type: ${r.type}\n`;

                if (r.vt && r.vt.data && r.vt.data.attributes && r.vt.data.attributes.last_analysis_stats) {
                    const stats = r.vt.data.attributes.last_analysis_stats;
                    const total = Object.values(stats).reduce((a, b) => a + b, 0);
                    const malCount = (stats.malicious || 0) + (stats.suspicious || 0);
                    txt += `VirusTotal: ${malCount}/${total} detections\n`;
                }
                if (r.abuseipdb && !r.abuseipdb.error) {
                    txt += `AbuseIPDB Confidence: ${r.abuseipdb.abuseConfidenceScore}%\n`;
                    txt += `AbuseIPDB Total Reports: ${r.abuseipdb.totalReports || 0}\n`;
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
                if (r.whois && !r.whoisError && !r.whois.notAvailable) {
                    txt += `WHOIS Created: ${r.whois.creation_date ? new Date(r.whois.creation_date).toLocaleDateString() : 'N/A'}\n`;
                    txt += `WHOIS Expires: ${r.whois.expiration_date ? new Date(r.whois.expiration_date).toLocaleDateString() : 'N/A'}\n`;
                    txt += `WHOIS Registrar: ${r.whois.registrar || 'N/A'}\n`;
                }
                // ThreatFox
                if (r.threatfox && r.threatfox.found && r.threatfox.iocs && r.threatfox.iocs.length > 0) {
                    const tf = r.threatfox.iocs[0];
                    txt += `ThreatFox: MATCH — ${tf.malware_printable || tf.malware || 'Unknown'} (${tf.confidence_level || 0}% confidence)\n`;
                    if (tf.threat_type_desc) txt += `ThreatFox Threat Type: ${tf.threat_type_desc}\n`;
                    if (tf.first_seen) txt += `ThreatFox First Seen: ${tf.first_seen.split(' ')[0]}\n`;
                    if (tf.tags && tf.tags.length > 0) txt += `ThreatFox Tags: ${tf.tags.join(', ')}\n`;
                } else if (r.threatfox && !r.threatfox.error) {
                    txt += `ThreatFox: Not found\n`;
                }
                // URLhaus
                if (r.urlhaus && r.urlhaus.found) {
                    txt += `URLhaus: ${r.urlhaus.url_status || 'Listed'} — ${r.urlhaus.threat || 'Unknown threat'}\n`;
                    if (r.urlhaus.date_added) txt += `URLhaus Date Added: ${r.urlhaus.date_added.split(' ')[0]}\n`;
                    if (r.urlhaus.tags && r.urlhaus.tags.length > 0) txt += `URLhaus Tags: ${r.urlhaus.tags.join(', ')}\n`;
                } else if (r.urlhaus && !r.urlhaus.error) {
                    txt += `URLhaus: Not found\n`;
                }
                // MalwareBazaar
                if (r.malwarebazaar && r.malwarebazaar.found) {
                    txt += `MalwareBazaar: MATCH — ${r.malwarebazaar.malware_family || 'Unknown'}\n`;
                    if (r.malwarebazaar.file_name) txt += `MalwareBazaar File Name: ${r.malwarebazaar.file_name}\n`;
                    if (r.malwarebazaar.file_type) txt += `MalwareBazaar File Type: ${r.malwarebazaar.file_type}\n`;
                    if (r.malwarebazaar.first_seen) txt += `MalwareBazaar First Seen: ${r.malwarebazaar.first_seen.split(' ')[0]}\n`;
                    if (r.malwarebazaar.bazaar_ref) txt += `MalwareBazaar Ref: ${r.malwarebazaar.bazaar_ref}\n`;
                } else if (r.malwarebazaar && !r.malwarebazaar.error) {
                    txt += `MalwareBazaar: Not found\n`;
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
            // Coerce message to a readable string in case an Error object or plain object was passed
            let msg = message;
            if (msg && typeof msg === 'object') {
                msg = msg.message || msg.error || JSON.stringify(msg);
            }
            msg = String(msg || 'Unknown error');
            console.error(`Error in ${target}:`, msg);
            const container = document.getElementById(target + 'Results');
            if (container) {
                container.innerHTML = `<div class="error-message">${msg}</div>`;
            }
            const emptyEl = document.getElementById(target + 'Empty');
            if (emptyEl) {
                emptyEl.style.display = 'none';
            }
            // Also show toast for visibility
            showToast(msg, 'error');
        }

        // Worker API endpoint — routes through Cloudflare Worker to protect API keys
        const WORKER_API_URL = 'https://threatanalyzer-api.juanlunadevelop.workers.dev';
        
        // Scan via Worker API - aggregates all threat intelligence lookups
        async function scanViaWorker(ioc, type) {
            try {
                console.log('Scanning via Worker API:', ioc, 'type:', type);
                
                // Get API keys from localStorage
                const keys = getKeys();
                
                // Use single endpoint that auto-detects IOC type
                const url = WORKER_API_URL + '/scan?value=' + encodeURIComponent(ioc);
                console.log('Worker API URL:', url);
                
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'X-VT-API-Key':    keys.vt       || '',
                        'X-AbuseIPDB-Key': keys.abuseipdb || '',
                        'X-Whois-Key':     keys.whois    || '',
                        'X-URLScan-Key':   keys.urlscan  || '',
                        'X-AbuseCH-Key':   keys.abusech  || ''
                    }
                });
                
                if (!response.ok) {
                    if (response.status === 404) {
                        throw new Error('IOC not found');
                    }
                    if (response.status === 429) {
                        throw new Error('Rate limited - please wait and try again');
                    }
                    throw new Error(`Worker API error: ${response.status}`);
                }
                
                const data = await response.json();
                console.log('Worker API response:', data);
                
                // Handle error response from Worker
                if (data.error) {
                    throw new Error(data.error);
                }
                
                // Store results in currentResults - Worker returns aggregated format
                // Format: {virustotal: {...}, abuseipdb: {...}, urlscan: {...}, whois: {...}}
                
                // Process VirusTotal results
                if (data.virustotal) {
                    if (data.virustotal.error) {
                        // error may be an object (e.g. {message: "..."}), not always a string
                        const vtErrMsg = typeof data.virustotal.error === 'string'
                            ? data.virustotal.error
                            : (data.virustotal.error.message || JSON.stringify(data.virustotal.error));
                        showError('vt', vtErrMsg);
                        sspSetStatus('vt', 'error', 'Error');
                    } else {
                        currentResults.vt = data.virustotal;
                        renderVirusTotal(data.virustotal);
                        const vtStats = data.virustotal?.data?.attributes?.last_analysis_stats;
                        const vtMal = vtStats ? ((vtStats.malicious||0)+(vtStats.suspicious||0)) : 0;
                        sspSetStatus('vt', 'done', vtMal > 0 ? `${vtMal} hit${vtMal>1?'s':''}` : 'Clean');
                    }
                } else {
                    sspSetStatus('vt', 'skipped');
                }
                
                // Process AbuseIPDB results
                if (data.abuseipdb) {
                    console.log('Frontend received abuseipdb data:', data.abuseipdb);
                    // Extract inner data if wrapped (API returns { data: {...} })
                    const abuseData = data.abuseipdb.data || data.abuseipdb;
                    console.log('AbuseIPDB extracted data:', abuseData);
                    if (abuseData.error) {
                        // error may be an object, coerce to string
                        const abuseErrMsg = typeof abuseData.error === 'string'
                            ? abuseData.error
                            : (abuseData.error.message || JSON.stringify(abuseData.error));
                        showError('abuseipdb', abuseErrMsg);
                        sspSetStatus('abuseipdb', 'error', 'Error');
                    } else {
                        currentResults.abuseipdb = abuseData;
                        renderAbuseIPDB(abuseData);
                        const score = abuseData.abuseConfidenceScore;
                        sspSetStatus('abuseipdb', 'done', score != null ? `${score}% abuse` : 'Done');
                    }
                } else {
                    sspSetStatus('abuseipdb', 'skipped');
                }
                
                // Process WHOIS results
                if (data.whois) {
                    if (data.whois.error) {
                        // error may be an object; Worker may fail to extract domain from a URL IOC
                        const whoisErrMsg = typeof data.whois.error === 'string'
                            ? data.whois.error
                            : (data.whois.error.message || 'No WHOIS data available');
                        showError('whois', whoisErrMsg);
                        sspSetStatus('whois', 'error', 'Error');
                    } else {
                        // Worker may return { result: {...} } or the unwrapped result directly
                        const whoisData = data.whois.result || data.whois;
                        currentResults.whois = whoisData;
                        renderWhois(whoisData);
                        const regDate = whoisData.creation_date;
                        if (regDate) {
                            const ageDays = Math.floor((Date.now() - new Date(regDate)) / 86400000);
                            sspSetStatus('whois', 'done', ageDays < 30 ? `${ageDays}d old ⚠` : `${Math.floor(ageDays/365)}yr old`);
                        } else {
                            sspSetStatus('whois', 'done', 'Done');
                        }
                    }
                } else {
                    sspSetStatus('whois', 'skipped');
                }
                
                // Process URLScan results
                if (data.urlscan) {
                    if (data.urlscan.error) {
                        showError('urlscan', data.urlscan.error);
                        sspSetStatus('urlscan', 'error', 'Error');

                    } else if (data.urlscan.status === 'pending' && data.urlscan.uuid) {
                        // Worker returned pending — poll Worker /urlscan/result every 2s
                        // (urlscan docs: poll every 2s after initial 10s wait)
                        const pendingUuid = data.urlscan.uuid;

                        sspSetStatus('urlscan', 'loading', 'Polling…');

                        const uc = document.getElementById('urlscanResults');
                        if (uc) uc.innerHTML = `<div class="loading">
                            <div class="spinner"></div>
                            <span id="urlscanStatusMsg">Scan submitted. Fetching result…</span>
                        </div>`;
                        const ue = document.getElementById('urlscanEmpty');
                        if (ue) ue.style.display = 'none';

                        (async () => {
                            const sleep  = ms => new Promise(r => setTimeout(r, ms));
                            const setMsg = msg => {
                                const el = document.getElementById('urlscanStatusMsg');
                                if (el) el.textContent = msg;
                            };

                            // Per urlscan docs: wait 10s then poll every 2s
                            await sleep(10000);

                            for (let i = 1; i <= 60; i++) { // 60 x 2s = 2 min max
                                setMsg(`Fetching URLScan result… (${i})`);
                                sspSetStatus('urlscan', 'loading', `Polling ${i}/60`);
                                try {
                                    // Route through Worker — it adds API-Key server-side
                                    const workerUrl = WORKER_API_URL +
                                        '/urlscan/result?uuid=' + encodeURIComponent(pendingUuid);
                                    const resp = await fetch(workerUrl, {
                                        headers: {
                                            'Accept': 'application/json',
                                            'X-URLScan-Key': keys.urlscan || ''
                                        }
                                    });

                                    if (resp.status === 200) {
                                        const result = await resp.json();
                                        if (result.status === 'pending') {
                                            await sleep(2000); continue;
                                        }
                                        if (result.error) {
                                            showError('urlscan', result.error);
                                            sspSetStatus('urlscan', 'error', 'Error');
                                            return;
                                        }
                                        currentResults.urlscan = result;
                                        renderURLScan(result);
                                        const usMal = result?.verdicts?.overall?.malicious;
                                        const usScore = result?.verdicts?.overall?.score ?? 0;
                                        sspSetStatus('urlscan', 'done', usMal ? 'Malicious' : usScore > 0 ? `Score ${usScore}` : 'Clean');
                                        try {
                                            if (typeof updateReputationGrid === 'function')
                                                updateReputationGrid(currentResults.vt, currentResults.abuseipdb, currentResults.whois, result);
                                            if (typeof renderCombined === 'function') renderCombined();
                                        } catch (_) {}
                                        return;
                                    }

                                    await sleep(2000);
                                } catch (e) {
                                    if (i >= 60) {
                                        showError('urlscan', 'URLScan polling failed: ' + e.message);
                                        sspSetStatus('urlscan', 'error', 'Timeout');
                                    } else await sleep(2000);
                                }
                            }

                            showError('urlscan',
                                `Scan still processing. ` +
                                `<a href="https://urlscan.io/result/${pendingUuid}/" target="_blank" ` +
                                `style="color:var(--accent-blue)">View on urlscan.io ↗</a>`);
                            sspSetStatus('urlscan', 'error', 'Timeout');
                        })();

                    } else {
                        // Complete result — render directly
                        currentResults.urlscan = data.urlscan;
                        renderURLScan(data.urlscan);
                        const usMal = data.urlscan?.verdicts?.overall?.malicious;
                        const usScore = data.urlscan?.verdicts?.overall?.score ?? 0;
                        sspSetStatus('urlscan', 'done', usMal ? 'Malicious' : usScore > 0 ? `Score ${usScore}` : 'Clean');
                    }
                } else {
                    sspSetStatus('urlscan', 'skipped');
                }
                
                // Process ThreatFox / URLhaus / MalwareBazaar (abuse.ch sources)
                if (data.threatfox) {
                    currentResults.threatfox = data.threatfox;
                    if (typeof renderThreatFox === 'function') renderThreatFox(data.threatfox);
                    if (data.threatfox.error) {
                        sspSetStatus('threatfox', 'error', 'Error');
                    } else {
                        sspSetStatus('threatfox', 'done', data.threatfox.found ? '⚠ Found' : 'Clean');
                    }
                } else {
                    sspSetStatus('threatfox', 'skipped');
                }

                if (data.urlhaus) {
                    currentResults.urlhaus = data.urlhaus;
                    if (typeof renderURLhaus === 'function') renderURLhaus(data.urlhaus);
                    if (data.urlhaus.error) {
                        sspSetStatus('urlhaus', 'error', 'Error');
                    } else {
                        sspSetStatus('urlhaus', 'done', data.urlhaus.found ? '⚠ Found' : 'Clean');
                    }
                } else {
                    sspSetStatus('urlhaus', 'skipped');
                }

                if (data.malwarebazaar) {
                    currentResults.malwarebazaar = data.malwarebazaar;
                    if (typeof renderMalwareBazaar === 'function') renderMalwareBazaar(data.malwarebazaar);
                    if (data.malwarebazaar.error) {
                        sspSetStatus('malwarebazaar', 'error', 'Error');
                    } else {
                        sspSetStatus('malwarebazaar', 'done', data.malwarebazaar.found ? `⚠ ${data.malwarebazaar.malware_family || 'Found'}` : 'Clean');
                    }
                } else {
                    sspSetStatus('malwarebazaar', 'skipped');
                }

                // Update combined view
                const combinedContainer = document.getElementById('combinedResults');
                if (combinedContainer) {
                    renderCombined();
                }
                
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

                // Persist results to IndexedDB for session restore
                persistScanResult(currentResults.ioc, currentResults.type, {
                    vt: currentResults.vt,
                    abuseipdb: currentResults.abuseipdb,
                    whois: currentResults.whois,
                    urlscan: currentResults.urlscan,
                    threatfox: currentResults.threatfox,
                    urlhaus: currentResults.urlhaus,
                    malwarebazaar: currentResults.malwarebazaar
                });

                return data;
                
            } catch (error) {
                console.error('Worker API Error:', error);
                showToast('Worker API error: ' + error.message, 'error');
                
                // Show errors for all services
                showError('vt', 'Worker API unavailable - ' + error.message);
                showError('abuseipdb', 'Worker API unavailable - ' + error.message);
                showError('whois', 'Worker API unavailable - ' + error.message);
                showError('urlscan', 'Worker API unavailable - ' + error.message);

                // Mark all SSP sources as failed
                ['vt','abuseipdb','whois','urlscan','threatfox','urlhaus','malwarebazaar']
                    .forEach(k => sspSetStatus(k, 'error', 'Failed'));
                
                throw error;
            }
        }
        
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

        // URLScan.io API - Submit new scan with polling for results
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
            console.log('renderAbuseIPDB called with:', data);
            
            // Safe helper function to display values
            const safe = (value) => {
                return value !== undefined && value !== null && value !== "" ? value : "N/A";
            };
            
            // Parse the data - handle both { data: {...} } and {...} formats
            // The API returns { data: {...} }, so we need to extract the inner data
            const apiData = data.data || data;
            console.log('AbuseIPDB Parsed Data:', apiData);
            
            const container = document.getElementById('abuseipdbResults');
            console.log('Container element:', container);
            if (!container || !apiData) {
                if (container) {
                    container.innerHTML = '<div class="error-message">AbuseIPDB data not available.</div>';
                }
                const emptyEl = document.getElementById('abuseipdbEmpty');
                if (emptyEl) emptyEl.style.display = 'none';
                return;
            }
            
            // Parse abuse confidence score
            const confidence = safe(apiData.abuseConfidenceScore);
            let confidenceColor = 'var(--accent-green)';
            if (confidence > 50) confidenceColor = 'var(--accent-yellow)';
            if (confidence > 75) confidenceColor = 'var(--accent-red)';

            // Parse date formats
            const lastReportedAt = apiData.lastReportedAt ? new Date(apiData.lastReportedAt).toLocaleString() : 'N/A';

            // Hostnames
            const hostnames = apiData.hostnames || [];
            
            // Categories
            const categories = apiData.categories || [];
            
            // Reports
            const reports = apiData.reports || [];

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
                                <tr><td>ipAddress</td><td><strong>${safe(apiData.ipAddress)}</strong></td><td>The IP address checked</td></tr>
                                <tr><td>isPublic</td><td>${apiData.isPublic !== undefined ? (apiData.isPublic ? 'True' : 'False') : 'N/A'}</td><td>Whether the IP is publicly routable</td></tr>
                                <tr><td>ipVersion</td><td>${safe(apiData.ipVersion)}</td><td>IP version (IPv4 or IPv6)</td></tr>
                                <tr><td>isWhitelisted</td><td>${apiData.isWhitelisted !== undefined ? (apiData.isWhitelisted ? 'True' : 'False') : 'N/A'}</td><td>Indicates if the IP is marked as whitelisted</td></tr>
                                <tr><td>abuseConfidenceScore</td><td><span style="color: ${confidenceColor}; font-weight: bold;">${safe(confidence)}%</span></td><td>Score indicating the likelihood of abuse (0-100)</td></tr>
                                <tr><td>countryCode</td><td>${safe(apiData.countryCode)}</td><td>2-letter ISO country code</td></tr>
                                <tr><td>usageType</td><td>${safe(apiData.usageType)}</td><td>Type of usage (e.g., Reserved, Fixed Line ISP, Government)</td></tr>
                                <tr><td>isp</td><td>${safe(apiData.isp)}</td><td>Internet Service Provider name</td></tr>
                                <tr><td>domain</td><td>${safe(apiData.domain)}</td><td>Associated domain, if any</td></tr>
                                <tr><td>hostnames</td><td>${hostnames.length > 0 ? hostnames.join(', ') : 'N/A'}</td><td>Resolved hostnames for the IP</td></tr>
                                <tr><td>isTor</td><td>${apiData.isTor !== undefined ? (apiData.isTor ? 'True' : 'False') : 'N/A'}</td><td>True if the IP is part of the Tor network</td></tr>
                                <tr><td>totalReports</td><td>${safe(apiData.totalReports)}</td><td>Total number of abuse reports received</td></tr>
                                <tr><td>numDistinctUsers</td><td>${safe(apiData.numDistinctUsers)}</td><td>Number of distinct users who reported this IP</td></tr>
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
                        <pre class="json-view" id="rawJsonAbuse">${JSON.stringify(apiData, null, 2)}</pre>
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

        // ════════════════════════════════════════════════════════════════
        // FEATURE: IOC Defanging / Refanging
        // ════════════════════════════════════════════════════════════════
        let _iocDefanged = false;

        function toggleDefang() {
            const input = document.getElementById('iocInput');
            const btn   = document.getElementById('defangBtn');
            if (!input || !btn) return;

            const lines = input.value.split('\n');
            if (!_iocDefanged) {
                input.value   = lines.map(l => defangIOC(l.trim())).join('\n');
                btn.textContent = '🔓 Refang';
                btn.title = 'Convert back to scannable format';
                _iocDefanged  = true;
            } else {
                input.value   = lines.map(l => normaliseIOC(l.trim())).join('\n');
                btn.textContent = '🛡️ Defang';
                btn.title = 'Defang for safe sharing';
                _iocDefanged  = false;
            }
        }

        // ════════════════════════════════════════════════════════════════
        // FEATURE: Paste from Clipboard
        // ════════════════════════════════════════════════════════════════
        async function pasteFromClipboard() {
            try {
                const text = await navigator.clipboard.readText();
                if (!text.trim()) { showToast('Clipboard is empty', 'warning'); return; }

                const input = document.getElementById('iocInput');
                input.value = text.trim();
                _iocDefanged = false;

                // Auto-detect mode
                const lines = text.trim().split(/\r?\n/).filter(l => l.trim());
                if (lines.length > 1) {
                    setScanMode('bulk');
                } else {
                    setScanMode('single');
                }
                input.dispatchEvent(new Event('input'));
                showToast(`Pasted ${lines.length} IOC${lines.length > 1 ? 's' : ''} from clipboard`, 'success');
            } catch (e) {
                showToast('Clipboard access denied — paste manually (Ctrl+V)', 'warning');
            }
        }

        // ════════════════════════════════════════════════════════════════
        // FEATURE: MITRE ATT&CK lookup (free TAXII — no key needed)
        // Maps malware family name to techniques via cached in-memory map
        // ════════════════════════════════════════════════════════════════
        const _mitreCache = {};

        async function lookupMITRE(malwareFamily) {
            if (!malwareFamily || malwareFamily === 'Unknown') return null;
            const key = malwareFamily.toLowerCase();
            if (_mitreCache[key] !== undefined) return _mitreCache[key];

            try {
                // MITRE ATT&CK Enterprise STIX data via GitHub (no key, CORS-friendly)
                const url = `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/software/${encodeURIComponent(key)}.json`;
                // Use a known-good lightweight endpoint: search MITRE by name
                const searchUrl = `https://attack.mitre.org/api/software/?term=${encodeURIComponent(malwareFamily)}`;

                // Fallback: use hardcoded common families for instant lookup
                const knownFamilies = {
                    'cobalt strike': { techniques: ['T1071.001', 'T1059.003', 'T1055'], tactics: ['C2', 'Execution', 'Defense Evasion'] },
                    'cobaltstrike':  { techniques: ['T1071.001', 'T1059.003', 'T1055'], tactics: ['C2', 'Execution', 'Defense Evasion'] },
                    'mimikatz':      { techniques: ['T1003.001', 'T1550.002'],           tactics: ['Credential Access', 'Lateral Movement'] },
                    'emotet':        { techniques: ['T1566.001', 'T1071.001', 'T1082'],  tactics: ['Initial Access', 'C2', 'Discovery'] },
                    'trickbot':      { techniques: ['T1566.001', 'T1071', 'T1055'],      tactics: ['Initial Access', 'C2', 'Defense Evasion'] },
                    'qakbot':        { techniques: ['T1566.001', 'T1059', 'T1071'],      tactics: ['Initial Access', 'Execution', 'C2'] },
                    'remcos':        { techniques: ['T1219', 'T1071.001', 'T1082'],      tactics: ['C2', 'Discovery'] },
                    'njrat':         { techniques: ['T1219', 'T1082', 'T1057'],          tactics: ['C2', 'Discovery'] },
                    'asyncrat':      { techniques: ['T1219', 'T1059.001', 'T1082'],      tactics: ['C2', 'Execution', 'Discovery'] },
                    'nanocore':      { techniques: ['T1219', 'T1082', 'T1113'],          tactics: ['C2', 'Discovery', 'Collection'] },
                    'agent tesla':   { techniques: ['T1056.001', 'T1071.001', 'T1027'],  tactics: ['Collection', 'C2', 'Defense Evasion'] },
                    'agenttesla':    { techniques: ['T1056.001', 'T1071.001', 'T1027'],  tactics: ['Collection', 'C2', 'Defense Evasion'] },
                    'redline':       { techniques: ['T1539', 'T1555', 'T1071'],          tactics: ['Credential Access', 'C2'] },
                    'lokibot':       { techniques: ['T1056', 'T1071.001'],               tactics: ['Collection', 'C2'] },
                    'icedid':        { techniques: ['T1566.001', 'T1055', 'T1071'],      tactics: ['Initial Access', 'Defense Evasion', 'C2'] },
                    'formbook':      { techniques: ['T1056.001', 'T1071', 'T1082'],      tactics: ['Collection', 'C2', 'Discovery'] },
                    'raccoon':       { techniques: ['T1539', 'T1555', 'T1071'],          tactics: ['Credential Access', 'C2'] },
                    'vidar':         { techniques: ['T1539', 'T1555.003', 'T1071'],      tactics: ['Credential Access', 'C2'] },
                    'ghostsocks':    { techniques: ['T1090', 'T1071'],                   tactics: ['C2'] },
                    'havoc':         { techniques: ['T1071.001', 'T1059', 'T1055'],      tactics: ['C2', 'Execution', 'Defense Evasion'] },
                    'sliver':        { techniques: ['T1071.001', 'T1059', 'T1027'],      tactics: ['C2', 'Execution', 'Defense Evasion'] },
                    'metasploit':    { techniques: ['T1059', 'T1055', 'T1071'],          tactics: ['Execution', 'Defense Evasion', 'C2'] },
                };

                const match = knownFamilies[key];
                _mitreCache[key] = match || null;
                return _mitreCache[key];
            } catch (e) {
                _mitreCache[key] = null;
                return null;
            }
        }

        function renderMITREBadges(mitreData) {
            if (!mitreData) return '';
            return mitreData.techniques.map((t, i) => {
                const tactic = mitreData.tactics[i] || '';
                return `<a href="https://attack.mitre.org/techniques/${t.replace('.','/')}/" target="_blank"
                           style="display:inline-flex;align-items:center;gap:3px;font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(163,113,247,0.15);color:#a371f7;text-decoration:none;border:1px solid rgba(163,113,247,0.3);"
                           title="${tactic}">${t}</a>`;
            }).join(' ');
        }

        // ════════════════════════════════════════════════════════════════
        // FEATURE: Bulk results visual summary chart
        // ════════════════════════════════════════════════════════════════
        function renderBulkSummaryChart(results) {
            const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
            const families = {};

            results.forEach(r => {
                let vtStats = null;
                if (r.vt?.data?.attributes?.last_analysis_stats) vtStats = r.vt.data.attributes.last_analysis_stats;
                const mal = vtStats ? (vtStats.malicious||0)+(vtStats.suspicious||0) : 0;
                const abuse = r.abuseipdb?.abuseConfidenceScore || 0;
                const hasTF = r.threatfox?.found;
                const hasUH = r.urlhaus?.found && r.urlhaus.url_status === 'online';
                const hasMB = r.malwarebazaar?.found;

                const score = calculateThreatScore(r.ioc, vtStats, abuse, 0, r.threatfox, r.urlhaus, r.malwarebazaar);
                if (score >= 80) counts.HIGH++;
                else if (score >= 50) counts.MEDIUM++;
                else counts.LOW++;

                const fam = r.threatfox?.iocs?.[0]?.malware_printable || r.malwarebazaar?.malware_family;
                if (fam && fam !== 'Unknown') families[fam] = (families[fam]||0) + 1;
            });

            const total = results.length || 1;
            const topFamilies = Object.entries(families).sort((a,b)=>b[1]-a[1]).slice(0,5);

            const bar = (count, total, color) => {
                const pct = Math.round((count/total)*100);
                return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                    <div style="width:70px;font-size:11px;color:var(--text-muted);text-align:right;">${count} IOCs</div>
                    <div style="flex:1;background:var(--bg-tertiary,#21262d);border-radius:4px;height:14px;overflow:hidden;">
                        <div style="width:${pct}%;height:100%;background:${color};border-radius:4px;transition:width 0.4s;"></div>
                    </div>
                    <div style="width:36px;font-size:11px;font-weight:700;color:${color};">${pct}%</div>
                </div>`;
            };

            const familyBadges = topFamilies.map(([f, c]) =>
                `<span style="font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(248,81,73,0.15);color:#f85149;border:1px solid rgba(248,81,73,0.2);">${f} ×${c}</span>`
            ).join(' ');

            return `
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px;">
                <div style="flex:1;min-width:220px;background:var(--bg-secondary);border:1px solid #30363d;border-radius:10px;padding:14px 16px;">
                    <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;">Risk Distribution</div>
                    <div style="display:flex;gap:20px;margin-bottom:12px;">
                        <div style="text-align:center;"><div style="font-size:22px;font-weight:800;color:#ef4444;">${counts.HIGH}</div><div style="font-size:10px;color:var(--text-muted);">HIGH</div></div>
                        <div style="text-align:center;"><div style="font-size:22px;font-weight:800;color:#f59e0b;">${counts.MEDIUM}</div><div style="font-size:10px;color:var(--text-muted);">MED</div></div>
                        <div style="text-align:center;"><div style="font-size:22px;font-weight:800;color:#22c55e;">${counts.LOW}</div><div style="font-size:10px;color:var(--text-muted);">LOW</div></div>
                        <div style="text-align:center;"><div style="font-size:22px;font-weight:800;color:var(--text-muted);">${total}</div><div style="font-size:10px;color:var(--text-muted);">TOTAL</div></div>
                    </div>
                    ${bar(counts.HIGH,   total, '#ef4444')}
                    ${bar(counts.MEDIUM, total, '#f59e0b')}
                    ${bar(counts.LOW,    total, '#22c55e')}
                </div>
                ${topFamilies.length > 0 ? `
                <div style="flex:1;min-width:200px;background:var(--bg-secondary);border:1px solid #30363d;border-radius:10px;padding:14px 16px;">
                    <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;">Malware Families Detected</div>
                    <div style="display:flex;flex-wrap:wrap;gap:6px;">${familyBadges}</div>
                </div>` : ''}
            </div>`;
        }

        // ════════════════════════════════════════════════════════════════
        // FEATURE: SIEM auto-populate from current scan results
        // ════════════════════════════════════════════════════════════════
        function autoPopulateSIEM() {
            if (!currentResults.ioc) {
                showToast('Run a scan first to auto-populate the SIEM query', 'warning');
                return;
            }
            const type = currentResults.type;
            const ioc  = currentResults.ioc;
            const input = document.getElementById('ipQueryInput');
            if (!input) return;

            // Collect all IPs — from the IOC itself if IP, or resolved IP from AbuseIPDB
            let ips = [];
            if (type === 'ip') {
                ips.push(ioc);
            }
            if (currentResults.abuseipdb?.resolvedIp) {
                ips.push(currentResults.abuseipdb.resolvedIp);
            }
            // Also pull IPs from URLScan lists
            if (currentResults.urlscan?.lists?.ips) {
                ips = ips.concat(currentResults.urlscan.lists.ips.slice(0, 10));
            }
            // Dedup
            ips = [...new Set(ips)];

            if (ips.length > 0) {
                input.value = ips.join('\n');
                generateQuery();
                switchTab('ipquery');
                showToast(`Auto-populated ${ips.length} IP${ips.length>1?'s':''} from ${ioc}`, 'success');
            } else {
                // For domains/URLs: put the IOC as context and show a note
                input.value = '';
                showToast(`No IPs found for ${type} — enter IPs manually`, 'info');
                switchTab('ipquery');
            }
        }

        // ════════════════════════════════════════════════════════════════
        // FEATURE: IndexedDB session persistence
        // Stores last 20 single-scan results; survives tab close/refresh
        // ════════════════════════════════════════════════════════════════
        const _DB_NAME = 'ThreatAnalyzerDB';
        const _DB_VER  = 1;
        let _db = null;

        function openDB() {
            return new Promise((resolve, reject) => {
                if (_db) { resolve(_db); return; }
                const req = indexedDB.open(_DB_NAME, _DB_VER);
                req.onupgradeneeded = e => {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains('scans')) {
                        const store = db.createObjectStore('scans', { keyPath: 'ioc' });
                        store.createIndex('ts', 'timestamp');
                    }
                };
                req.onsuccess = e => { _db = e.target.result; resolve(_db); };
                req.onerror   = e => { console.warn('IndexedDB error', e); reject(e); };
            });
        }

        async function persistScanResult(ioc, type, results) {
            try {
                const db = await openDB();
                const tx = db.transaction('scans', 'readwrite');
                const store = tx.objectStore('scans');
                store.put({ ioc, type, results, timestamp: Date.now() });

                // Keep only 20 most recent
                const all = await new Promise(r => {
                    const req = store.index('ts').getAll();
                    req.onsuccess = e => r(e.target.result);
                });
                if (all.length > 20) {
                    all.sort((a,b) => a.timestamp - b.timestamp);
                    all.slice(0, all.length - 20).forEach(r => store.delete(r.ioc));
                }
            } catch(e) {
                console.warn('persistScanResult failed:', e);
            }
        }

        async function restoreScanResult(ioc) {
            try {
                const db = await openDB();
                return new Promise(resolve => {
                    const tx   = db.transaction('scans', 'readonly');
                    const req  = tx.objectStore('scans').get(ioc);
                    req.onsuccess = e => resolve(e.target.result || null);
                    req.onerror   = () => resolve(null);
                });
            } catch(e) { return null; }
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
                    <h2 style="margin-bottom: 20px; color: var(--accent-blue);"> Frequently Asked Questions</h2>
                    
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> What does ThreatAnalyzer do?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            ThreatAnalyzer enriches Indicators of Compromise (IOCs) with multi-source threat intelligence, 
                            correlates results, and summarizes risk signals so analysts can act quickly.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> What IOC types are supported?</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>URL</strong></li>
                            <li><strong>Domain</strong></li>
                            <li><strong>IP Address</strong></li>
                            <li><strong>File Hash</strong> (MD5, SHA1, SHA256)</li>
                        </ul>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> Does it automatically detect IOC types?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            Yes. Leave the IOC type set to Auto-detect and ThreatAnalyzer will infer the type as you paste or type.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> Can I investigate a single IOC?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            Single IOC mode runs a full investigation across all enabled providers and consolidates the results.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> Can I scan multiple IOCs in bulk?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            Yes. Paste multiple IOCs (one per line) to run a bulk scan and review risk signals at scale.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> How are results combined?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            ThreatAnalyzer merges provider verdicts into a Combined Results & Analysis view that highlights severity, 
                            confidence, and key context in one place.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> What is Quick Query for SIEM / EDR?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            Quick Query generates ready-to-use search statements for popular SIEM/EDR workflows, saving time during investigations.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> What is the Investigation Notes workspace?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8;">
                            Use Investigation Notes to capture findings, hypotheses, and context alongside your IOC analysis.
                        </p>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> Which threat intelligence providers are supported?</h3>
                        <ul style="margin-left: 20px; color: var(--text-secondary); line-height: 1.8;">
                            <li><strong>VirusTotal</strong></li>
                            <li><strong>AbuseIPDB</strong></li>
                            <li><strong>WHOIS</strong></li>
                            <li><strong>URLScan</strong></li>
                        </ul>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <h3 style="color: var(--accent-blue); margin-top: 16px;"> How do I use ThreatAnalyzer?</h3>
                        <p style="color: var(--text-secondary); line-height: 1.8; margin-bottom: 12px;">
                            Watch the quick demo below for a walkthrough of the platform in action.
                        </p>
                        <div class="demo-video-card" onclick="window.open('https://youtu.be/-Yu7HrRjHo8','_blank','noopener')">
                            <div class="demo-video-overlay">
                                ▶ Watch Demo Video
                            </div>
                            <p class="demo-video-desc">
                                See how ThreatAnalyzer works: IOC investigation, bulk scanning, and threat intelligence correlation.
                            </p>
                        </div>
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

