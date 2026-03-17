// UI Panels Module
// Modern Analyst Dashboard for SOC Threat Investigation

function renderCombinedPanel() {
    const container = document.getElementById('combinedResults');

    if (!currentResults.vt && !currentResults.abuseipdb && !currentResults.whois && !currentResults.urlscan
        && !currentResults.threatfox && !currentResults.urlhaus && !currentResults.malwarebazaar) {
        container.innerHTML = `
            <div class="empty-state-modern">
                <div class="empty-icon">🔍</div>
                <h3>No Analysis Data</h3>
                <p>Run threat intelligence scans to see combined analysis</p>
            </div>
        `;
        return;
    }

    // Extract data for verdict determination
    let vtMalicious = 0;
    let vtSuspicious = 0;
    if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        vtMalicious = stats.malicious || 0;
        vtSuspicious = stats.suspicious || 0;
    }

    let abuseConfidence = 0;
    let abuseReports = 0;
    console.log('Combined Analysis - currentResults.abuseipdb:', currentResults.abuseipdb);
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        abuseConfidence = currentResults.abuseipdb.abuseConfidenceScore || 0;
        abuseReports = currentResults.abuseipdb.totalReports || 0;
        console.log('Combined Analysis - Abuse Confidence:', abuseConfidence, '%');
    }

    let urlscanMalicious = false;
    let urlscanSuspicious = false;
    let urlscanScore = 0;
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        const overall = currentResults.urlscan.verdicts.overall;
        urlscanMalicious = overall.malicious || false;
        urlscanScore = overall.score || 0;
        urlscanSuspicious = urlscanScore > 0 && urlscanScore <= 50 && !urlscanMalicious;
    }

    let domainAge = null;
    if (currentResults.whois && currentResults.whois.creation_date) {
        const creationDate = new Date(currentResults.whois.creation_date);
        const now = new Date();
        domainAge = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
    }

    // ── abuse.ch signals ────────────────────────────────────────────────────
    let threatfoxFound = false;
    let threatfoxMalware = '';
    let threatfoxConfidence = 0;
    if (currentResults.threatfox && currentResults.threatfox.found && currentResults.threatfox.iocs && currentResults.threatfox.iocs.length > 0) {
        threatfoxFound = true;
        threatfoxMalware = currentResults.threatfox.iocs[0].malware_printable || currentResults.threatfox.iocs[0].malware || '';
        threatfoxConfidence = currentResults.threatfox.iocs[0].confidence_level || 0;
    }

    let urlhausFound = false;
    let urlhausOnline = false;
    let urlhausThreat = '';
    if (currentResults.urlhaus && currentResults.urlhaus.found) {
        urlhausFound = true;
        urlhausOnline = currentResults.urlhaus.url_status === 'online';
        urlhausThreat = currentResults.urlhaus.threat || '';
    }

    let mbFound = false;
    let mbFamily = '';
    if (currentResults.malwarebazaar && currentResults.malwarebazaar.found) {
        mbFound = true;
        mbFamily = currentResults.malwarebazaar.malware_family || 'Unknown';
    }

    // Determine verdict based on priority order
    let verdictCategory = '';
    let verdictClass = '';
    
    if (urlscanMalicious || (threatfoxFound && threatfoxConfidence >= 75) || urlhausOnline || mbFound) {
        verdictCategory = 'MALICIOUS';
        verdictClass = 'high';
    } else if (vtMalicious > 5) {
        verdictCategory = 'MALICIOUS';
        verdictClass = 'high';
    } else if (abuseConfidence > 75) {
        verdictCategory = 'MALICIOUS';
        verdictClass = 'high';
    } else if (vtMalicious >= 3 && vtMalicious <= 5) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    } else if (urlscanSuspicious || (threatfoxFound && threatfoxConfidence >= 50) || urlhausFound) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    } else if (domainAge !== null && domainAge < 180) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    } else {
        verdictCategory = 'NEUTRAL';
        verdictClass = 'low';
    }

    // Analyst Recommendation
    let recommendation = '';
    if (verdictCategory === 'MALICIOUS') {
        recommendation = 'BLOCK AND INVESTIGATE';
    } else if (verdictCategory === 'SUSPICIOUS') {
        recommendation = 'REVIEW';
    } else {
        recommendation = 'MONITOR';
    }

    // Collect signals
    const positiveSignals = [];
    const riskSignals = [];

    if (currentResults.whois && currentResults.whois.creation_date) {
        if (domainAge !== null && domainAge > 365) {
            positiveSignals.push({ icon: '✓', text: 'Established domain (>365 days)', color: 'green' });
        } else if (domainAge !== null && domainAge < 180) {
            riskSignal = { icon: '⚠', text: 'Newly registered domain (<180 days)', color: 'yellow' };
            riskSignals.push(riskSignal);
        }
    }
    if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        if (!stats.malicious && !stats.suspicious) {
            positiveSignals.push({ icon: '✓', text: 'No VirusTotal malicious detections', color: 'green' });
        }
        if (stats.malicious > 0) {
            riskSignals.push({ icon: '✗', text: `Malware detected (${stats.malicious} engines)`, color: 'red' });
        }
        if (stats.suspicious > 0) {
            riskSignals.push({ icon: '⚠', text: `Suspicious detections (${stats.suspicious} engines)`, color: 'yellow' });
        }
    }
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        if (abuseConfidence === 0) {
            positiveSignals.push({ icon: '✓', text: 'No abuse reports (AbuseIPDB)', color: 'green' });
        } else if (abuseConfidence > 75) {
            riskSignals.push({ icon: '✗', text: `High abuse confidence (${abuseConfidence}%)`, color: 'red' });
        } else if (abuseConfidence > 0) {
            riskSignals.push({ icon: '⚠', text: `Moderate abuse confidence (${abuseConfidence}%)`, color: 'yellow' });
        }
    }
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        if (!urlscanMalicious && urlscanScore === 0) {
            positiveSignals.push({ icon: '✓', text: 'URLScan: No threats detected', color: 'green' });
        }
        if (urlscanMalicious) {
            riskSignals.push({ icon: '✗', text: 'URLScan: Malicious verdict', color: 'red' });
        }
    }

    // ThreatFox signals
    if (threatfoxFound) {
        riskSignals.push({ icon: '✗', text: `ThreatFox: ${threatfoxMalware || 'Malware'} (${threatfoxConfidence}% confidence)`, color: threatfoxConfidence >= 75 ? 'red' : 'yellow' });
    } else if (currentResults.threatfox && !currentResults.threatfox.error) {
        positiveSignals.push({ icon: '✓', text: 'ThreatFox: No IOC matches', color: 'green' });
    }

    // URLhaus signals
    if (urlhausFound) {
        riskSignals.push({ icon: '✗', text: `URLhaus: ${urlhausThreat || 'Malware distribution'} — ${currentResults.urlhaus.url_status || 'known'}`, color: urlhausOnline ? 'red' : 'yellow' });
    } else if (currentResults.urlhaus && !currentResults.urlhaus.error) {
        positiveSignals.push({ icon: '✓', text: 'URLhaus: Not listed as malware distributor', color: 'green' });
    }

    // MalwareBazaar signals
    if (mbFound) {
        riskSignals.push({ icon: '✗', text: `MalwareBazaar: Known malware — ${mbFamily}`, color: 'red' });
    } else if (currentResults.malwarebazaar && !currentResults.malwarebazaar.error) {
        positiveSignals.push({ icon: '✓', text: 'MalwareBazaar: Hash not in malware database', color: 'green' });
    }

    // Determine colors based on verdict
    const verdictColors = {
        high: { bg: 'rgba(248, 81, 73, 0.15)', border: '#f85149', text: '#f85149', gradient: 'linear-gradient(135deg, #f85149 0%, #da3633 100%)' },
        suspicious: { bg: 'rgba(210, 153, 34, 0.15)', border: '#d29922', text: '#d29922', gradient: 'linear-gradient(135deg, #d29922 0%, #bb8009 100%)' },
        low: { bg: 'rgba(63, 185, 80, 0.15)', border: '#3fb950', text: '#3fb950', gradient: 'linear-gradient(135deg, #3fb950 0%, #238636 100%)' }
    };
    const colors = verdictColors[verdictClass];

    const typeIcon = currentResults.type === 'ip' ? '🖥' : currentResults.type === 'domain' ? '🌐' : currentResults.type === 'url' ? '🔗' : currentResults.type === 'hash' ? '📄' : '🔍';

    let html = `
        <style>
            .dashboard-container {
                display: flex;
                flex-direction: column;
                gap: 20px;
                animation: fadeIn 0.4s ease-out;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            .dashboard-header {
                background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
                border: 1px solid #30363d;
                border-radius: 16px;
                padding: 24px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                flex-wrap: wrap;
                gap: 16px;
            }
            .ioc-info {
                display: flex;
                align-items: center;
                gap: 16px;
            }
            .ioc-badge {
                background: ${colors.bg};
                border: 1px solid ${colors.border};
                border-radius: 12px;
                padding: 12px 20px;
                display: flex;
                align-items: center;
                gap: 12px;
            }
            .ioc-icon {
                font-size: 24px;
            }
            .ioc-details {
                display: flex;
                flex-direction: column;
            }
            .ioc-value {
                font-size: 18px;
                font-weight: 600;
                color: #e6edf3;
                font-family: 'JetBrains Mono', monospace;
            }
            .ioc-type {
                font-size: 12px;
                color: #8b949e;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .verdict-badge {
                background: ${colors.gradient};
                border-radius: 12px;
                padding: 16px 32px;
                text-align: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3), 0 0 40px ${colors.bg};
            }
            .verdict-label {
                font-size: 11px;
                color: rgba(255,255,255,0.7);
                text-transform: uppercase;
                letter-spacing: 2px;
                margin-bottom: 4px;
            }
            .verdict-text {
                font-size: 22px;
                font-weight: 700;
                color: white;
                text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            }
            .quick-actions {
                display: flex;
                gap: 8px;
            }
            .quick-btn {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 10px 16px;
                color: #8b949e;
                cursor: pointer;
                font-size: 13px;
                transition: all 0.2s ease;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .quick-btn:hover {
                background: #30363d;
                color: #e6edf3;
                border-color: #58a6ff;
            }
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 16px;
            }
            .dashboard-card {
                background: linear-gradient(180deg, #161b22 0%, #12171e 100%);
                border: 1px solid #30363d;
                border-radius: 16px;
                overflow: hidden;
                transition: all 0.3s ease;
            }
            .dashboard-card:hover {
                border-color: #58a6ff;
                box-shadow: 0 8px 32px rgba(88, 166, 255, 0.1);
                transform: translateY(-2px);
            }
            .card-header {
                background: linear-gradient(90deg, #1c2128 0%, #161b22 100%);
                padding: 16px 20px;
                border-bottom: 1px solid #21262d;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }
            .card-title {
                font-size: 14px;
                font-weight: 600;
                color: #e6edf3;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .card-title-icon {
                width: 32px;
                height: 32px;
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 16px;
            }
            .card-body {
                padding: 20px;
            }
            .signal-list {
                list-style: none;
                display: flex;
                flex-direction: column;
                gap: 12px;
            }
            .signal-item {
                display: flex;
                align-items: flex-start;
                gap: 12px;
                padding: 12px;
                border-radius: 10px;
                background: #21262d;
                transition: all 0.2s ease;
            }
            .signal-item:hover {
                background: #2d333b;
            }
            .signal-icon {
                width: 28px;
                height: 28px;
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 14px;
                flex-shrink: 0;
            }
            .signal-icon.green { background: rgba(63, 185, 80, 0.2); }
            .signal-icon.yellow { background: rgba(210, 153, 34, 0.2); }
            .signal-icon.red { background: rgba(248, 81, 73, 0.2); }
            .signal-text {
                color: #e6edf3;
                font-size: 13px;
                line-height: 1.5;
            }
            .no-signals {
                color: #6e7681;
                font-size: 13px;
                text-align: center;
                padding: 20px;
            }
            .evidence-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
            }
            .evidence-item {
                background: #21262d;
                border-radius: 10px;
                padding: 16px;
                text-align: center;
            }
            .evidence-source {
                font-size: 11px;
                color: #8b949e;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 8px;
            }
            .evidence-value {
                font-size: 18px;
                font-weight: 600;
                color: #e6edf3;
                margin-bottom: 4px;
            }
            .evidence-detail {
                font-size: 11px;
            }
            .evidence-detail.green { color: #3fb950; }
            .evidence-detail.yellow { color: #d29922; }
            .evidence-detail.red { color: #f85149; }
            .evidence-detail.gray { color: #6e7681; }
            .recommendation-box {
                background: ${colors.gradient};
                border-radius: 16px;
                padding: 28px;
                text-align: center;
            }
            .recommendation-icon {
                font-size: 40px;
                margin-bottom: 12px;
            }
            .recommendation-text {
                font-size: 20px;
                font-weight: 700;
                color: white;
                text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            }
            .recommendation-hint {
                font-size: 12px;
                color: rgba(255,255,255,0.7);
                margin-top: 8px;
            }
            .sources-bar {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
            }
            .source-tag {
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 11px;
                color: #8b949e;
            }
            .source-tag.active {
                background: rgba(88, 166, 255, 0.15);
                border-color: #58a6ff;
                color: #58a6ff;
            }
            .empty-state-modern {
                text-align: center;
                padding: 60px 20px;
                color: #8b949e;
            }
            .empty-icon {
                font-size: 48px;
                margin-bottom: 16px;
                opacity: 0.5;
            }
            .empty-state-modern h3 {
                font-size: 18px;
                color: #e6edf3;
                margin-bottom: 8px;
            }
        </style>
        
        <div class="dashboard-container">
            <!-- Header Section -->
            <div class="dashboard-header">
                <div class="ioc-info">
                    <div class="ioc-badge">
                        <span class="ioc-icon">${typeIcon}</span>
                        <div class="ioc-details">
                            <span class="ioc-value">${currentResults.ioc}</span>
                            <span class="ioc-type">${(currentResults.type || 'unknown').toUpperCase()}</span>
                        </div>
                    </div>
                    <div class="sources-bar">
                        ${currentResults.vt ? '<span class="source-tag active">VirusTotal</span>' : '<span class="source-tag">VirusTotal</span>'}
                        ${currentResults.abuseipdb ? '<span class="source-tag active">AbuseIPDB</span>' : '<span class="source-tag">AbuseIPDB</span>'}
                        ${currentResults.whois ? '<span class="source-tag active">WHOIS</span>' : '<span class="source-tag">WHOIS</span>'}
                        ${currentResults.urlscan ? '<span class="source-tag active">URLScan</span>' : '<span class="source-tag">URLScan</span>'}
                    </div>
                </div>
                <div class="verdict-badge">
                    <div class="verdict-label">Final Verdict</div>
                    <div class="verdict-text">${verdictCategory}</div>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="quick-actions">
                <button class="quick-btn" onclick="copyIOC()">📋 Copy IOC</button>
                <button class="quick-btn" onclick="copyCombinedResults()">📄 Copy Report</button>
                <button class="quick-btn" onclick="exportTXT()">💾 Export</button>
            </div>

            <!-- Main Grid -->
            <div class="dashboard-grid">
                <!-- Risk Signals Card -->
                <div class="dashboard-card">
                    <div class="card-header">
                        <div class="card-title">
                            <div class="card-title-icon" style="background: rgba(248, 81, 73, 0.2);">⚠️</div>
                            Risk Signals
                        </div>
                    </div>
                    <div class="card-body">
                        ${riskSignals.length > 0 ? `
                            <ul class="signal-list">
                                ${riskSignals.map(s => `
                                    <li class="signal-item">
                                        <div class="signal-icon ${s.color}">${s.icon}</div>
                                        <span class="signal-text">${s.text}</span>
                                    </li>
                                `).join('')}
                            </ul>
                        ` : '<div class="no-signals">No risk signals detected</div>'}
                    </div>
                </div>

                <!-- Positive Signals Card -->
                <div class="dashboard-card">
                    <div class="card-header">
                        <div class="card-title">
                            <div class="card-title-icon" style="background: rgba(63, 185, 80, 0.2);">✅</div>
                            Positive Signals
                        </div>
                    </div>
                    <div class="card-body">
                        ${positiveSignals.length > 0 ? `
                            <ul class="signal-list">
                                ${positiveSignals.map(s => `
                                    <li class="signal-item">
                                        <div class="signal-icon ${s.color}">${s.icon}</div>
                                        <span class="signal-text">${s.text}</span>
                                    </li>
                                `).join('')}
                            </ul>
                        ` : '<div class="no-signals">No positive signals detected</div>'}
                    </div>
                </div>

                <!-- Evidence Weighting Card -->
                <div class="dashboard-card">
                    <div class="card-header">
                        <div class="card-title">
                            <div class="card-title-icon" style="background: rgba(88, 166, 255, 0.2);">📊</div>
                            Evidence Weighting
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="evidence-grid">
                            <!-- VirusTotal -->
                            <div class="evidence-item">
                                <div class="evidence-source">VirusTotal</div>
                                ${currentResults.vt ? (() => {
                                    const stats = currentResults.vt.data.attributes.last_analysis_stats;
                                    const total = Object.values(stats).reduce((a, b) => a + b, 0);
                                    const conf = vtMalicious > 5 ? 'red' : vtMalicious > 0 ? 'yellow' : 'green';
                                    return `<div class="evidence-value">${vtMalicious}/${total}</div><div class="evidence-detail ${conf}">${vtMalicious > 5 ? 'HIGH RISK' : vtMalicious > 0 ? 'MEDIUM' : 'CLEAN'}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                            <!-- AbuseIPDB -->
                            <div class="evidence-item">
                                <div class="evidence-source">AbuseIPDB</div>
                                ${currentResults.abuseipdb ? (() => {
                                    const conf = abuseConfidence > 75 ? 'red' : abuseConfidence > 0 ? 'yellow' : 'green';
                                    return `<div class="evidence-value">${abuseConfidence}%</div><div class="evidence-detail ${conf}">${abuseConfidence > 75 ? 'HIGH' : abuseConfidence > 0 ? 'MEDIUM' : 'CLEAN'}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                            <!-- URLScan -->
                            <div class="evidence-item">
                                <div class="evidence-source">URLScan</div>
                                ${currentResults.urlscan ? (() => {
                                    const conf = urlscanMalicious ? 'red' : urlscanScore > 0 ? 'yellow' : 'green';
                                    const status = urlscanMalicious ? 'MALICIOUS' : urlscanScore > 0 ? 'SUSPICIOUS' : 'CLEAN';
                                    return `<div class="evidence-value">${urlscanScore}</div><div class="evidence-detail ${conf}">${status}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                            <!-- WHOIS -->
                            <div class="evidence-item">
                                <div class="evidence-source">WHOIS</div>
                                ${currentResults.whois ? (() => {
                                    const conf = domainAge < 180 ? 'yellow' : domainAge < 365 ? 'yellow' : 'green';
                                    const status = domainAge < 180 ? 'SUSPICIOUS' : domainAge < 365 ? 'NEUTRAL' : 'CLEAN';
                                    return `<div class="evidence-value">${domainAge}d</div><div class="evidence-detail ${conf}">${status}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                            <!-- ThreatFox -->
                            <div class="evidence-item">
                                <div class="evidence-source">🦊 ThreatFox</div>
                                ${currentResults.threatfox && !currentResults.threatfox.error ? (() => {
                                    if (!currentResults.threatfox.found) return '<div class="evidence-value">✓</div><div class="evidence-detail green">CLEAN</div>';
                                    const col = threatfoxConfidence >= 75 ? 'red' : 'yellow';
                                    return `<div class="evidence-value">${threatfoxConfidence}%</div><div class="evidence-detail ${col}">${threatfoxMalware || 'MALWARE'}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                            <!-- URLhaus -->
                            <div class="evidence-item">
                                <div class="evidence-source">🔴 URLhaus</div>
                                ${currentResults.urlhaus && !currentResults.urlhaus.error ? (() => {
                                    if (!currentResults.urlhaus.found) return '<div class="evidence-value">✓</div><div class="evidence-detail green">CLEAN</div>';
                                    const col = urlhausOnline ? 'red' : 'yellow';
                                    return `<div class="evidence-value">${currentResults.urlhaus.url_status || 'listed'}</div><div class="evidence-detail ${col}">${urlhausThreat || 'MALWARE'}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                            <!-- MalwareBazaar -->
                            <div class="evidence-item">
                                <div class="evidence-source">☣️ MalwareBazaar</div>
                                ${currentResults.malwarebazaar && !currentResults.malwarebazaar.error ? (() => {
                                    if (!currentResults.malwarebazaar.found) return '<div class="evidence-value">✓</div><div class="evidence-detail green">CLEAN</div>';
                                    return `<div class="evidence-value">☣️</div><div class="evidence-detail red">${mbFamily || 'MALWARE'}</div>`;
                                })() : '<div class="evidence-value">-</div><div class="evidence-detail gray">No data</div>'}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Analyst Recommendation Card -->
                <div class="dashboard-card">
                    <div class="card-header">
                        <div class="card-title">
                            <div class="card-title-icon" style="background: rgba(163, 113, 247, 0.2);">💡</div>
                            Analyst Recommendation
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="recommendation-box">
                            <div class="recommendation-icon">${verdictCategory === 'MALICIOUS' ? '🚫' : verdictCategory === 'SUSPICIOUS' ? '👁️' : '✓'}</div>
                            <div class="recommendation-text">${recommendation}</div>
                            <div class="recommendation-hint">Investigation guidance - adapt based on context</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

function toggleCardPanel(header) {
    const body = header.nextElementSibling;
    body.classList.toggle('collapsed');
    const arrow = header.querySelector('span');
    arrow.textContent = body.classList.contains('collapsed') ? '▶' : '▼';
}

function toggleSocCardPanel(cardId) {
    const header = document.getElementById(cardId + '-header');
    const body = document.getElementById(cardId + '-body');
    const toggle = document.getElementById(cardId + '-toggle');

    if (header && body && toggle) {
        header.classList.toggle('expanded');
        body.classList.toggle('collapsed');
        toggle.classList.toggle('collapsed');
    }
}

// ─── ThreatFox render ────────────────────────────────────────────────────────
function renderThreatFox(data) {
    const container = document.getElementById('threatfoxResults');
    const emptyEl   = document.getElementById('threatfoxEmpty');
    if (!container) return;
    if (emptyEl) emptyEl.style.display = 'none';

    if (!data || data.error) {
        container.innerHTML = `<div class="error-message">${data?.error || 'ThreatFox data unavailable'}</div>`;
        return;
    }

    if (!data.found) {
        container.innerHTML = `
            <div class="empty-state" style="padding:40px;text-align:center;">
                <div style="font-size:36px;margin-bottom:12px;">✅</div>
                <h3 style="color:var(--color-success,#3fb950);margin-bottom:8px;">Not found in ThreatFox</h3>
                <p style="color:var(--text-muted);">This IOC has no known ThreatFox entries.</p>
            </div>`;
        return;
    }

    const iocs = data.iocs || [];
    const first = iocs[0] || {};

    // Confidence badge colour
    const conf = first.confidence_level || 0;
    const confColor = conf >= 75 ? 'var(--color-danger,#f85149)'
                    : conf >= 50 ? 'var(--color-warning,#d29922)'
                    : 'var(--color-success,#3fb950)';

    // Build rows for each matched IOC
    const rows = iocs.map(ioc => {
        const tags = (ioc.tags || []).map(t => `<span class="ioc-tag">${t}</span>`).join('');
        const conf = ioc.confidence_level || 0;
        const confCol = conf >= 75 ? '#f85149' : conf >= 50 ? '#d29922' : '#3fb950';
        return `
            <tr>
                <td style="font-family:monospace;font-size:12px;word-break:break-all;">${ioc.ioc || '-'}</td>
                <td><span class="category-badge ${ioc.ioc_type || ''}">${ioc.ioc_type || '-'}</span></td>
                <td><span class="category-badge malicious">${ioc.threat_type || '-'}</span></td>
                <td style="max-width:160px;">${ioc.malware_printable || ioc.malware || '-'}</td>
                <td><span style="color:${confCol};font-weight:700;">${conf}%</span></td>
                <td>${ioc.first_seen ? ioc.first_seen.split(' ')[0] : '-'}</td>
                <td>${tags || '<span style="color:var(--text-muted)">—</span>'}</td>
                <td>${ioc.reference
                    ? `<a href="${ioc.reference}" target="_blank" style="color:var(--accent-blue);font-size:11px;">↗ ref</a>`
                    : '-'}</td>
            </tr>`;
    }).join('');

    // Malware aliases / Malpedia link for first hit
    const aliasHtml = first.malware_alias
        ? first.malware_alias.split(',').map(a => `<span class="ioc-tag">${a.trim()}</span>`).join(' ')
        : '<span style="color:var(--text-muted)">None</span>';

    const malpediaHtml = first.malware_malpedia
        ? `<a href="${first.malware_malpedia}" target="_blank" style="color:var(--accent-blue);">
               ${first.malware_malpedia.split('/').pop()} ↗</a>`
        : '<span style="color:var(--text-muted)">N/A</span>';

    container.innerHTML = `
        <!-- Summary banner -->
        <div class="result-card" style="border-left:4px solid #f85149;margin-bottom:16px;">
            <div class="card-body" style="display:flex;flex-wrap:wrap;gap:24px;align-items:center;">
                <div style="text-align:center;min-width:80px;">
                    <div style="font-size:32px;font-weight:800;color:#f85149;">${iocs.length}</div>
                    <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">ThreatFox Hits</div>
                </div>
                <div style="flex:1;min-width:200px;">
                    <div style="margin-bottom:6px;">
                        <span style="color:var(--text-muted);font-size:11px;">THREAT TYPE</span><br>
                        <span style="font-weight:600;color:var(--text-primary);">${first.threat_type_desc || first.threat_type || '-'}</span>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">MALWARE FAMILY</span><br>
                        <span style="font-weight:600;color:#f85149;">${first.malware_printable || first.malware || 'Unknown'}</span>
                    </div>
                </div>
                <div style="flex:1;min-width:200px;">
                    <div style="margin-bottom:6px;">
                        <span style="color:var(--text-muted);font-size:11px;">CONFIDENCE</span><br>
                        <span style="font-weight:800;font-size:20px;color:${confColor};">${conf}%</span>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">FIRST SEEN</span><br>
                        <span style="color:var(--text-primary);">${first.first_seen ? first.first_seen.split(' ')[0] : '-'}</span>
                    </div>
                </div>
                <div style="flex:1;min-width:200px;">
                    <div style="margin-bottom:6px;">
                        <span style="color:var(--text-muted);font-size:11px;">ALIASES</span><br>
                        <div style="margin-top:4px;">${aliasHtml}</div>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">MALPEDIA</span><br>
                        ${malpediaHtml}
                    </div>
                </div>
            </div>
        </div>

        <!-- IOC table -->
        <div class="result-card">
            <div class="card-header" onclick="toggleCard(this)">
                <h3>🦊 ThreatFox IOC Matches (${iocs.length})</h3>
                <span>▼</span>
            </div>
            <div class="card-body" style="overflow-x:auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>IOC Value</th>
                            <th>Type</th>
                            <th>Threat</th>
                            <th>Malware</th>
                            <th>Confidence</th>
                            <th>First Seen</th>
                            <th>Tags</th>
                            <th>Ref</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        </div>`;
}

// ─── URLhaus render ──────────────────────────────────────────────────────────
function renderURLhaus(data) {
    const container = document.getElementById('urlhausResults');
    const emptyEl   = document.getElementById('urlhausEmpty');
    if (!container) return;
    if (emptyEl) emptyEl.style.display = 'none';

    if (!data || data.error) {
        container.innerHTML = `<div class="error-message">${data?.error || 'URLhaus data unavailable'}</div>`;
        return;
    }

    if (!data.found) {
        container.innerHTML = `
            <div class="empty-state" style="padding:40px;text-align:center;">
                <div style="font-size:36px;margin-bottom:12px;">✅</div>
                <h3 style="color:var(--color-success,#3fb950);margin-bottom:8px;">Not found in URLhaus</h3>
                <p style="color:var(--text-muted);">This IOC has no known URLhaus malware distribution entries.</p>
            </div>`;
        return;
    }

    // Status colour
    const statusColor = data.url_status === 'online'  ? '#f85149'
                      : data.url_status === 'offline' ? '#3fb950'
                      : 'var(--text-muted)';

    // Blacklist badges
    const blHtml = Object.entries(data.blacklists || {}).map(([bl, status]) => {
        const listed = status === 'listed';
        return `<span class="category-badge ${listed ? 'malicious' : 'undetected'}"
                      title="${bl}">${bl.replace('surbl_', '').replace('_', ' ')}: ${status}</span>`;
    }).join(' ') || '<span style="color:var(--text-muted)">None checked</span>';

    // Tags
    const tagHtml = (data.tags || []).map(t => `<span class="ioc-tag">${t}</span>`).join(' ')
                  || '<span style="color:var(--text-muted)">None</span>';

    // Associated URLs table (for host/IP lookups)
    const urlRows = (data.urls || []).map(u => {
        const uColor = u.url_status === 'online' ? '#f85149' : '#3fb950';
        const uTags = (u.tags || []).map(t => `<span class="ioc-tag" style="font-size:10px;">${t}</span>`).join(' ');
        return `
            <tr>
                <td style="font-family:monospace;font-size:11px;word-break:break-all;max-width:300px;">${u.url || '-'}</td>
                <td><span style="color:${uColor};font-weight:700;">${u.url_status || '-'}</span></td>
                <td>${u.threat || '-'}</td>
                <td>${u.date_added ? u.date_added.split(' ')[0] : '-'}</td>
                <td>${uTags || '-'}</td>
            </tr>`;
    }).join('');

    const urlsSection = urlRows ? `
        <div class="result-card" style="margin-top:16px;">
            <div class="card-header" onclick="toggleCard(this)">
                <h3>🔗 Associated Malware URLs (${data.urls.length})</h3>
                <span>▼</span>
            </div>
            <div class="card-body" style="overflow-x:auto;">
                <table class="data-table">
                    <thead><tr><th>URL</th><th>Status</th><th>Threat</th><th>Date Added</th><th>Tags</th></tr></thead>
                    <tbody>${urlRows}</tbody>
                </table>
            </div>
        </div>` : '';

    // Payload section (hash lookups)
    const payloadSection = data.sha256_hash ? `
        <div class="result-card" style="margin-top:16px;">
            <div class="card-header" onclick="toggleCard(this)">
                <h3>📦 Payload Details</h3>
                <span>▼</span>
            </div>
            <div class="card-body">
                <table class="data-table">
                    <tr><th>File Type</th><td>${data.file_type || 'N/A'}</td></tr>
                    <tr><th>File Size</th><td>${data.file_size ? (data.file_size / 1024).toFixed(1) + ' KB' : 'N/A'}</td></tr>
                    <tr><th>MD5</th><td style="font-family:monospace;">${data.md5_hash || 'N/A'}</td></tr>
                    <tr><th>SHA256</th><td style="font-family:monospace;word-break:break-all;">${data.sha256_hash || 'N/A'}</td></tr>
                    <tr><th>Signature</th><td>${data.signature || 'N/A'}</td></tr>
                </table>
            </div>
        </div>` : '';

    container.innerHTML = `
        <!-- Summary -->
        <div class="result-card" style="border-left:4px solid ${statusColor};margin-bottom:16px;">
            <div class="card-body" style="display:flex;flex-wrap:wrap;gap:24px;align-items:center;">
                <div style="text-align:center;min-width:80px;">
                    <div style="font-size:28px;">🔴</div>
                    <div style="font-size:20px;font-weight:800;color:${statusColor};text-transform:uppercase;">
                        ${data.url_status || 'Found'}
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);">URL STATUS</div>
                </div>
                <div style="flex:1;min-width:200px;">
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">THREAT TYPE</span><br>
                        <span style="font-weight:600;color:#f85149;">${data.threat || 'Unknown'}</span>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">DATE ADDED</span><br>
                        <span>${data.date_added ? data.date_added.split(' ')[0] : 'N/A'}</span>
                    </div>
                </div>
                <div style="flex:1;min-width:200px;">
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">TAGS</span><br>
                        <div style="margin-top:4px;">${tagHtml}</div>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">BLACKLISTS</span><br>
                        <div style="margin-top:4px;">${blHtml}</div>
                    </div>
                </div>
                ${data.urlhaus_ref ? `
                <div>
                    <a href="${data.urlhaus_ref}" target="_blank"
                       style="color:var(--accent-blue);font-size:13px;">View on URLhaus ↗</a>
                </div>` : ''}
            </div>
        </div>
        ${urlsSection}
        ${payloadSection}`;
}

// ─── MalwareBazaar render ────────────────────────────────────────────────────
function renderMalwareBazaar(data) {
    const container = document.getElementById('malwarebazaarResults');
    const emptyEl   = document.getElementById('malwarebazaarEmpty');
    if (!container) return;
    if (emptyEl) emptyEl.style.display = 'none';

    if (!data || data.error) {
        container.innerHTML = `<div class="error-message">${data?.error || 'MalwareBazaar data unavailable'}</div>`;
        return;
    }

    if (!data.found) {
        container.innerHTML = `
            <div class="empty-state" style="padding:40px;text-align:center;">
                <div style="font-size:36px;margin-bottom:12px;">✅</div>
                <h3 style="color:var(--color-success,#3fb950);margin-bottom:8px;">Not found in MalwareBazaar</h3>
                <p style="color:var(--text-muted);">This hash has no MalwareBazaar sample entry.</p>
            </div>`;
        return;
    }

    const tagHtml = (data.tags || []).map(t => `<span class="ioc-tag">${t}</span>`).join(' ')
                  || '<span style="color:var(--text-muted)">None</span>';

    // Vendor intel table
    const vendorRows = Object.entries(data.vendor_intel || {}).map(([vendor, info]) => {
        const det = info.detection || info.result || 'Detected';
        return `<tr><td>${vendor}</td><td style="color:#f85149;font-weight:600;">${det}</td></tr>`;
    }).join('');

    const vendorSection = vendorRows ? `
        <div class="result-card" style="margin-top:16px;">
            <div class="card-header" onclick="toggleCard(this)">
                <h3>🛡️ Vendor Intelligence</h3><span>▼</span>
            </div>
            <div class="card-body" style="overflow-x:auto;">
                <table class="data-table">
                    <thead><tr><th>Vendor</th><th>Detection</th></tr></thead>
                    <tbody>${vendorRows}</tbody>
                </table>
            </div>
        </div>` : '';

    container.innerHTML = `
        <!-- Summary -->
        <div class="result-card" style="border-left:4px solid #f85149;margin-bottom:16px;">
            <div class="card-body" style="display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start;">
                <div style="text-align:center;min-width:80px;">
                    <div style="font-size:36px;">☣️</div>
                    <div style="font-size:13px;font-weight:700;color:#f85149;margin-top:4px;">MALWARE</div>
                </div>
                <div style="flex:1;min-width:180px;">
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">MALWARE FAMILY</span><br>
                        <span style="font-weight:700;font-size:16px;color:#f85149;">${data.malware_family || 'Unknown'}</span>
                    </div>
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">FILE NAME</span><br>
                        <span style="font-family:monospace;">${data.file_name || 'N/A'}</span>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">TAGS</span><br>
                        <div style="margin-top:4px;">${tagHtml}</div>
                    </div>
                </div>
                <div style="flex:1;min-width:180px;">
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">FILE TYPE</span><br>
                        <span>${data.file_type_desc || data.file_type || 'N/A'}</span>
                    </div>
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">FILE SIZE</span><br>
                        <span>${data.file_size ? (data.file_size / 1024).toFixed(1) + ' KB' : 'N/A'}</span>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">ORIGIN COUNTRY</span><br>
                        <span>${data.origin_country || 'Unknown'}</span>
                    </div>
                </div>
                <div style="flex:1;min-width:180px;">
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">FIRST SEEN</span><br>
                        <span>${data.first_seen ? data.first_seen.split(' ')[0] : 'N/A'}</span>
                    </div>
                    <div style="margin-bottom:8px;">
                        <span style="color:var(--text-muted);font-size:11px;">LAST SEEN</span><br>
                        <span>${data.last_seen ? data.last_seen.split(' ')[0] : 'N/A'}</span>
                    </div>
                    <div>
                        <span style="color:var(--text-muted);font-size:11px;">REPORTER</span><br>
                        <span>${data.reporter || 'N/A'}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Hashes -->
        <div class="result-card" style="margin-bottom:16px;">
            <div class="card-header" onclick="toggleCard(this)">
                <h3>#️⃣ Hash Values</h3><span>▼</span>
            </div>
            <div class="card-body">
                <table class="data-table">
                    <tr><th style="width:80px;">MD5</th>
                        <td style="font-family:monospace;word-break:break-all;">${data.md5 || 'N/A'}</td></tr>
                    <tr><th>SHA1</th>
                        <td style="font-family:monospace;word-break:break-all;">${data.sha1 || 'N/A'}</td></tr>
                    <tr><th>SHA256</th>
                        <td style="font-family:monospace;word-break:break-all;">${data.sha256 || 'N/A'}</td></tr>
                </table>
                ${data.bazaar_ref
                    ? `<div style="margin-top:12px;">
                           <a href="${data.bazaar_ref}" target="_blank"
                              style="color:var(--accent-blue);">View full sample on MalwareBazaar ↗</a>
                       </div>` : ''}
            </div>
        </div>
        ${vendorSection}`;
}
