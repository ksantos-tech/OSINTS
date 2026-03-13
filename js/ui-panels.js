// UI Panels Module
// Modern Analyst Dashboard for SOC Threat Investigation

function renderCombinedPanel() {
    const container = document.getElementById('combinedResults');

    if (!currentResults.vt && !currentResults.abuseipdb && !currentResults.whois && !currentResults.urlscan) {
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
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        abuseConfidence = currentResults.abuseipdb.abuseConfidenceScore || 0;
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

    // Determine verdict based on priority order
    let verdictCategory = '';
    let verdictClass = '';
    
    if (urlscanMalicious) {
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
    } else if (urlscanSuspicious) {
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
