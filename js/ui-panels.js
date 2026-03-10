// UI Panels Module
// Contains rendering logic for SOC panels and collapsible card helpers.

function renderCombinedPanel() {
    const container = document.getElementById('combinedResults');

    if (!currentResults.vt && !currentResults.abuseipdb && !currentResults.whois && !currentResults.urlscan) {
        container.innerHTML = '<div class="empty-state"><span>Run scans to see combined analysis</span></div>';
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
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        const overall = currentResults.urlscan.verdicts.overall;
        urlscanMalicious = overall.malicious || false;
        const score = overall.score || 0;
        urlscanSuspicious = score > 0 && score <= 50 && !urlscanMalicious;
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
    
    // Priority 1: URLScan verdict = Malicious → MALICIOUS
    if (urlscanMalicious) {
        verdictCategory = 'MALICIOUS';
        verdictClass = 'high';
    }
    // Priority 2: VirusTotal detections > 5 → MALICIOUS
    else if (vtMalicious > 5) {
        verdictCategory = 'MALICIOUS';
        verdictClass = 'high';
    }
    // Priority 3: AbuseIPDB confidence > 75 → MALICIOUS
    else if (abuseConfidence > 75) {
        verdictCategory = 'MALICIOUS';
        verdictClass = 'high';
    }
    // Priority 4: VirusTotal detections 3-5 → SUSPICIOUS
    else if (vtMalicious >= 3 && vtMalicious <= 5) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    }
    // Priority 5: URLScan verdict = Suspicious → SUSPICIOUS
    else if (urlscanSuspicious) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    }
    // Priority 6: Domain age < 180 days → SUSPICIOUS
    else if (domainAge !== null && domainAge < 180) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    }
    // Priority 7: Otherwise → NEUTRAL
    else {
        verdictCategory = 'NEUTRAL';
        verdictClass = 'low';
    }

    // Analyst Recommendation
    let recommendation = '';
    let recommendationClass = '';
    if (verdictCategory === 'MALICIOUS') {
        recommendation = 'BLOCK AND INVESTIGATE';
        recommendationClass = 'block';
    } else if (verdictCategory === 'SUSPICIOUS') {
        recommendation = 'REVIEW';
        recommendationClass = 'review';
    } else {
        recommendation = 'MONITOR';
        recommendationClass = 'allow';
    }

    // Collect Positive Signals based on new rules
    const positiveSignals = [];
    if (currentResults.whois && currentResults.whois.creation_date) {
        if (domainAge !== null && domainAge > 365) {
            positiveSignals.push('Established domain (>365 days)');
        }
    }
    if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        if (!stats.malicious && !stats.suspicious) {
            positiveSignals.push('No VirusTotal malicious detections');
        }
    }
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        if (currentResults.abuseipdb.abuseConfidenceScore === 0) {
            positiveSignals.push('No abuse reports (AbuseIPDB)');
        }
    }
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        if (!currentResults.urlscan.verdicts.overall.malicious && (currentResults.urlscan.verdicts.overall.score || 0) === 0) {
            positiveSignals.push('No URLScan malicious verdict');
        }
    }

    // Collect Risk Signals based on new rules
    const riskSignals = [];
    if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        if (stats.malicious > 0) {
            riskSignals.push('Malware detections from VirusTotal');
        }
        if (stats.suspicious > 0) {
            riskSignals.push('Suspicious detections from VirusTotal');
        }
    }
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        if (currentResults.abuseipdb.abuseConfidenceScore > 75) {
            riskSignals.push('High AbuseIPDB confidence');
        } else if (currentResults.abuseipdb.abuseConfidenceScore > 0) {
            riskSignals.push('Moderate AbuseIPDB confidence');
        }
    }
    if (currentResults.whois && currentResults.whois.creation_date) {
        if (domainAge !== null && domainAge < 180) {
            riskSignals.push('Newly registered domain (<180 days)');
        }
    }
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        if (currentResults.urlscan.verdicts.overall.malicious) {
            riskSignals.push('URLScan flagged as malicious');
        }
    }

    const typeIcon = currentResults.type === 'ip' ? '🖥' : currentResults.type === 'domain' ? '📧' : currentResults.type === 'url' ? '🌐' : currentResults.type === 'hash' ? '📄' : '🔍';
    let html = '';

    html += '<div class="quick-actions-bar">';
    html += '<button onclick="copyIOC()" class="quick-action-btn">📋 Copy IOC</button>';
    html += '<button onclick="copyCombinedResults()" class="quick-action-btn">📄 Copy Report</button>';
    html += '<button onclick="exportTXT()" class="quick-action-btn">💾 Export</button>';
    html += '</div>';

    html += '<div class="ioc-header-bar">';
    html += '<div class="ioc-header-main">';
    html += '<span class="ioc-icon">' + typeIcon + '</span>';
    html += '<span class="ioc-value">' + currentResults.ioc + '</span>';
    html += '<span class="ioc-type-badge">' + (currentResults.type || 'N/A').toUpperCase() + '</span>';
    html += '</div>';
    html += '<div class="sources-indicator">';
    let sources = [];
    if (currentResults.vt) sources.push('VirusTotal');
    if (currentResults.abuseipdb) sources.push('AbuseIPDB');
    if (currentResults.whois) sources.push('WHOIS');
    if (currentResults.urlscan) sources.push('URLScan');
    html += '📡 Sources: ' + (sources.length > 0 ? sources.join(' | ') : 'None');
    html += '</div>';
    html += '</div>';

    // Final Verdict Banner
    const verdictColor = verdictClass === 'high' ? 'var(--accent-red)' : verdictClass === 'suspicious' ? 'var(--accent-yellow)' : 'var(--accent-green)';
    html += '<div class="soc-card" style="border-left: 4px solid ' + verdictColor + ';">';
    html += '<div class="soc-card-header expanded">';
    html += '<h3 style="color: ' + verdictColor + ';">⚖️ Final Verdict: ' + verdictCategory + '</h3>';
    html += '</div>';
    html += '</div>';

    // Positive Signals Section
    html += '<div class="soc-card"><div id="positive-signals-header" class="soc-card-header expanded" onclick="toggleSocCardPanel(\'positive-signals\')"><h3>✅ Positive Signals</h3><span id="positive-signals-toggle" class="soc-card-toggle">▼</span></div>';
    html += '<div id="positive-signals-body" class="soc-card-body">';
    if (positiveSignals.length > 0) {
        html += '<ul style="margin: 0; padding-left: 20px; color: var(--accent-green);">';
        positiveSignals.forEach(signal => {
            html += '<li style="margin-bottom: 8px;">' + signal + '</li>';
        });
        html += '</ul>';
    } else {
        html += '<span style="color: var(--text-muted);">No positive signals detected</span>';
    }
    html += '</div></div>';

    // Risk Signals Section
    html += '<div class="soc-card"><div id="risk-signals-header" class="soc-card-header expanded" onclick="toggleSocCardPanel(\'risk-signals\')"><h3>⚠️ Risk Signals</h3><span id="risk-signals-toggle" class="soc-card-toggle">▼</span></div>';
    html += '<div id="risk-signals-body" class="soc-card-body">';
    if (riskSignals.length > 0) {
        html += '<ul style="margin: 0; padding-left: 20px; color: var(--accent-red);">';
        riskSignals.forEach(signal => {
            html += '<li style="margin-bottom: 8px;">' + signal + '</li>';
        });
        html += '</ul>';
    } else {
        html += '<span style="color: var(--text-muted);">No risk signals detected</span>';
    }
    html += '</div></div>';

    // Evidence Weighting Section
    html += '<div class="soc-card"><div id="evidence-header" class="soc-card-header expanded" onclick="toggleSocCardPanel(\'evidence\')"><h3>📊 Evidence Weighting</h3><span id="evidence-toggle" class="soc-card-toggle">▼</span></div>';
    html += '<div id="evidence-body" class="soc-card-body">';

    // VirusTotal
    html += '<div style="margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">';
    html += '<div style="font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">VirusTotal</div>';
    if (currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);
        html += '<div style="color: var(--text-secondary); font-size: 13px;">Detections: ' + vtMalicious + ' / ' + total + '</div>';
        html += '<div style="color: var(--text-muted); font-size: 12px;">Confidence: ' + (vtMalicious > 5 ? 'HIGH' : vtMalicious > 0 ? 'MEDIUM' : 'LOW') + '</div>';
    } else {
        html += '<div style="color: var(--text-muted); font-size: 13px;">No data available</div>';
    }
    html += '</div>';

    // AbuseIPDB
    html += '<div style="margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">';
    html += '<div style="font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">AbuseIPDB</div>';
    if (currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        html += '<div style="color: var(--text-secondary); font-size: 13px;">' + (abuseConfidence > 0 ? 'Abuse reports found' : 'No abuse reports') + '</div>';
        html += '<div style="color: var(--text-muted); font-size: 12px;">Confidence: ' + (abuseConfidence > 75 ? 'HIGH' : abuseConfidence > 0 ? 'MEDIUM' : 'LOW') + '</div>';
    } else {
        html += '<div style="color: var(--text-muted); font-size: 13px;">No data available</div>';
    }
    html += '</div>';

    // URLScan
    html += '<div style="margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">';
    html += '<div style="font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">URLScan</div>';
    if (currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        const overall = currentResults.urlscan.verdicts.overall;
        html += '<div style="color: var(--text-secondary); font-size: 13px;">' + (overall.malicious ? 'Malicious verdict' : 'No malicious verdict') + '</div>';
        html += '<div style="color: var(--text-muted); font-size: 12px;">Verdict: ' + (overall.malicious ? 'MALICIOUS' : (overall.score > 0 ? 'SUSPICIOUS' : 'CLEAN')) + '</div>';
    } else {
        html += '<div style="color: var(--text-muted); font-size: 13px;">No data available</div>';
    }
    html += '</div>';

    // WHOIS
    html += '<div>';
    html += '<div style="font-weight: 600; color: var(--text-primary); margin-bottom: 6px;">WHOIS</div>';
    if (currentResults.whois && currentResults.whois.creation_date) {
        html += '<div style="color: var(--text-secondary); font-size: 13px;">Domain Age: ' + domainAge + ' days</div>';
        let ageSignal = 'CLEAN';
        if (domainAge < 180) ageSignal = 'SUSPICIOUS';
        else if (domainAge < 365) ageSignal = 'NEUTRAL';
        html += '<div style="color: var(--text-muted); font-size: 12px;">Classification: ' + ageSignal + '</div>';
    } else {
        html += '<div style="color: var(--text-muted); font-size: 13px;">No data available</div>';
    }
    html += '</div>';

    html += '</div></div>';

    // Analyst Recommendation Section
    html += '<div class="soc-card"><div id="recommendation-header" class="soc-card-header expanded" onclick="toggleSocCardPanel(\'recommendation\')"><h3>💡 Analyst Recommendation</h3><span id="recommendation-toggle" class="soc-card-toggle">▼</span></div>';
    html += '<div id="recommendation-body" class="soc-card-body"><div class="recommendation-box ' + recommendationClass + '">';
    html += '<div class="recommendation-action" style="font-size: 16px; font-weight: 600;">' + recommendation + '</div>';
    html += '<div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">Investigation guidance - adapt based on context</div>';
    html += '</div></div></div>';

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
