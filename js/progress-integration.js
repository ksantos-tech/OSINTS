/**
 * INTEGRATION INSTRUCTIONS
 * Add this code to your scripts.js file to enable the single scan progress indicator
 */

// 1. Modify the startSingleScan function (around line 1665)
// Replace the existing function with this enhanced version:

async function startSingleScan(input) {
    const typeEl = document.getElementById('iocType');
    const typeSelect = typeEl ? typeEl.value : 'auto';
    const ioc = normaliseIOC(input.trim());
    const type = typeSelect === 'auto' ? detectIOCType(ioc) : typeSelect;
    
    _iocDefanged = false;
    const defangBtn = document.getElementById('defangBtn');
    if (defangBtn) defangBtn.textContent = '🛡️ Defang';
    
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

    // Initialize the progress indicator
    const keys = getKeys();
    if (typeof SingleScanProgress !== 'undefined') {
        SingleScanProgress.init(type, {
            vt: keys.vt,
            abuseipdb: keys.abuseipdb,
            whois: keys.whois,
            urlscan: keys.urlscan,
            threatfox: keys.abusech,
            urlhaus: keys.abusech,
            malwarebazaar: keys.abusech
        });
    }

    // Show loading states
    showLoading('vt');
    showLoading('abuseipdb');
    showLoading('whois');
    showLoading('urlscan');

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

// 2. Modify the scanViaWorker function (around line 3293)
// Add progress tracking calls throughout the function:

async function scanViaWorker(ioc, type) {
    try {
        console.log('Scanning via Worker API:', ioc, 'type:', type);
        
        const keys = getKeys();
        const url = WORKER_API_URL + '/scan?value=' + encodeURIComponent(ioc);
        console.log('Worker API URL:', url);
        
        // Mark all applicable sources as scanning
        if (typeof SingleScanProgress !== 'undefined') {
            if (keys.vt) SingleScanProgress.startSource('vt', 'Querying VirusTotal...');
            if (keys.abuseipdb && type === 'ip') SingleScanProgress.startSource('abuseipdb', 'Querying AbuseIPDB...');
            if (keys.whois && (type === 'domain' || type === 'url')) SingleScanProgress.startSource('whois', 'Querying WHOIS...');
            if (keys.urlscan && (type === 'url' || type === 'domain')) SingleScanProgress.startSource('urlscan', 'Submitting to URLScan...');
            if (keys.abusech) {
                SingleScanProgress.startSource('threatfox', 'Querying ThreatFox...');
                SingleScanProgress.startSource('urlhaus', 'Querying URLhaus...');
                if (type === 'hash') SingleScanProgress.startSource('malwarebazaar', 'Querying MalwareBazaar...');
            }
        }
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-VT-API-Key': keys.vt || '',
                'X-AbuseIPDB-Key': keys.abuseipdb || '',
                'X-Whois-Key': keys.whois || '',
                'X-URLScan-Key': keys.urlscan || '',
                'X-AbuseCH-Key': keys.abusech || ''
            }
        });
        
        if (!response.ok) {
            // Mark all as error if worker completely fails
            if (typeof SingleScanProgress !== 'undefined') {
                ['vt', 'abuseipdb', 'whois', 'urlscan', 'threatfox', 'urlhaus', 'malwarebazaar'].forEach(source => {
                    SingleScanProgress.errorSource(source, `Worker error: ${response.status}`);
                });
            }
            
            if (response.status === 404) throw new Error('IOC not found');
            if (response.status === 429) throw new Error('Rate limited - please wait and try again');
            throw new Error(`Worker API error: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Worker API response:', data);
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Process VirusTotal results
        if (data.virustotal) {
            if (data.virustotal.error) {
                const vtErrMsg = typeof data.virustotal.error === 'string'
                    ? data.virustotal.error
                    : (data.virustotal.error.message || JSON.stringify(data.virustotal.error));
                showError('vt', vtErrMsg);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.errorSource('vt', vtErrMsg);
                }
            } else {
                currentResults.vt = data.virustotal;
                renderVirusTotal(data.virustotal);
                
                // Check for threats in VT results
                const stats = data.virustotal.data?.attributes?.last_analysis_stats;
                const malicious = (stats?.malicious || 0) + (stats?.suspicious || 0);
                
                if (typeof SingleScanProgress !== 'undefined') {
                    if (malicious > 0) {
                        SingleScanProgress.threatFound('vt', `${malicious} detections found`);
                    } else {
                        SingleScanProgress.completeSource('vt', 'No threats detected');
                    }
                }
            }
        } else if (keys.vt) {
            if (typeof SingleScanProgress !== 'undefined') {
                SingleScanProgress.errorSource('vt', 'No data returned');
            }
        }
        
        // Process AbuseIPDB results
        if (data.abuseipdb) {
            const abuseData = data.abuseipdb.data || data.abuseipdb;
            if (abuseData.error) {
                const abuseErrMsg = typeof abuseData.error === 'string'
                    ? abuseData.error
                    : (abuseData.error.message || JSON.stringify(abuseData.error));
                showError('abuseipdb', abuseErrMsg);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.errorSource('abuseipdb', abuseErrMsg);
                }
            } else {
                currentResults.abuseipdb = abuseData;
                renderAbuseIPDB(abuseData);
                
                const confidence = abuseData.abuseConfidenceScore || 0;
                if (typeof SingleScanProgress !== 'undefined') {
                    if (confidence > 25) {
                        SingleScanProgress.threatFound('abuseipdb', `Abuse score: ${confidence}%`);
                    } else {
                        SingleScanProgress.completeSource('abuseipdb', `Abuse score: ${confidence}%`);
                    }
                }
            }
        } else if (keys.abuseipdb && type === 'ip') {
            if (typeof SingleScanProgress !== 'undefined') {
                SingleScanProgress.errorSource('abuseipdb', 'No data returned');
            }
        }
        
        // Process WHOIS results
        if (data.whois) {
            if (data.whois.error) {
                const whoisErrMsg = typeof data.whois.error === 'string'
                    ? data.whois.error
                    : (data.whois.error.message || 'No WHOIS data available');
                showError('whois', whoisErrMsg);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.errorSource('whois', whoisErrMsg);
                }
            } else {
                const whoisData = data.whois.result || data.whois;
                currentResults.whois = whoisData;
                renderWhois(whoisData);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.completeSource('whois', 'WHOIS data retrieved');
                }
            }
        } else if (keys.whois && (type === 'domain' || type === 'url')) {
            if (typeof SingleScanProgress !== 'undefined') {
                SingleScanProgress.errorSource('whois', 'No data returned');
            }
        }
        
        // Process URLScan results
        if (data.urlscan) {
            if (data.urlscan.error) {
                showError('urlscan', data.urlscan.error);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.errorSource('urlscan', data.urlscan.error);
                }
            } else if (data.urlscan.status === 'pending' && data.urlscan.uuid) {
                // URLScan is pending - update progress and poll
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.updateSource('urlscan', 'scanning', 'Scan in progress...');
                }
                // ... rest of URLScan polling code ...
                // When complete, call:
                // SingleScanProgress.completeSource('urlscan', 'Scan complete');
                // or SingleScanProgress.threatFound('urlscan', 'Threats detected');
            } else {
                currentResults.urlscan = data.urlscan;
                renderURLScan(data.urlscan);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.completeSource('urlscan', 'Scan complete');
                }
            }
        }
        
        // Process ThreatFox results
        if (data.threatfox) {
            if (data.threatfox.found) {
                currentResults.threatfox = data.threatfox;
                if (typeof renderThreatFox === 'function') renderThreatFox(data.threatfox);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.threatFound('threatfox', 'IOC found in ThreatFox');
                }
            } else {
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.completeSource('threatfox', 'Not found in ThreatFox');
                }
            }
        }
        
        // Process URLhaus results
        if (data.urlhaus) {
            if (data.urlhaus.found) {
                currentResults.urlhaus = data.urlhaus;
                if (typeof renderURLhaus === 'function') renderURLhaus(data.urlhaus);
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.threatFound('urlhaus', 'URL listed in URLhaus');
                }
            } else {
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.completeSource('urlhaus', 'Not found in URLhaus');
                }
            }
        }
        
        // Process MalwareBazaar results
        if (data.malwarebazaar) {
            if (data.malwarebazaar.found) {
                currentResults.malwarebazaar = data.malwarebazaar;
                if (typeof renderMalwareBazaar === 'function') renderMalwareBazaar(data.malwarebazaar);
                if (typeof SingleScanProgress !== 'undefined') {
                    const family = data.malwarebazaar.malware_family || 'Malware';
                    SingleScanProgress.threatFound('malwarebazaar', `${family} detected`);
                }
            } else {
                if (typeof SingleScanProgress !== 'undefined') {
                    SingleScanProgress.completeSource('malwarebazaar', 'Not found in MalwareBazaar');
                }
            }
        }
        
        // Update SOC dashboard and combined view
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
        
    } catch (error) {
        console.error('scanViaWorker error:', error);
        showToast('Scan failed: ' + error.message, 'error');
        
        // Mark all sources as error
        if (typeof SingleScanProgress !== 'undefined') {
            ['vt', 'abuseipdb', 'whois', 'urlscan', 'threatfox', 'urlhaus', 'malwarebazaar'].forEach(source => {
                SingleScanProgress.errorSource(source, error.message);
            });
        }
        
        // Fall back to legacy scan method
        if (typeof startSingleScanLegacy === 'function') {
            console.log('Falling back to legacy scan...');
            await startSingleScanLegacy(ioc, type);
        }
    }
}
