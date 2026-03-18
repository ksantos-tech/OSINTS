/**
 * Single Scan Progress Indicator Module
 * Tracks and displays progress of threat intelligence source queries during a single IOC scan
 */

const SingleScanProgress = (() => {
    // Configuration for threat intelligence sources
    const SOURCES = [
        { id: 'vt', name: 'VirusTotal', icon: 'VT', requiresKey: true },
        { id: 'abuseipdb', name: 'AbuseIPDB', icon: 'AB', requiresKey: true, ipOnly: true },
        { id: 'whois', name: 'WHOIS', icon: 'WH', requiresKey: true, domainOnly: true },
        { id: 'urlscan', name: 'URLScan', icon: 'US', requiresKey: true, urlDomainOnly: true },
        { id: 'threatfox', name: 'ThreatFox', icon: 'TF', requiresKey: true },
        { id: 'urlhaus', name: 'URLhaus', icon: 'UH', requiresKey: true },
        { id: 'malwarebazaar', name: 'MalwareBazaar', icon: 'MB', requiresKey: true, hashOnly: true }
    ];

    let state = {
        active: false,
        total: 0,
        completed: 0,
        sources: {}
    };

    /**
     * Initialize the progress indicator
     * @param {string} iocType - Type of IOC being scanned (ip, domain, url, hash)
     * @param {object} apiKeys - Object containing API keys for each service
     */
    function init(iocType, apiKeys = {}) {
        const container = document.getElementById('singleScanProgress');
        const grid = document.getElementById('progressSourcesGrid');
        
        if (!container || !grid) {
            console.warn('Progress indicator containers not found');
            return;
        }

        // Reset state
        state = {
            active: true,
            total: 0,
            completed: 0,
            sources: {}
        };

        // Filter and prepare sources based on IOC type and available API keys
        const applicableSources = SOURCES.filter(source => {
            // Skip if API key not configured
            if (source.requiresKey && !apiKeys[source.id]) {
                return false;
            }

            // Check IOC type compatibility
            if (source.ipOnly && iocType !== 'ip') return false;
            if (source.domainOnly && iocType !== 'domain' && iocType !== 'url') return false;
            if (source.urlDomainOnly && iocType !== 'url' && iocType !== 'domain') return false;
            if (source.hashOnly && iocType !== 'hash') return false;

            return true;
        });

        state.total = applicableSources.length;

        // Build source cards
        grid.innerHTML = applicableSources.map((source, index) => {
            state.sources[source.id] = {
                status: 'pending',
                message: 'Waiting...'
            };

            return createSourceCard(source, index);
        }).join('');

        // Update counter
        updateCounter();

        // Show the progress indicator
        container.style.display = 'block';
    }

    /**
     * Create HTML for a source card
     */
    function createSourceCard(source, index) {
        return `
            <div class="progress-source-card pending" id="progress-${source.id}" style="animation-delay: ${index * 0.05}s">
                <div class="progress-source-icon">${source.icon}</div>
                <div class="progress-source-info">
                    <div class="progress-source-name">${source.name}</div>
                    <div class="progress-source-status">Waiting...</div>
                </div>
                <div class="progress-source-badge">Pending</div>
            </div>
        `;
    }

    /**
     * Update a source's status
     * @param {string} sourceId - ID of the source (vt, abuseipdb, etc.)
     * @param {string} status - Status: 'scanning', 'success', 'threat', 'error', 'skipped'
     * @param {string} message - Status message to display
     */
    function updateSource(sourceId, status, message = '') {
        if (!state.active || !state.sources[sourceId]) return;

        const card = document.getElementById(`progress-${sourceId}`);
        if (!card) return;

        const statusEl = card.querySelector('.progress-source-status');
        const badge = card.querySelector('.progress-source-badge');

        // Remove all status classes
        card.className = 'progress-source-card';
        
        // Add new status
        card.classList.add(status);

        // Update message
        if (statusEl) {
            statusEl.textContent = message || getDefaultMessage(status);
        }

        // Update badge
        if (badge) {
            badge.textContent = getBadgeText(status);
        }

        // Update state
        const previousStatus = state.sources[sourceId].status;
        state.sources[sourceId].status = status;
        state.sources[sourceId].message = message;

        // Increment completed counter if transitioning to a final state
        if (previousStatus === 'scanning' || previousStatus === 'pending') {
            if (status === 'success' || status === 'threat' || status === 'error' || status === 'skipped') {
                state.completed++;
                updateCounter();
            }
        }
    }

    /**
     * Update the progress counter
     */
    function updateCounter() {
        const completedEl = document.getElementById('progressCompleted');
        const totalEl = document.getElementById('progressTotal');

        if (completedEl) completedEl.textContent = state.completed;
        if (totalEl) totalEl.textContent = state.total;

        // Auto-hide after all complete (with delay for user to see final state)
        if (state.completed === state.total && state.total > 0) {
            setTimeout(hide, 3000);
        }
    }

    /**
     * Get default message for a status
     */
    function getDefaultMessage(status) {
        const messages = {
            pending: 'Waiting...',
            scanning: 'Querying API...',
            success: 'No threats detected',
            threat: 'Threat detected',
            error: 'Query failed',
            skipped: 'Skipped'
        };
        return messages[status] || '';
    }

    /**
     * Get badge text for a status
     */
    function getBadgeText(status) {
        const badges = {
            pending: 'Pending',
            scanning: 'Scanning',
            success: 'Clean',
            threat: 'Threat',
            error: 'Error',
            skipped: 'Skipped'
        };
        return badges[status] || 'Unknown';
    }

    /**
     * Mark a source as scanning
     */
    function startSource(sourceId, message = 'Querying API...') {
        updateSource(sourceId, 'scanning', message);
    }

    /**
     * Mark a source as successfully completed with no threats
     */
    function completeSource(sourceId, message = 'No threats detected') {
        updateSource(sourceId, 'success', message);
    }

    /**
     * Mark a source as completed with threats found
     */
    function threatFound(sourceId, message = 'Threat detected') {
        updateSource(sourceId, 'threat', message);
    }

    /**
     * Mark a source as failed/error
     */
    function errorSource(sourceId, message = 'Query failed') {
        updateSource(sourceId, 'error', message);
    }

    /**
     * Mark a source as skipped (e.g., incompatible IOC type)
     */
    function skipSource(sourceId, message = 'Skipped') {
        updateSource(sourceId, 'skipped', message);
    }

    /**
     * Hide the progress indicator
     */
    function hide() {
        const container = document.getElementById('singleScanProgress');
        if (container) {
            container.style.display = 'none';
        }
        state.active = false;
    }

    /**
     * Reset and hide the progress indicator
     */
    function reset() {
        hide();
        state = {
            active: false,
            total: 0,
            completed: 0,
            sources: {}
        };
    }

    // Public API
    return {
        init,
        startSource,
        completeSource,
        threatFound,
        errorSource,
        skipSource,
        updateSource,
        hide,
        reset,
        getState: () => ({ ...state })
    };
})();

// Make it globally available
window.SingleScanProgress = SingleScanProgress;
