// Threat Engine Module
// Threat scoring, intelligence aggregation, and analyst recommendation logic.

function computeThreatAssessment(currentResults) {
    let riskScore = 0;

    let vtMalicious = 0;
    let vtTotal = 0;
    if (currentResults && currentResults.vt && currentResults.vt.data && currentResults.vt.data.attributes) {
        const stats = currentResults.vt.data.attributes.last_analysis_stats;
        vtTotal = Object.values(stats).reduce((a, b) => a + b, 0);
        vtMalicious = (stats.malicious || 0) + (stats.suspicious || 0);
        if (vtMalicious > 0) riskScore += 40;
    }

    let abuseConfidence = 0;
    if (currentResults && currentResults.abuseipdb && currentResults.abuseipdb.abuseConfidenceScore !== undefined) {
        abuseConfidence = currentResults.abuseipdb.abuseConfidenceScore || 0;
        if (abuseConfidence > 25) riskScore += 25;
    }

    let urlscanScore = 0;
    if (currentResults && currentResults.urlscan && currentResults.urlscan.verdicts && currentResults.urlscan.verdicts.overall) {
        urlscanScore = currentResults.urlscan.verdicts.overall.score || 0;
        if (urlscanScore > 50) riskScore += 20;
    }

    let domainAge = null;
    if (currentResults && currentResults.whois && currentResults.whois.creation_date) {
        const creationDate = new Date(currentResults.whois.creation_date);
        const now = new Date();
        domainAge = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
        if (domainAge < 30) riskScore += 15;
    }

    const threatScore = Math.min(100, riskScore);

    let verdictCategory = 'LOW RISK';
    let verdictClass = 'low';
    if (threatScore > 50) {
        verdictCategory = 'HIGH RISK';
        verdictClass = 'high';
    } else if (threatScore > 20) {
        verdictCategory = 'SUSPICIOUS';
        verdictClass = 'suspicious';
    }

    let recommendation = 'ALLOW';
    let recommendationClass = 'allow';
    if (threatScore > 50) {
        recommendation = 'BLOCK';
        recommendationClass = 'block';
    } else if (threatScore >= 20) {
        recommendation = 'REVIEW';
        recommendationClass = 'review';
    }

    return {
        threatScore,
        verdictCategory,
        verdictClass,
        recommendation,
        recommendationClass,
        vtMalicious,
        vtTotal,
        abuseConfidence,
        urlscanScore,
        domainAge
    };
}
