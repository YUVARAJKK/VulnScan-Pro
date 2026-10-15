/**
 * Unified risk scoring model — Node.js mirror of the CANONICAL model computed
 * by the Python scanner engine (`scanner_engine/analysis/severity.py`).
 *
 * Rule: change the Python engine first, then mirror it here and in the
 * frontend report view (`ScanReportView.computeRisk`). The same finding set
 * must produce the same score, grade and rating on every surface.
 *
 * Model (v2 — severity-band):
 *   critical=70, high=50, medium=30, low=10, info=0 risk points per finding
 *   risk_score  = min(100, sum of points)
 *   health_score = 100 - risk_score
 *   grade: A+ >=95, A >=85, B >=75, C >=60, D >=40, else F
 *   rating: CRITICAL >=70, HIGH >=50, MODERATE >=30, LOW >=10, SECURE
 */
function calculateRiskScore(vulnerabilities) {
    const weights = { critical: 70, high: 50, medium: 30, low: 10, info: 0 };
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    let points = 0;
    for (const v of vulnerabilities || []) {
        const sev = v && v.severity;
        if (sev && sev in severityCounts) severityCounts[sev]++;
        points += weights[sev] || 0;
    }

    const riskScore = Math.min(100, points);
    const healthScore = Math.max(0, 100 - riskScore);
    const grade = healthScore >= 95 ? 'A+'
        : healthScore >= 85 ? 'A'
        : healthScore >= 75 ? 'B'
        : healthScore >= 60 ? 'C'
        : healthScore >= 40 ? 'D'
        : 'F';
    const rating = threatLevelForRisk(riskScore);

    return { riskScore, healthScore, grade, rating, severityCounts };
}

/**
 * Map a risk score to a threat-level label.
 */
function threatLevelForRisk(riskScore) {
    if (riskScore >= 70) return 'CRITICAL';
    if (riskScore >= 50) return 'HIGH';
    if (riskScore >= 30) return 'MODERATE';
    if (riskScore >= 10) return 'LOW';
    return 'SECURE';
}

module.exports = { calculateRiskScore, threatLevelForRisk };
