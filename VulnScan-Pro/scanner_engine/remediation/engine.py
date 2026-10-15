"""Vulnerability-specific remediation engine."""

from __future__ import annotations

# Remediation templates keyed by detector name and finding patterns
REMEDIATION_DB = {
    'security_headers': {
        'default': 'Configure the web server to include the missing security header.',
        'hsts': 'Add Strict-Transport-Security header with max-age=31536000; includeSubDomains; preload.',
        'csp': "Implement Content-Security-Policy with strict directives. Use nonces for inline scripts: script-src 'nonce-{random}'.",
        'x_frame_options': 'Add X-Frame-Options: DENY header or use CSP frame-ancestors directive.',
        'x_content_type_options': 'Add X-Content-Type-Options: nosniff header.',
        'referrer_policy': 'Add Referrer-Policy: strict-origin-when-cross-origin header.',
        'permissions_policy': 'Add Permissions-Policy header to restrict browser feature access.',
    },
    'cookie_security': {
        'default': 'Configure cookies with HttpOnly, Secure, and SameSite attributes.',
        'httponly': 'Set HttpOnly flag on all session cookies to prevent XSS-based session theft.',
        'secure': 'Set Secure flag on all cookies to ensure they are only sent over HTTPS.',
        'samesite': 'Set SameSite=Strict or SameSite=Lax on cookies to prevent CSRF attacks.',
    },
    'cors': {
        'default': 'Implement a strict CORS policy with explicit allowed origins.',
        'wildcard': 'Replace Access-Control-Allow-Origin: * with specific trusted origins.',
        'reflection': 'Never reflect the Origin header without validation. Use an allowlist of trusted domains.',
        'credentials': 'Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins.',
    },
    'http_methods': {
        'default': 'Restrict dangerous HTTP methods in web server configuration.',
        'trace': 'Disable TRACE method in web server configuration to prevent XST attacks.',
    },
    'information_disclosure': {
        'default': 'Remove debug information and error details from production responses.',
        'stack_trace': 'Configure custom error pages that do not expose stack traces or internal details.',
        'server_version': 'Suppress server version information (e.g., Nginx: server_tokens off).',
        'sensitive_path': 'Block access to sensitive paths via web server configuration or WAF rules.',
    },
    'directory_exposure': {
        'default': 'Disable directory listings and remove backup files from the web root.',
        'listing': 'Disable directory listing in web server configuration (e.g., Apache: Options -Indexes).',
        'backup': 'Remove backup files from the web root and block access via WAF rules.',
    },
    'xss': {
        'default': 'Sanitize all user input and encode output. Implement CSP with nonces.',
        'reflected': 'Use context-aware output encoding. Encode user input before inserting into HTML.',
        'attribute': 'Validate and sanitize input used in HTML attributes. Use CSP to prevent inline handlers.',
    },
    'sqli': {
        'default': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL.',
        'error_based': 'Use parameterized queries and disable detailed SQL error messages in production.',
        'blind': 'Use parameterized queries. Implement time-based or boolean-based detection avoidance.',
    },
    'open_redirect': {
        'default': 'Validate redirect targets against an allowlist of trusted domains.',
    },
    'path_traversal': {
        'default': 'Validate and sanitize file paths. Use a chroot jail or sandbox. Never use user input directly in file operations.',
        'lfi': 'Validate file paths against a whitelist. Use basename() to strip directory components.',
    },
}


def generate_remediation(finding: 'Finding') -> str:
    """
    Generate remediation guidance for a vulnerability finding.
    Uses the detector name and finding title to select the best remediation.
    """
    detector = finding.detected_by or ''
    title = (finding.title or '').lower()

    detector_remediations = REMEDIATION_DB.get(detector, {})
    if not detector_remediations:
        return finding.remediation or 'Consult security best practices for remediation guidance.'

    # Try to match specific pattern
    for pattern, remediation in detector_remediations.items():
        if pattern != 'default' and pattern in title:
            return remediation

    # Fall back to default for this detector
    return detector_remediations.get('default', finding.remediation or 'Review and remediate according to security best practices.')
