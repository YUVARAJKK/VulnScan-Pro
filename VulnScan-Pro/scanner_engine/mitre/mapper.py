"""MITRE ATT&CK technique mapping for vulnerability findings."""

from __future__ import annotations

# MITRE ATT&CK technique database
MITRE_TECHNIQUES = {
    'T1190': {
        'id': 'T1190',
        'name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'description': 'Adversaries may attempt to exploit a public-facing application.',
    },
    'T1133': {
        'id': 'T1133',
        'name': 'External Remote Services',
        'tactic': 'Initial Access',
        'description': 'Adversaries may use valid accounts to log into externally accessible services.',
    },
    'T1040': {
        'id': 'T1040',
        'name': 'Network Sniffing',
        'tactic': 'Credential Access',
        'description': 'Adversaries may sniff network traffic to capture information.',
    },
    'T1059': {
        'id': 'T1059',
        'name': 'Command and Scripting Interpreter',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse command and script interpreters.',
    },
    'T1059.007': {
        'id': 'T1059.007',
        'name': 'JavaScript',
        'tactic': 'Execution',
        'description': 'Adversaries may abuse JavaScript for execution.',
    },
    'T1185': {
        'id': 'T1185',
        'name': 'Browser Session Hijacking',
        'tactic': 'Credential Access',
        'description': 'Adversaries may attempt to manipulate a users browser session.',
    },
    'T1592': {
        'id': 'T1592',
        'name': 'Gather Victim Host Information',
        'tactic': 'Reconnaissance',
        'description': 'Adversaries may gather information about the victim hosts.',
    },
    'T1046': {
        'id': 'T1046',
        'name': 'Network Service Discovery',
        'tactic': 'Discovery',
        'description': 'Adversaries may attempt to get a listing of services running on remote hosts.',
    },
    'T1083': {
        'id': 'T1083',
        'name': 'File and Directory Discovery',
        'tactic': 'Discovery',
        'description': 'Adversaries may enumerate files and directories to find specific information.',
    },
    'T1418': {
        'id': 'T1418',
        'name': 'Software Discovery',
        'tactic': 'Discovery',
        'description': 'Adversaries may attempt to get a listing of software installed on the system.',
    },
    'T1566': {
        'id': 'T1566',
        'name': 'Phishing',
        'tactic': 'Initial Access',
        'description': 'Adversaries may send phishing messages to gain access to victim systems.',
    },
    'T1565': {
        'id': 'T1565',
        'name': 'Data Manipulation',
        'tactic': 'Impact',
        'description': 'Adversaries may insert, delete, or manipulate data to manipulate outcomes.',
    },
}

# Keyword-to-technique mapping
KEYWORD_MAPPING = {
    'ssl': ['T1040'],
    'tls': ['T1040'],
    'certificate': ['T1040'],
    'hsts': ['T1040', 'T1190'],
    'header': ['T1190'],
    'csp': ['T1059.007'],
    'xss': ['T1059.007', 'T1185'],
    'sql injection': ['T1190', 'T1565'],
    'sqli': ['T1190', 'T1565'],
    'injection': ['T1190'],
    'cors': ['T1185'],
    'cookie': ['T1185', 'T1040'],
    'clickjacking': ['T1185'],
    'redirect': ['T1133'],
    'path traversal': ['T1083', 'T1190'],
    'lfi': ['T1083'],
    'directory': ['T1083'],
    'port': ['T1046', 'T1133'],
    'dns': ['T1592'],
    'spf': ['T1566'],
    'dmarc': ['T1566'],
    'server': ['T1592'],
    'powered-by': ['T1592'],
    'debug': ['T1592'],
    'trace': ['T1040'],
    'method': ['T1190'],
    'backup': ['T1083'],
    'robots.txt': ['T1592'],
}


def map_finding_to_mitre(finding: 'Finding') -> dict:
    """
    Map a vulnerability finding to MITRE ATT&CK techniques.
    Returns {primary: technique_dict, techniques: [technique_dict, ...]}.
    """
    title = (getattr(finding, 'title', '') or '').lower()
    description = (getattr(finding, 'description', '') or '').lower()
    combined = f'{title} {description}'

    # Check if finding already has MITRE info
    if finding.mitre_technique and finding.mitre_technique in MITRE_TECHNIQUES:
        primary = MITRE_TECHNIQUES[finding.mitre_technique]
        return {'primary': primary, 'techniques': [primary]}

    # Match keywords
    matched_ids = set()
    for keyword, technique_ids in KEYWORD_MAPPING.items():
        if keyword in combined:
            matched_ids.update(technique_ids)

    techniques = [MITRE_TECHNIQUES[tid] for tid in matched_ids if tid in MITRE_TECHNIQUES]
    primary = techniques[0] if techniques else {
        'id': 'N/A', 'name': 'No mapping available', 'tactic': 'N/A', 'description': ''
    }

    return {'primary': primary, 'techniques': techniques}
