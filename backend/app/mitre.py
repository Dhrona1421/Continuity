"""Curated ATT&CK metadata used by bundled detections.

This is intentionally a documented subset, not a claim to mirror the complete ATT&CK corpus.
"""

MITRE_TECHNIQUES: dict[str, dict[str, object]] = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1189": {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactics": ["Initial Access"],
        "url": "https://attack.mitre.org/techniques/T1189/",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1110.004": {
        "id": "T1110.004",
        "name": "Credential Stuffing",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1110/004/",
    },
    "T1539": {
        "id": "T1539",
        "name": "Steal Web Session Cookie",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1539/",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1552": {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1499": {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactics": ["Impact"],
        "url": "https://attack.mitre.org/techniques/T1499/",
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Unix Shell",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
}


def technique_view(technique_id: str) -> dict[str, object]:
    return MITRE_TECHNIQUES.get(
        technique_id,
        {
            "id": technique_id,
            "name": "Unresolved bundled metadata",
            "tactics": [],
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        },
    )
