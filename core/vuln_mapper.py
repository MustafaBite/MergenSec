# core/vuln_mapper.py

# Port → servis eşleştirme
def get_service(port):
    if port == 80:
        return "http"
    elif port == 22:
        return "ssh"
    elif port == 21:
        return "ftp"
    else:
        return None


# Basit CVE veritabanı
CVE_DB = {
    "http": {
        "cve": "CVE-2021-41773",
        "description": "Apache Path Traversal",
        "cvss": 7.5
    },
    "ssh": {
        "cve": "CVE-2018-15473",
        "description": "OpenSSH User Enumeration",
        "cvss": 5.3
    },
    "ftp": {
        "cve": "CVE-2015-3306",
        "description": "ProFTPd Remote Code Execution",
        "cvss": 9.8
    }
}


# CVSS → risk seviyesi
def classify_risk(cvss):
    if cvss >= 7:
        return "HIGH"
    elif cvss >= 4:
        return "MEDIUM"
    else:
        return "LOW"


# Ana mapping fonksiyonu
def map_vulnerability(port):
    service = get_service(port)

    if service in CVE_DB:
        data = CVE_DB[service]
        risk = classify_risk(data["cvss"])

        return {
            "port": port,
            "service": service,
            "cve": data["cve"],
            "description": data["description"],
            "cvss": data["cvss"],
            "risk": risk
        }

    return None