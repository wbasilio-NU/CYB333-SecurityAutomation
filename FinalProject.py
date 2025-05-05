# The prupose of this Python script is to audit system configurations against an PCI-DSS security benchmark and report compliance
import json
import subprocess
import os

pci_dss_requirements = {
    "tls_version_required": "1.2",
    "min_password_length": 12,
    "file_integrity_check": True,
    "mfa_enabled": True,
    "firewall_default_policy": "DROP",
    "ssh_permit_root_login": "no",
    "disk_encryption_required": True,
    "log_rotation_enabled": True
}
# PCI-DSS v4.0 requirements for system configurations
# This section defines the PCI-DSS v4.0 requirements for system configurations

def is_windows():
    """Checks if the operating system is Windows"""
    return os.name == 'nt'
def is_linux():
    """Checks if the operating system is Linux"""
    return os.name == 'posix'

def check_tls_version():
    """Checks if TLS version 1.2 or higher is enabled"""
    if is_windows():
        result = subprocess.run(["powershell", "-Command", "Get-TlsCipherSuite"], capture_output=True, text=True)
        if pci_dss_requirements["tls_version_required"] in result.stdout:
            return {"TLS Version": "Compliant"}
        return {"TLS Version": "Non-Compliant"}
    # Check TLS version using OpenSSL on Windows
    if is_linux():
        result = subprocess.run(["openssl", "s_client", "-connect", "localhost:443"], capture_output=True, text=True)
        if pci_dss_requirements["tls_version_required"] in result.stdout:
            return {"TLS Version": "Compliant"}
        return {"TLS Version": "Non-Compliant"}
    else:
        return {"TLS Version": "Unknown OS or Unsupported"}
    # Check TLS version using OpenSSL on Linux
    
def check_password_policy():
    """Check password policy settings"""
    if is_windows():
        result = subprocess.run(["net", "accounts"], capture_output=True, text=True)
        if f"Minimum password length is {pci_dss_requirements['min_password_length']}" in result.stdout:
            return {"Password Policy": "Compliant"}
        return {"Password Policy": "Non-Compliant"}
    # Checks password policy using net command on Windows
    if is_linux():
        # Check password policy using PAM configuration
        with open("/etc/pam.d/common-password", "r") as file:
            config = file.readlines()
        if any(f"minlen={pci_dss_requirements['min_password_length']}" in line for line in config):
            return {"Password Policy": "Compliant"}
        return {"Password Policy": "Non-Compliant"}
    else:
        return {"Password Policy": "Unknown OS or Unsupported"}

def check_file_integrity():
    """Check file integrity settings"""
    if is_windows():
        # Windows does not have a direct command for file integrity status
        return {"File Integrity": "Not Applicable"}
    if is_linux():
        for command in [["aide", "--init"], ["aide", "--check"]]:
            results = subprocess.run(command, capture_output=True, text=True)
        # Check for compliance messages
        if pci_dss_requirements["file_integrity_check"] in results.stdout or "AIDE database is up to date" in results.stdout:
            return {"File Integrity": "Compliant"}
        return {"File Integrity": "Non-Compliant"}
    else:
        return {"File Integrity": "Unknown OS or Unsupported"}
    
def check_mfa():
    """Check if MFA is enabled"""
    if is_windows():
        # Windows does not have a direct command for MFA status
        return {"MFA": "Not Applicable"}
    if is_linux():
        # Check MFA status using PAM configuration
        with open("/etc/pam.d/common-auth", "r") as file:
            config = file.readlines()
        if any("pam_google_authenticator.so" in line for line in config):
            return {"MFA": "Compliant"}
        return {"MFA": "Non-Compliant"}
    else:
        return {"MFA": "Unknown OS or Unsupported"}    

def check_firewall():
    """Check firewall settings"""
    if is_windows():
        # Check firewall status using netsh on Windows
        result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True)
        if pci_dss_requirements["firewall_default_policy"] in result.stdout:
            return {"Firewall": "Compliant"}
        return {"Firewall": "Non-Compliant"}
    if is_linux():
        # Check firewall status using iptables on Linux
        result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
        if pci_dss_requirements["firewall_default_policy"] in result.stdout:
            return {"Firewall": "Compliant"}
        return {"Firewall": "Non-Compliant"}
    else:
        return {"Firewall": "Unknown OS or Unsupported"}
    
def check_ssh_security():
    """Check SSH security settings"""
    if is_windows():
        # Windows does not have SSH by default, so we skip this check
        return {"SSH Security": "Not Applicable"}
    if is_linux():
        # Check SSH configuration on Linux
        with open("/etc/ssh/sshd_config", "r") as file:
            config = file.readlines()
        if any(f"PermitRootLogin {pci_dss_requirements['ssh_permit_root_login']}" in line for line in config):
            return {"SSH Security": "Compliant"}
        return {"SSH Security": "Non-Compliant"}
    else:
        return {"SSH Security": "Unknown OS or Unsupported"}    

def check_disk_encryption():
    """Check disk encryption status"""
    if is_windows():
        # Windows does not have a direct command for disk encryption status
        return {"Disk Encryption": "Not Applicable"}
    if is_linux():
        # Check disk encryption using lsblk on Linux
        result = subprocess.run(["lsblk", "-o", "NAME,MOUNTPOINT,TYPE"], capture_output=True, text=True)
        if "crypt" in result.stdout:
            return {"Disk Encryption": "Compliant"}
        return {"Disk Encryption": "Non-Compliant"}
    else:
        return {"Disk Encryption": "Unknown OS or Unsupported"}

def check_logging():
    """Check if log rotation is enabled"""
    if is_windows():
        # Windows does not have a direct command for log rotation status
        return {"Logging": "Not Applicable"}
    if is_linux():
        # Check log rotation status using logrotate on Linux
        result = subprocess.run(["logrotate", "--version"], capture_output=True, text=True)
        if pci_dss_requirements["log_rotation_enabled"] in result.stdout:
            return {"Logging": "Compliant"}
        return {"Logging": "Non-Compliant"}
    else:
        return {"Logging": "Unknown OS or Unsupported"}

def create_ticket_in_ats(results):
    """Create a ticket in an ATS system if non-compliance is detected"""
    # Filter non-compliant items
    non_compliant_items = {key: value for key, value in results.items() if "Non-Compliant" in value.values()}
    
    if non_compliant_items:
        # Simulate ticket creation (replace this with actual ATS API integration)
        ticket_details = {
            "title": "PCI-DSS Non-Compliance Detected",
            "description": f"The following items are non-compliant:\n{json.dumps(non_compliant_items, indent=4)}",
            "priority": "High",
            "status": "Open"
        }
        # Save ticket details to a file (or replace with an API call to ATS)
        with open("ats_ticket.json", "w") as file:
            json.dump(ticket_details, file, indent=4)
        
        print("Non-compliance detected! A ticket has been created in the ATS system.")
        print(json.dumps(ticket_details, indent=4))
    else:
        print("All checks are compliant. No ticket created.")

if __name__ == "__main__":
    # Run compliance checks
    results = {
        "TLS Version": check_tls_version(),
        "Password Policy": check_password_policy(),
        "File Integrity": check_file_integrity(),
        "MFA": check_mfa(),
        "Firewall": check_firewall(),
        "SSH Security": check_ssh_security(),
        "Disk Encryption": check_disk_encryption(),
        "Logging": check_logging()
    }
    
    # Saves compliance report
    with open("pci_dss_compliance_report.json", "w") as file:
        json.dump(results, file, indent=4)

    print("PCI-DSS v4.0 Compliance Audit Completed ✅")
    print(json.dumps(results, indent=4))

    # Creates a ticket in ATS if non-compliance is detected
    create_ticket_in_ats(results)
