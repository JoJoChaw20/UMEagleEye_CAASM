# Playbook: Vulnerability Remediation (CVE)
**Scenario**: High or Critical vulnerability detected in installed packages.
**Tactic**: Initial Access / Execution

## Remediation Steps
1. **Identify Package**:
   Locate the vulnerable package and version from the UMEagleEye Vulnerabilities dashboard.
   
2. **Update Package**:
   Use the system package manager to update to the patched version.
   Debian/Ubuntu: `sudo apt-get update && sudo apt-get install --only-upgrade <package_name>`
   RHEL/CentOS: `sudo yum update <package_name>`
   
3. **Verify Patch**:
   Re-run the SBOM scan in UMEagleEye to confirm the vulnerability is resolved.
   
4. **Alternative (Virtual Patching)**:
   If a patch is not available, implement a WAF rule or firewall restriction to block the exploit path.
