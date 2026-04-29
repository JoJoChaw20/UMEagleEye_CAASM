# Playbook: Unauthorized Port Open (SSH/22)
**Scenario**: Drift detection identifies that port 22 (SSH) has been opened without authorization.
**Tactic**: Initial Access / Persistence

## Remediation Steps
1. **Immediate Containment**:
   Restrict access to the port immediately using the system firewall.
   Command: `sudo ufw deny 22/tcp` or `sudo iptables -A INPUT -p tcp --dport 22 -j DROP`
   
2. **Investigation**:
   Check who is currently logged in: `who` or `w`.
   Review authentication logs: `sudo tail -f /var/log/auth.log`.
   
3. **Recovery**:
   Disable SSH if not needed: `sudo systemctl stop ssh` and `sudo systemctl disable ssh`.
   If needed, change to a non-standard port and enforce SSH keys.
