# UMEagleEye - System Implementation & RBAC Documentation

This document summarizes the current implementation of the UMEagleEye authentication and authorization system, the design justifications, and the roadmap for future security improvements based on industry standards.

---

## 1. Current Implementation Logic

### Authentication & JWT
The system uses a stateless **JSON Web Token (JWT)** architecture for authentication.
* **Password Hashing:** Passwords are hashed using `bcrypt` before storage.
* **Token Generation:** Upon successful login, the backend generates a JWT signed with a server-side `JWT_SECRET_KEY`.
* **Claims:** The token includes the `user_id`, `username`, and the user's `role` (e.g., `ops_lead`, `security_engineer`).

### Multi-Factor Authentication (MFA)
A Time-based One-Time Password (TOTP) mechanism is implemented to enhance account security.
* **Algorithm:** Uses `pyotp` (RFC 6238).
* **Setup:** Users generate a secret key and a QR code via the `/auth/mfa/setup` endpoint.
* **Enforcement:** Once MFA is enabled (`mfa_enabled: true`), the standard login endpoint redirects users to a verification step.

### MFA Verification Workflow
When MFA is enabled, the authentication process becomes a two-step flow:
1. **Step 1 (`/login`):** Validates username/password. If successful, returns `mfa_required: true` and an empty `access_token`.
2. **Step 2 (`/mfa/verify`):** Requires the user's `username` and the 6-digit TOTP code. If verified, returns the final JWT `access_token`.

### Role-Based Access Control (RBAC)
Access control is enforced at the API layer using FastAPI dependencies.
* **Role Verification:** The `require_roles` dependency extracts the role from the signed JWT token.
* **Tamper-Proofing:** Because the token is cryptographically signed, users cannot modify their role (e.g., from `auditor` to `ops_lead`) without invalidating the signature, which the server checks on every request.

### Hybrid Asset Discovery (Sprint 1)
The core of the CAASM platform is the continuous discovery of cyber assets across the network.
* **Active Scanning (FR-01-01):** Utilizes **Nmap** (and Masscan for high-speed sweeps) to probe subnets for live hosts. It captures hostnames, IP addresses, open ports, and service versions (`-sV`) along with OS fingerprinting (`-O`).
* **Passive Discovery (FR-01-02):** A background **Scapy** listener sniffs network traffic to identify devices based on ARP requests and DHCP broadcasts without active probing.
* **Persistence & Schema:** Discovered data is normalized and stored in a PostgreSQL `Asset` table. The schema uses `INET` and `MACADDR` types for network integrity and `JSONB` for flexible OS/Port metadata.
* **Asynchronous Execution:** Discovery tasks are decoupled from the API using **Celery**. This allows for long-running scans to occur in the background without blocking the user interface.

---

## 2. Design Justifications

### Backend-Only Registration
**Justification:** Security & Enterprise Control.
* **Surface Area Reduction:** Omitting a public registration page on the frontend prevents arbitrary users from creating accounts.
* **Provisioning Model:** For an SME-focused security tool, accounts should be provisioned by an administrator rather than being open to the public. This ensures that only authorized personnel can access sensitive vulnerability data.

### Swagger vs. Frontend Authorization
**Justification:** Developer Testing vs. End-User Experience.
* **Swagger UI:** A developer tool that requires manual token management (copy-paste) because it is a stateless API explorer.
* **Frontend App:** The production interface handles authorization automatically. It captures the token after login and attaches it to all background API calls without the user ever seeing the "Value" box or token strings.

### Agentless Hybrid Discovery
**Justification:** Zero-Trust Visibility for SMEs.
* **Low Friction:** SMEs typically lack the infrastructure to deploy agents (like CrowdStrike) on every machine. Agentless discovery provides immediate value with zero deployment effort.
* **Comprehensive Coverage:** Passive listening catches transient devices (like mobile phones or rogue laptops) that might be offline during a scheduled active scan.


---

## 3. Future Improvements (Industry Standards)

Based on current CAASM industry leaders (Axonius, JupiterOne) and cybersecurity best practices, the following improvements are recommended:

### Short-Term (UX & Security)
* **MFA Recovery Codes:** Implement backup/recovery codes for users who lose access to their TOTP device.
* **API-Based Cloud Connectors:** Integrate with AWS/Azure APIs to discover cloud-native assets (EC2, RDS) that are not discoverable via standard network probing.

* **Frontend MFA UI:** Build a dedicated UI in the React application for QR code enrollment and TOTP code entry to improve the user experience.
* **Advanced Entity Resolution:** Implement a deduplication algorithm to merge asset records when a device changes its IP address but retains its MAC address.

* **Session Management:** Implement token revocation (blacklisting) or "Refresh Tokens" to allow for longer sessions while maintaining the ability to kick users out if needed.

### Long-Term (Enterprise Standards)
* **SSO Integration:** Implement OIDC/SAML support to allow SMEs to log in using their existing Microsoft 365 or Google Workspace accounts.
* **Just-In-Time (JIT) Provisioning:** Automatically create accounts for users when they first log in via SSO, based on their corporate group memberships.
* **Audit Logging for Roles:** Implement detailed auditing of every action taken by an `ops_lead` vs. an `auditor` to meet regulatory compliance requirements (e.g., ISO 27001).

---

> [!IMPORTANT]
> **Security Reminder:** The `JWT_SECRET_KEY` must never be hardcoded in production. It should always be managed via environmental variables or a secure vault.
