# 🛡️ SOC Investigation — Suspicious Login Activity
**Case Study: Unauthorized Access Attempt in Microsoft 365**

---

## 📘 Scenario Overview
A small business uses Microsoft 365 for identity and email. The SOC receives an alert indicating **multiple failed login attempts** followed by a **successful login from an unusual location**. The user confirms they were **asleep** at the time of the successful authentication.

### **User & Alert Details**

| Field                   | Details                          |
|-------------------------|----------------------------------|
| **User**                | jane.harris@brisbanetech.com.au  |
| **Normal Location**     | Brisbane, QLD                    |
| **Suspicious Location** | Singapore                        |
| **Time of Alert**       | 02:14 AEST                       |
| **Alert Source**        | Azure AD Identity Protection     |
| **Authentication Method** | Password only (no MFA)         |

---

## 🔍 Initial Log Review (Azure Sentinel)

### **KQL Query Used**
```kql
SigninLogs
| where UserPrincipalName == "jane.harris@brisbanetech.com.au"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
Sample Output
TimeGenerated (AEST)	UserPrincipalName	IPAddress	Location	ResultType	ResultDescription
2024‑11‑12 02:06:14.221	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
2024‑11‑12 02:06:47.902	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
2024‑11‑12 02:07:12.443	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
2024‑11‑12 02:07:45.118	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
🧠 Analyst Assessment
Indicators of Compromise
Multiple failed attempts from a foreign IP

Successful login shortly after repeated failures

User confirms no activity at that time

No MFA enabled (high‑risk configuration)

Likely Attack Pattern
This behaviour aligns with:

Password spraying

Credential stuffing

Compromised credentials via phishing or breach reuse

🚨 Recommended Immediate Actions
1. Containment
Force password reset for the affected user

Revoke active sessions in Azure AD

Block the suspicious IP address

Enable MFA immediately

2. Investigation
Review sign‑in logs for lateral movement

Check mailbox rules for forwarding or deletion

Review audit logs for privilege escalation

Search for additional failed attempts across tenant

3. Recovery
Confirm user identity and secure account

Validate no unauthorized changes were made

Re‑enable access with MFA enforced

4. Lessons Learned
Enforce MFA tenant‑wide

Implement conditional access policies

Enable risk‑based sign‑in alerts

Educate users on password hygiene

📁 Future Enhancements for This Repo
Full SOC investigation template

Triage flowchart

MITRE ATT&CK mapping

KQL cheat sheet

“How to write a SOC case study” guide

Additional scenarios (phishing, malware, insider threat, etc.)
