# SOC Investigation — Suspicious Login Activity  
### **Case Study 001: Unauthorised Access Attempt in Microsoft 365**  
**Status:** Closed  
**Severity:** High  
**Cause:** Credentials Compromised  

---

## 🧭 Executive Summary  
A Brisbane‑based employee’s Microsoft 365 account showed multiple failed login attempts from a foreign IP address (Singapore), followed by a successful authentication while the user was asleep.  
The pattern strongly indicates credential compromise via **password spraying** or **credential stuffing**.

Immediate containment actions were taken to secure the account, revoke sessions, and enforce MFA.

This case demonstrates:  
- Identity‑based threat detection  
- KQL log analysis  
- MITRE ATT&CK mapping  
- Analyst reasoning  
- Containment workflow  

---

## 🎯 Case Objectives  
- Determine whether the login was legitimate or malicious  
- Identify the source and method of compromise  
- Assess potential lateral movement  
- Contain the account and prevent further misuse  
- Provide remediation and long‑term recommendations  

---

## 👤 User and Alert Details  

| Field | Details |
|-------|---------|
| **User** | jane.harris@brisbanetech.com.au |
| **Normal location** | Brisbane, QLD |
| **Suspicious location** | Singapore |
| **Time of alert** | 02:14 AEST |
| **Alert source** | Azure AD Identity Protection |
| **Authentication method** | Password only (no MFA) |

---

## 📊 Initial Log Review (Azure Sentinel)

### **KQL Query Used**
```kql
SigninLogs
| where UserPrincipalName == "jane.harris@brisbanetech.com.au"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
```

### **Sample Output**
| Time Generated (AEST) | IP | Location | Result | Description |
|------------------------|----|----------|--------|-------------|
| 02:06:14 | 203.0.113.55 | Singapore | 50053 | Invalid username or password |
| 02:06:47 | 203.0.113.55 | Singapore | 50053 | Invalid username or password |
| 02:07:12 | 203.0.113.55 | Singapore | 50053 | Invalid username or password |
| 02:07:45 | 203.0.113.55 | Singapore | 50053 | Invalid username or password |
| 02:14:00 | 203.0.113.55 | Singapore | 0 | Success |

---

## 🧠 Analyst Assessment  

### **Indicators of Compromise**
- Multiple failed attempts from a foreign IP  
- Successful login shortly after repeated failures  
- User confirms no activity at that time  
- No MFA enabled  
- High‑risk sign‑on flagged by Identity Protection  

### **Likely Attack Pattern**
- Password spraying  
- Credential stuffing  
- Phishing‑derived credentials  

**Risk Level:** **High**  
The attacker successfully authenticated and could have accessed email, files, or attempted lateral movement.

---

## 🛡️ Containment Actions  

### **Immediate**
- Forced password reset  
- Revoked all active sessions  
- Blocked the suspicious IP  
- Enabled MFA for the user  

### **Investigation**
- Reviewed sign‑in logs for lateral movement  
- Checked mailbox rules for forwarding or deletion  
- Reviewed audit logs for privilege escalation  
- Searched for additional failed attempts across the tenant  

### **Recovery**
- Verified no unauthorised mailbox rules  
- Confirmed no privilege escalation  
- Re‑enabled access with MFA enforced  

---

## 🧬 MITRE ATT&CK Mapping  

| Tactic | Technique | ID | Why it Applies |
|--------|-----------|----|----------------|
| Valid Accounts | Compromised Credentials | T1078 | Attacker used stolen credentials |
| Credential Access | Password Spraying / Stuffing | T1110 | Multiple failed attempts indicate brute‑force patterns |
| Valid Accounts | MFA Bypass / Password Only | T1078.004 | Successful login using legitimate credentials |
| Discovery | Account Discovery | T1087 | Likely enumeration before login |
| Persistence | Account Manipulation | T1098 | Risk of mailbox rule creation or persistence |

---

## 🕒 Timeline of Events (AEST)

| Time | Event Description |
|------|-------------------|
| 02:06:14 | Failed login attempt from Singapore |
| 02:06:47 | Failed login attempt from same IP |
| 02:07:12 | Failed login attempt from same IP |
| 02:07:45 | Failed login attempt from same IP |
| 02:14:00 | Successful login from Singapore |
| 08:00 | User reports they were asleep |
| 08:10 | SOC initiates investigation |

---

## 📊 Incident Flow Diagram (Mermaid)
*(Diagram file located in `/diagrams/incident-flow.mmd`)*

---

## 📁 Repository Structure  
```
soc-investigation-suspicious-logins/
├── README.md
├── diagrams/
│   └── incident-flow.mmd
├── logs/
│   └── sample-signinlogs.csv
├── queries/
│   └── signinlogs-query.kql
├── reports/
│   └── analyst-summary.md
└── artifacts/
    └── ioc-list.txt
```
