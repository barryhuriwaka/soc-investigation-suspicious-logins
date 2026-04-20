[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

<div align="center">

# 🔥 CYBERSECURITY CASE STUDY 001  
### **Suspicious Login Activity • Identity Threat • Account Compromise**

</div>

---

# CASE STUDY 001 — Suspicious Login Activity  
**Status:** Closed  
**Severity:** High  
**Category:** Identity Threat / Account Compromise  

---

## 🧭 Executive Summary  

Azure AD Identity Protection detected multiple failed login attempts from Singapore, followed by a successful authentication while the user was asleep.  
This behaviour strongly indicates credential compromise via password spraying or credential stuffing.

Immediate containment actions were taken to secure the account, revoke sessions, and enforce MFA.

---

## 🎯 Objectives  

- Determine whether the login was legitimate or malicious  
- Identify the source and method of compromise  
- Assess potential lateral movement  
- Contain the account and prevent further misuse  
- Provide remediation and long‑term recommendations  

---

## 👤 User & Alert Details  

| Field | Details |
|-------|---------|
| **User** | jane.harris@brisbanetech.com.au |
| **Normal Location** | Brisbane, QLD |
| **Suspicious Location** | Singapore |
| **Alert Source** | Azure AD Identity Protection |
| **Authentication** | Password only (no MFA) |

---

## 🔍 Initial Indicators  

- Multiple failed attempts from a foreign IP  
- Successful login shortly after repeated failures  
- User confirms no activity at that time  
- No MFA enabled  
- High‑risk sign‑on flagged  

---

## 📊 KQL Queries Used  

```kusto
SigninLogs
| where UserPrincipalName == "jane.harris@brisbanetech.com.au"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
```

---

## 🧠 Analyst Assessment  

### Indicators of Compromise  

- Foreign login  
- Multiple failed attempts  
- Successful login while user asleep  
- No MFA  
- High‑risk sign‑in  

### Likely Attack Pattern  

- Password spraying  
- Credential stuffing  
- Phishing‑derived credentials  

---

## 🛡️ Containment Actions  

- Forced password reset  
- Revoked all active sessions  
- Blocked suspicious IP  
- Enabled MFA  
- Reviewed mailbox rules  
- Checked for lateral movement  

---

## 🧬 MITRE ATT&CK Mapping  

| Tactic | Technique | ID |
|--------|-----------|----|
| Valid Accounts | Compromised Credentials | T1078 |
| Credential Access | Password Spraying | T1110 |
| Defense Evasion | MFA Bypass Attempt | T1078.004 |

---

## 🕒 Timeline (AEST)  

| Time | Event |
|------|--------|
| 02:06 | Failed login from Singapore |
| 02:14 | Successful login |
| 08:00 | User reports issue |
| 08:10 | SOC begins investigation |

---

## 📁 Repo Structure  

```
/diagrams
/logs
/queries
/reports
/artifacts
README.md
```

---

[Next Case Study → Case Study 002 — Business Email Compromise](https://github.com/barryhuriwaka/Business-Email-Compromise)
[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

