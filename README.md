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

## Authentication Activity

| Time (AEST) | Source IP | Location | Result |
|------------|------------|----------|----------|
| 02:06 | 45.77.xxx.xxx | Singapore | Failed |
| 02:08 | 45.77.xxx.xxx | Singapore | Failed |
| 02:10 | 45.77.xxx.xxx | Singapore | Failed |
| 02:14 | 45.77.xxx.xxx | Singapore | Success |
---

## 🔍 Initial Indicators  

- Multiple failed attempts from a foreign IP  
- Successful login shortly after repeated failures  
- User confirms no activity at that time  
- No MFA enabled  
- High‑risk sign‑on flagged  

---
## Investigation Query

```kql
SigninLogs
| where UserPrincipalName == "jane.harris@brisbanetech.com.au"
| project
    TimeGenerated,
    IPAddress,
    Location,
    ResultType,
    AppDisplayName
| order by TimeGenerated asc
```
### Observations

- Three failed authentication attempts preceded a successful login.
- All authentication attempts originated from the same source IP.
- The location was inconsistent with the user's normal sign-in activity.
- The user confirmed no travel or login activity during this period.

This query helped identify repeated authentication failures prior to the successful login.

---
## Findings

### Finding 1 - Unusual Geographic Login

User normally authenticates from Brisbane, Australia.

A successful authentication was observed from Singapore, which does not align with the user's historical sign-in pattern.

### Finding 2 - Multiple Authentication Failures

Several failed authentication attempts preceded the successful login.

This pattern is consistent with password spraying or credential stuffing activity.

### Finding 3 - Lack of MFA Protection

The affected account did not have multi-factor authentication enabled, allowing successful access after password compromise.
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
|----------|----------|----------|
| Initial Access | Valid Accounts | T1078 |
| Credential Access | Password Spraying | T1110.003 |
| Persistence | Valid Accounts | T1078 |
---

## Timeline (AEST)

| Time | Event |
|--------|----------|
| 02:06 | Failed authentication from Singapore |
| 02:08 | Additional failed authentication attempt |
| 02:10 | Third failed authentication attempt |
| 02:14 | Successful authentication from Singapore |
| 08:00 | User reports suspicious activity |
| 08:10 | SOC investigation initiated |
| 08:25 | Active sessions revoked |
| 08:30 | Password reset completed |
| 08:35 | MFA enabled |
| 08:45 | Investigation closed |

---
## Final Assessment

The investigation determined the account was likely compromised through password spraying, credential stuffing, or the use of previously exposed credentials.

Evidence supporting this assessment included:

- Multiple failed login attempts from a foreign location
- Successful authentication from the same source IP
- User confirmation that no login activity occurred at the time
- Absence of multi-factor authentication

No evidence of lateral movement, malicious mailbox rules, or additional account compromise was identified.

**Case Status:** Closed

**Severity:** High

[Next Case Study → Case Study 002 — Business Email Compromise](https://github.com/barryhuriwaka/Business-Email-Compromise)
[← Back to Main Portfolio](https://github.com/barryhuriwaka/cybersecurity-portfolio)

