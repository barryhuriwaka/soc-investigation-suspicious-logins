#  SOC Investigation — Suspicious Login Activity
**Case Study: Unauthorized Access Attempt in Microsoft 365**

## Case Summary
A user account belonging to a Brisbane-based employee showed multiple failed login attempts from a foreign IP address, followed by a successful authentication while the user was asleep. The activity originated from Singapore and occurred in the absence of MFA, strongly indicating credential compromise. Immediate containment and investigation actions were required to secure the account and prevent lateral movement.

---

##  Scenario Overview
A small business uses Microsoft 365 for identity and email. The SOC receives an alert indicating multiple failed login attempts followed by a successful login from an unusual location. The user confirms they were asleep at the time of the successful authentication.


### **User & Alert Details**

| Field                   | Details                          |
|-------------------------|----------------------------------|
| User                    | jane.harris@brisbanetech.com.au  |
| Normal Location         | Brisbane, QLD                    |
| Suspicious Location     | Singapore                        |
| Time of Alert           | 02:14 AEST                       |
| Alert Source            | Azure AD Identity Protection     |
| Authentication Method   | Password only (no MFA)           |





## 🔍 Initial Log Review (Azure Sentinel)


### **KQL Query Used**
```
SigninLogs
| where UserPrincipalName == "jane.harris@brisbanetech.com.au"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
```
### **Sample Output**

| TimeGenerated (AEST)       | UserPrincipalName               | IPAddress     | Location  | ResultType | ResultDescription            |
|----------------------------|----------------------------------|---------------|-----------|------------|------------------------------|
| 2024‑11‑12 02:06:14.221    | jane.harris@brisbanetech.com.au | 203.0.113.55  | Singapore | 50053      | Invalid username or password |
| 2024‑11‑12 02:06:47.902    | jane.harris@brisbanetech.com.au | 203.0.113.55  | Singapore | 50053      | Invalid username or password |
| 2024‑11‑12 02:07:12.443    | jane.harris@brisbanetech.com.au | 203.0.113.55  | Singapore | 50053      | Invalid username or password |
| 2024‑11‑12 02:07:45.118    | jane.harris@brisbanetech.com.au | 203.0.113.55  | Singapore | 50053      | Invalid username or password |

## Analyst Assessment

### Indicators of Compromise

Multiple failed attempts from a foreign IP

Successful login shortly after repeated failures

User confirms no activity at that time

No MFA enabled (high‑risk configuration)

### Likely Attack Pattern

This behaviour aligns with:

Password spraying

Credential stuffing

Compromised credentials via phishing or breach reuse

## Recommended Immediate Actions

### Containment
 Force password reset for the affected user
 Revoke active sessions in Azure AD
 Block the suspicious IP address
 Enable MFA immediately

### Investigation

Review sign‑in logs for lateral movement

Check mailbox rules for forwarding or deletion

Review audit logs for privilege escalation

Search for additional failed attempts across tenant

### Recovery

Confirm user identity and secure account

Validate no unauthorized changes were made

Re‑enable access with MFA enforced

### Lessons Learned
   
Enforce MFA tenant‑wide

Implement conditional access policies

Enable risk‑based sign‑in alerts

Educate users on password hygiene

## Future Enhancements for This Repo

Full SOC investigation template

Triage flowchart

MITRE ATT&CK mapping

KQL cheat sheet

“How to write a SOC case study” guide

Additional scenarios (phishing, malware, insider threat, etc.)

## 🕒 Timeline of Events

| Time (AEST)            | Event Description                                      |
|------------------------|--------------------------------------------------------|
| 02:06:14               | Failed login attempt from Singapore (203.0.113.55)     |
| 02:06:47               | Failed login attempt from same IP                      |
| 02:07:12               | Failed login attempt from same IP                      |
| 02:07:45               | Failed login attempt from same IP                      |
| 02:14:00 (approx.)     | Successful login from Singapore                        |
| 08:00                  | User reports they were asleep during the activity      |
| 08:10                  | SOC initiates investigation and containment actions     |

## 🧬 MITRE ATT&CK Mapping

| Tactic              | Technique                     | ID        | Relevance to Case                                      |
|---------------------|-------------------------------|-----------|--------------------------------------------------------|
| Initial Access      | Valid Accounts                | T1078     | Attacker used compromised credentials to log in        |
| Credential Access   | Credential Stuffing / Spraying| T1110     | Multiple failed attempts indicate password attacks     |
| Defense Evasion     | Valid Accounts                | T1078.004 | Successful login using legitimate credentials          |
| Discovery           | Account Discovery             | T1087     | Possible enumeration attempts prior to login           |
| Impact (Potential)  | Account Manipulation          | T1098     | Risk of mailbox rule creation or persistence           |

## 📊 Incident Flow Diagram (Mermaid)

```mermaid
flowchart TD
    A[Attacker attempts login from Singapore] --> B[Multiple failed attempts]
    B --> C[Successful login]
    C --> D[User asleep - activity confirmed suspicious]
    D --> E[SOC receives alert]
    E --> F[Containment actions: reset password, revoke sessions]
    F --> G[Investigation: logs, mailbox rules, audit review]
    G --> H[Recovery and MFA enforcement]```

 ```   
soc-investigation-suspicious-logins/
├── README.md                     # Main case study
├── diagrams/
│   └── incident-flow.mmd         # Mermaid diagrams
├── logs/
│   └── sample-signinlogs.csv     # Sanitised log samples (optional)
├── queries/
│   └── signinlogs-query.kql      # KQL queries used in investigation
├── reports/
│   └── analyst-summary.md        # Optional extended report
└── artifacts/
    └── ioc-list.txt              # Indicators of compromise
```
