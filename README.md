SOC Investigation — Suspicious Login Activity
Scenario
A small business uses Microsoft 365 for email and identity. The SOC receives an alert for multiple failed login attempts followed by a successful login from an IP address located outside Australia. The user reports they were asleep at the time of the login.

User: jane.harris@brisbanetech.com.au
Normal location: Brisbane, QLD
Suspicious location: Singapore
Time: 02:14 AEST
Alert source: Azure AD Identity Protection
Authentication: Password only (no MFA)

Log Data (Azure Sentinel)
Failed Login Attempts
KQL Query

Code
```
SigninLogs
| where UserPrincipalName == "jane.harris@brisbanetech.com.au"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
```
Sample Output
TimeGenerated (AEST)	UserPrincipalName	IPAddress	Location	ResultType	ResultDescription
2024-11-12 02:06:14.221	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
2024-11-12 02:06:47.902	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
2024-11-12 02:07:12.443	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
2024-11-12 02:07:45.118	jane.harris@brisbanetech.com.au	203.0.113.55	Singapore	50053	Invalid username or password
