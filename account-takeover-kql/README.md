# KQL Account Takeover Investigation

**Fictional SOC scenario — Cloudora (B2B HR software company)**
Tools: Azure Data Explorer (KQL), Microsoft Entra sign-in & audit logs

## Scenario

Cloudora's IT admin flagged an alert: the CEO, Daniel Reeve, appeared to have signed in from Lagos, Nigeria at 03:12 AM — while he should have been asleep at home in London. With the company days from closing its biggest enterprise deal, a compromised executive mailbox posed a serious business risk. I was brought in to confirm or refute the compromise, build the full timeline, hunt for persistence, check for other victims, and write the incident report.

## Step 1 — Setting up the investigation lab

I set up a free Azure Data Explorer cluster and loaded two log sources:

- `CloudoraSignIn_CL` — sign-in logs
- `CloudoraAudit_CL` — audit logs

Verified the data loaded correctly:

```kql
CloudoraSignIn_CL
| count
```

<img width="1543" height="732" alt="Screenshot 2026-08-16 190917" src="https://github.com/user-attachments/assets/a84ae1fd-d721-4678-9651-090f45df089f" />



## Step 2 — Confirming the compromise

**Checked Daniel's sign-ins on the day of the incident:**

```kql
CloudoraSignIn_CL
| where UserPrincipalName == "daniel.reeve@cloudora.io"
| where TimeGenerated between (datetime(2026-08-10) .. datetime(2026-08-11))
| project TimeGenerated, AppDisplayName, IPAddress, City, Country, ResultType, ResultDescription
| order by TimeGenerated asc
```

Found a pattern of several failed logins followed by a successful login at 03:12 AM from Lagos. `ResultType` 50126 = failure, `ResultType` 0 = success.

<img width="1908" height="978" alt="Screenshot 2026-08-16 165952" src="https://github.com/user-attachments/assets/0305d1a7-877d-409f-8f3e-45906bd86697" />


**Impossible travel check:** Daniel signed in again from London just ~5 hours later. A flight from Lagos to London takes more than 6 hours — so this couldn't be him travelling.

```kql
CloudoraSignIn_CL
| where UserPrincipalName == "daniel.reeve@cloudora.io"
| summarize SignIns=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Country, City, IPAddress
| order by SignIns desc
```

<img width="1909" height="975" alt="Screenshot 2026-08-16 170314" src="https://github.com/user-attachments/assets/dab3c006-6138-445f-9c22-35dc9884616f" />


**Baseline vs. anomaly:** Compared Daniel's activity to a normal traveling employee, Omar (based in Dubai). Omar's logins were daytime, single-attempt successes from a consistent device — normal travel behavior. Daniel's 3 AM burst of failures followed by a success from a brand-new device was a confirmed compromise, not travel.

```kql
CloudoraSignIn_CL
| where UserPrincipalName == "omar.farah@cloudora.io"
| summarize SignIns=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Country, City, IPAddress
| order by SignIns desc
```

<img width="1908" height="973" alt="Screenshot 2026-08-16 170929" src="https://github.com/user-attachments/assets/6ff437d5-d17d-4ce4-abd0-26127ccc3b68" />


## Step 3 — Finding initial access

**Identifying the password spray:** searched for the Lagos IP ranges for high failure rates across multiple accounts.

```kql
CloudoraSignIn_CL
| where IPAddress startswith "102.89."
| summarize Attempts=count() by bin(TimeGenerated, 1d), ResultType
```

The attacker hit 20+ different accounts, trying only 1–2 passwords on each account to stay under lockout thresholds — classic **password spraying (MITRE T1110.003)**. Using `bin()` to bucket by day showed three consecutive nights of spraying before Daniel's password was finally cracked on night three.

<img width="1549" height="672" alt="Screenshot 2026-08-16 171956" src="https://github.com/user-attachments/assets/3d09d3b2-aeee-4d33-b2bc-7716af02ed58" />


## Step 4 — Hunting for persistence

Switched to the audit logs to see what the attacker did after gaining access:

```kql
CloudoraAudit_CL
| where IPAddress startswith "102.89."
| project TimeGenerated, ActivityDisplayName, TargetUser, Details
| order by TimeGenerated asc
```

- **MFA backdoor:** 6 minutes after login, the attacker registered a new MFA device — a Pixel 6 authenticator app (**T1098.005**). This meant a password reset alone would not lock the attacker out.
- **BEC staging:** an inbox rule was created to automatically hide (move + mark read) any email containing "finance" or "invoice" — a classic **Business Email Compromise** setup used to intercept financial communications and stage fraud.

<img width="1547" height="636" alt="Screenshot 2026-08-16 172655" src="https://github.com/user-attachments/assets/37280134-f6b5-44e1-bfa4-ed56c72c7268" />


## Step 5 — Scoping the incident

Queried for any other successful logins from the attacker's Lagos IPs to check for additional victims:

```kql
CloudoraSignIn_CL
| where IPAddress startswith "102.89." and ResultType == "0"
| project UserPrincipalName, IPAddress, TimeGenerated
| order by TimeGenerated asc
```

Found a second victim — Priya Nair — accessed ~30 minutes after Daniel. Investigated her sign-in and audit trail separately:

```kql
CloudoraSignIn_CL
| where UserPrincipalName == "priya.nair@cloudora.io"
| project TimeGenerated, AppDisplayName, City, Country, ResultType, ResultDescription, IPAddress
| order by TimeGenerated asc
```

Several failed attempts preceded a successful login at 03:52 AM. Her audit logs showed no attacker activity (no persistence set up), but credential reset was still required as a precaution.

<img width="1546" height="729" alt="Screenshot 2026-08-16 173122" src="https://github.com/user-attachments/assets/318214cd-9f69-41ca-b4cf-94cd13207152" />

<img width="1543" height="860" alt="Screenshot 2026-08-16 201207" src="https://github.com/user-attachments/assets/9af98f66-e48b-4dae-8481-4b4a89660ccf" />


## Step 6 — Containment and remediation

Followed the NIST Incident Response lifecycle:

`Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident Activity`

1. Revoke sessions **before** attempting password resets
2. Reset credentials (password reset alone is not sufficient)
3. Remove the attacker's MFA method (Pixel 6 device)
4. Remove the malicious inbox rule so mail flows normally again
5. Block the attacker's IPs
6. Verify — rerun steps 1–5 as queries to confirm no further attacker activity

## Step 7 — Final reporting

Documented the full incident in a formal Incident Report, including:

- An executive summary in plain English for the CEO, and a technical timeline for the IT team
- Every timestamp normalized to UTC to avoid time-zone confusion
- A full Indicators of Compromise (IOCs) list — attacker IPs and the malicious inbox rule name — so other analysts can use them for future detection
