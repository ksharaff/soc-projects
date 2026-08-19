# Cloudora Payroll Phishing Investigation

![Status](https://img.shields.io/badge/status-resolved-brightgreen) ![Severity](https://img.shields.io/badge/severity-P1-red) ![Type](https://img.shields.io/badge/type-simulated%20engagement-blue) ![Tools](https://img.shields.io/badge/tools-KQL%20%7C%20Azure%20Data%20Explorer-informational)



## Scenario

A high-priority P1 incident: a phishing email themed "Payroll update: action required" was sent to 40 Cloudora employees, threatening to withhold salaries if payroll details weren't confirmed by 5:00 PM — a deliberate urgency/panic tactic. Several employees reported it, one forwarded a marketing newsletter in the same batch unsure if it was related, and at least one person had already typed their password into the linked page.

**Goal:** determine who was affected, identify the attacker's infrastructure, evict them from the tenant, and prove containment.

---

## Investigation Walkthrough

### 1. Triage & Evidence Collection

Three "witnesses" were needed to tell the full story:

1. **The emails** — what the attacker actually sent
2. **Message trace logs** — who received it and who clicked
3. **Sign-in logs** — whose credentials were actually used

### 2. Email Header & Authentication Analysis

I opened the suspicious emails in a **plain text editor**—not a mail client—to prevent loading tracking pixels that could alert the attacker.

- **Reading the "Postmarks":** I ignored the display name and focused on the **Authentication Results** header.
- **Variant A:** This email failed all three major checks: **SPF** (not on the authorized guest list), **DKIM** (the cryptographic "wax seal" was missing or broken), and **DMARC** (the company policy said to quarantine it). I traced it to an external server on a lookalike domain: **`cloudora-hortal.example`**.

<img width="878" height="386" alt="Screenshot 2026-08-19 192920" src="https://github.com/user-attachments/assets/01cb6c89-3477-4fc1-b071-e9df4c16ce71" />


The Lookalike Trap (Variant B): This was a sneakier version that actually passed authentication. I learned that a valid seal only proves the domain is real, not that the sender is trustworthy; the attacker simply registered their own lookalike domain and "honestly" signed the email as themselves.
<img width="857" height="405" alt="Screenshot 2026-08-19 193020" src="https://github.com/user-attachments/assets/7405c7c0-8062-4a81-8a1f-2c6f000ca2ab" />


The False Positive: I also analyzed a marketing newsletter. It passed all checks and was aligned with our brand and Mailchimp (mcsv.net), proving it was legitimate.
<img width="870" height="388" alt="Screenshot 2026-08-19 193121" src="https://github.com/user-attachments/assets/745ab84e-922e-4275-a998-f52bc8a401fd" />



**Why the newsletter is clean and Variant B isn't, despite both passing authentication:** the newsletter passes SPF/DKIM/DMARC *for `cloudora.io` itself*, sent via Mailchimp as an authorized third party with DKIM aligned to the real domain. Variant B also passes all three checks, but only because the attacker registered their own look-alike domain and honestly signed it as themselves — passing authentication proves the domain in the `From` header is real, not that the sender is trustworthy, and that domain was never Cloudora's.

### 3. Investigation Lab Setup

I used **Azure Data Explorer (ADX)** to query the logs using **KQL**.

1. **Data Ingestion:** I created two tables: CloudoraMsgTrace_CL and CloudoraSignIn_CL.
2. **Data Discipline:** I made sure to set columns like **`ResultType`** to **strings** so my queries wouldn't break, and I ran a **`count`** to verify I had all **67 rows** of trace data.

### 4. Scoping the Campaign (KQL)

First, I ran a query to check the message traces for how many people got delivered the email.
<img width="1542" height="864" alt="Screenshot 2026-08-19 172403" src="https://github.com/user-attachments/assets/b87d7a00-1347-491a-ac58-1d6d66a51f5f" />


Secondly, to be more precise, I wanted to check how many and who clicked the link and whether they entered their credentials or not. I noticed that 4 didn’t submit their credentials, while 2 others did.
<img width="1543" height="856" alt="Screenshot 2026-08-19 172605" src="https://github.com/user-attachments/assets/010386d1-73c5-4dad-ac05-1c7a114d6e2c" />


Query to produce every account that received the phish but didn’t click
<img width="902" height="856" alt="Screenshot 2026-08-19 212826" src="https://github.com/user-attachments/assets/843116dd-4767-4ca8-bdc1-9d306347db10" />


Thirdly, I wanted to check the ones that both CLICKED AND SUBMITTED. Not only that, but the sign-in details which include the IP address, Country, City, DeviceOS, etc..

I noticed two things:

- My query showed Freya signed in from Manchester at 8:00 AM on her iPhone, but by 10:34 AM, a successful sign-in occurred from **Amsterdam** (IP 198.18.7.200) on a Windows machine she never uses.
- There were no failed logins before the success. This proved the attacker was "handed the key" via the phishing page.
<img width="1548" height="860" alt="Screenshot 2026-08-19 181439" src="https://github.com/user-attachments/assets/d3009014-cab8-4c60-84a8-0eec7f6a2dea" />


Lastly, I wrote a query which investigates deeper into this unusual IP, summarizing all success sign-ins for that IP. After I ran the query, two names showed up. These two accounts were both signed-in from the same IP, country, and date with approximately only 3 hours apart.
<img width="1542" height="602" alt="Screenshot 2026-08-19 181524" src="https://github.com/user-attachments/assets/a5c2efd0-b248-4e56-be21-37bd3162ef2e" />


### 5. Containment & Remediation

Followed the NIST IR model, order-of-operations matters here:

1. **Revoke sessions** — booting the attacker out matters more than a password reset while their session is still live
2. **Reset credentials** — only after sessions are dead
3. **Enforce/re-register MFA** on both compromised accounts
4. **Block infrastructure** — sending IPs (`198.18.44.10`, `198.18.44.23`, `198.18.51.7`), the login IP (`198.18.7.200`), and `cloudora-hr-portal.example` (+ subdomains)
5. **Purge** the delivered phish from every mailbox
6. **Verify** — re-run the sign-in pivot and confirm zero activity from `198.18.7.200` after containment

### 6: Writing an email to the staff who got sent the phishing email

> **Subject:** Security Notice — Phishing Email Sent to Cloudora Staff Today
>
> Dear [name],
>
> A phishing email with the subject "Payroll update: action required" was sent to a number of Cloudora staff today. It impersonated Cloudora HR and asked recipients to confirm their payroll details through a link.
>
> Our records show this email reached your inbox but you did not click the link. No action is needed on your part — thank you for not engaging with it.
>
> As a reminder: Cloudora HR will never ask you to "confirm" payroll details urgently through an email link. Genuine payroll requests always come through myhr.cloudora.io. If you see a similar email again, please forward it to security@cloudora.io rather than clicking anything.
>
> Thanks for staying alert,
> Cloudora Security Operations

**Clicked-but-no-credentials group (firmer):**

> **Subject:** Action Required — You Clicked a Phishing Link Today
>
> Dear [name],
>
> Our records show you clicked a link in today's phishing email. Our logs confirm you did not enter your password on the page, so your account has not been compromised.
>
> Please, before end of day: close the page if it's still open in a browser tab, let IT run a quick device check, and report anything unfamiliar on your account over the next few days to security@cloudora.io.
>
> This was not a real Cloudora email — genuine payroll requests always come through myhr.cloudora.io, never a "confirm your details" link.
>
> Thanks,
> Cloudora Security Operations

### 7. Detection Rule

The signal that would have caught this automatically: **a successful sign-in from a country the user doesn't normally use, within a few hours of that same user clicking a phishing link.** That's exactly what caught Freya and Ryan.

A 6-hour window comfortably covers both real compromises (1h47m and 4h17m after click) while staying tight enough to be a same-day alert. Checking each user's *own* baseline country — rather than a hardcoded country list — is what makes the rule generalize to legitimate travelers later on.

---

## Key Findings

- **54 messages delivered** across two campaign variants (33 for Variant A, 21 for Variant B); **7 additional copies quarantined** by Exchange Online Protection
- **6 recipients clicked** the phishing link; **2 submitted credentials** (Freya Lynn, Ryan Boyd)
- **2 accounts confirmed compromised** — both accessed by the same attacker IP (`198.18.7.200`, Amsterdam, NL) within a ~3-hour window of each other
- Attacker reached **SharePoint Online** in addition to mailbox access on one account
- One marketing newsletter correctly cleared as a **false positive** with documented evidence, distinguishing it from the auth-passing Variant B phish



## Disclaimer

This is a **simulated client engagement**, built on the MyFirstHack "Cloudora" training dataset (a `myfirstcyberjob` community resource). Cloudora, all employees, IP addresses, and domains are fictional. The look-alike domain uses the reserved `.example` TLD, which can never resolve to a real site. Completed as a self-directed portfolio exercise, not as employment.

## Author

**K**
GitHub: [@ksharaff](https://github.com/ksharaff) · Portfolio: [ksharaff.github.io](https://ksharaff.github.io)
