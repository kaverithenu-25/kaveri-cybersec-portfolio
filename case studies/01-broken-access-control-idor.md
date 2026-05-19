**Broken Access Control (IDOR) — A Real-World Pattern in a Fintech-Style Flow**

Case study #01 · Author: Kaveri J. B. · Category: Web Application Security · OWASP: A01:2021 Broken Access Control


**TL;DR**

A common but high-impact authorization flaw where the application trusts a client-supplied identifier (e.g. userId, accountId, invoiceId) without verifying that the authenticated user actually owns the referenced resource. The result: any logged-in user can access — and sometimes modify — data belonging to other users by simply changing a number in the URL or request body.
This case study walks through how the issue manifests, how to identify it during a VAPT engagement, how to reproduce a sanitised version in a lab environment, and how to remediate it at both the code and architecture level.

**1. Background**
During a VAPT engagement on a fintech-style web application handling customer financial records, an Insecure Direct Object Reference (IDOR) vulnerability was identified in a transaction history module. The application correctly enforced authentication (every endpoint required a valid session token), but failed to enforce authorization — meaning it did not verify whether the requesting user had permission to view the specific resource being requested.
This is one of the most common findings in real-world web application assessments and consistently ranks in the OWASP Top 10. It tends to slip past automated scanners because the technical request looks valid — the only thing wrong is who is making it.

**2. The vulnerability**
What the vulnerable flow looked like
After login, a user could view their own transaction history by visiting:
GET /api/v1/transactions?userId=10234
Authorization: Bearer <valid-session-token>
The application returned the transactions for userId=10234. The flaw: it returned them for any userId value supplied in the query string, as long as the requester had some valid session — even one belonging to a completely different user.
Why this happens
The pattern is almost always one of three root causes:

The application trusts the client to send the correct ID. Developers assume that because the frontend only shows the logged-in user's own ID, no one will tamper with it. Attackers, of course, do.
Authorization is enforced only at the page/UI layer. The login check exists, but the per-resource ownership check is missing in the API handler.
Sequential or guessable IDs. When resources use integers (1, 2, 3...) instead of UUIDs, enumeration becomes trivial.


**3. Detection methodology**
Step-by-step approach used during the engagement:

-Map the application. Walk through every authenticated function as a normal user (User A). Note every endpoint that takes an ID parameter — query string, URL path, request body, or hidden form field.
-Capture authenticated requests in Burp Suite. Each request that references a user-owned object becomes a candidate for IDOR testing.
-Create a second test account (User B). Note User B's resource IDs as a control set.
-Replay User A's requests but substitute User B's IDs, using User A's session token. If the server returns User B's data — you have an IDOR.
-Escalate horizontally and vertically. Test if User A can not only read but also modify, delete, or perform actions on User B's resources. Test if a regular user can access admin-tier IDs.


**4. Reproduction in a safe lab environment**
To demonstrate this pattern publicly without breaching client confidentiality, the same flaw is reproducible against the OWASP Juice Shop vulnerable application.
Lab setup
bashdocker run --rm -p 3000:3000 bkimminich/juice-shop
Navigate to http://localhost:3000 and create two test accounts (usera@lab.local and userb@lab.local).
Reproduction steps

Log in as User A and add an item to the basket.
Inspect the basket request in Burp Suite — note the basket ID in the URL (e.g. /rest/basket6).
Log in as User B in a separate browser/incognito session — note their basket ID (e.g. /rest/basket/7).
As User A, in Burp Repeater, change the URL to User B's basket ID: /rest/basket/7 while keeping User A's authorization header.
Observe: the response returns User B's basket contents.



**5. Impact assessment**
**Dimension        Rating                      Reasoning **  
Confidentiality    High          Direct exposure of another user's financial / personal data
Integrity          Medium–High   If the endpoint also accepts POST/PUT, attacker can modify others' records
Availability       Low           Unlikely direct impact, though deletion variants exist
CVSS 3.1           7.7 (High)    AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
Business impact    Critical      Regulatory exposure (data protection law), reputation damage, contractual breach

In a fintech context, this single finding can be sufficient to fail a security audit or block a regulated product launch.

**6. Remediation**
Immediate fix (code level)
Every protected endpoint must verify resource ownership server-side. A typical Node.js / Express example:
javascript
// VULNERABLE
app.get('/api/v1/transactions', authenticate, (req, res) => {
  const userId = req.query.userId;          // ← trusts client
  return db.getTransactions(userId);
});

// FIXED
app.get('/api/v1/transactions', authenticate, (req, res) => {
  const userId = req.user.id;               // ← from session, not query
  return db.getTransactions(userId);
});
If the endpoint legitimately needs to accept an ID (e.g. admin viewing any user), enforce an explicit authorization check:

javascript
app.get('/api/v1/transactions/:id', authenticate, (req, res) => {
  const resource = db.getTransaction(req.params.id);
  if (resource.ownerId !== req.user.id && !req.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }
  return res.send(resource);
});

Architectural improvements

Replace sequential integer IDs with UUIDs to prevent enumeration.
Implement a central authorization layer (e.g. policy-based access control with libraries like CASL or OPA) rather than scattered per-endpoint checks.
Add automated authorization tests to CI/CD: spin up two test users and assert that User A cannot access User B's resources for every endpoint.

Detection in SAST / DAST

SAST (SonarQube, Semgrep): custom rules can flag controller methods that read object IDs from req.query / req.params and pass them directly to the data layer without an ownership check.
DAST: authenticated DAST tools with multi-user configuration (e.g. Burp Suite Enterprise, OWASP ZAP with authentication scripts) can detect IDOR patterns automatically.


**7. Lessons learned**

-Authentication ≠ authorization. A logged-in user is not automatically an authorized user. Every protected resource needs an ownership check.
-The frontend is not a security boundary. "The UI only shows their own ID" is not a control — attackers don't use the UI.
-IDOR is a class of bugs, not a single bug. Fixing one endpoint while leaving others vulnerable provides false confidence. A systematic codebase sweep is required.
-Test it continuously. A one-time pentest finding is closed in a sprint, but the same flaw often resurfaces in a future release. Authorization tests belong in the CI pipeline.


**8. References**

OWASP Top 10 — A01:2021 Broken Access Control  
OWASP — Insecure Direct Object Reference Prevention Cheat Sheet                     
OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization                                      
                                       PortSwigger Web Security Academy — Access control vulnerabilities and privilege escalation
