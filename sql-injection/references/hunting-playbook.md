# SQL Injection Hunting Playbook (Bug Bounty Posture)

Load this file for *where and how to hunt* — target selection, attack-surface signals, root causes, real-world cases, and reportable-impact framing. Technique payloads live in `SKILL.md` and the other references. Distilled from elementalsouls/Claude-BugHunter (`hunt-sqli`, built from 29 disclosed reports/CVEs) and SNGWN/CEH-Notes Module 15.

## 1. Crown Jewel Targets

SQLi remains one of the highest-paying vulnerability classes because it threatens confidentiality, integrity, and availability at scale.

**Highest-value targets:**
- **SaaS platforms with multi-tenant databases** — one injection can expose all customers' data
- **E-commerce / payment systems** — PII, card data, transaction records
- **Search endpoints** — user input passed directly into queries (e.g. Rockstar Games `/search`)
- **Analytics/tracking subdomains** — built fast, tested less (e.g. `sctrack.email.uber.com.cn`)
- **Third-party plugins on enterprise installs** — WordPress/CMS extensions running on corporate domains (Uber's Huge IT Video Gallery)
- **Internal tooling exposed externally** — Apache Airflow, GitHub Enterprise, admin dashboards
- **NoSQL backends (MongoDB)** — often overlooked; same injection class, different syntax

**Asset types that pay most:** production APIs with `/search`, `/filter`, `/sort`, `/report` params; regional legacy subdomains (`.cn`, `.co`, `.io` variants); self-hosted OSS tools (Airflow, GitLab, Jenkins) in scope; email-tracking infrastructure.

## 2. Attack Surface Signals

**URL patterns suggesting injectable parameters:**
```
/search?q=            /api/v1/items?id=       /page=&limit=&offset=
/filter?category=     /index.php?id=          /track?uid=&campaign=
/sort?by=&order=      /gallery?album_id=      /report?start_date=&end_date=
```

**Response-header stack hints:** `X-Powered-By: PHP` → likely MySQL/PostgreSQL; `Server: Apache` + PHP → classic LAMP; `X-Powered-By: Express` → check MongoDB/NoSQL; any leaked DB error string → immediate fingerprint (see `dbms-cheatsheet.md` error-signature table).

**JS-bundle patterns indicating dynamic query construction (grep before fuzzing):**
```bash
grep -rE "query\s*\+=" src/
grep -rE "WHERE.*\+" src/
grep -rE "fetch\(\`[^\`]*\$\{" src/        # template-literal URLs with user input
grep -rE "\.find\(\{" src/ | grep -v sanitize   # Mongo-style calls
grep -rE "axios\.get\('[^']*\+" src/
```

**Tech-stack specifics worth auditing:** WordPress sites with third-party plugins (`/wp-content/plugins/` — check installed plugins against known CVEs AND fuzz their params); Airflow (`/admin/`, `/api/experimental/`); GitHub Enterprise (`/_graphql`, `/api/v3/`); Node+Mongo combos (`$where`/`$regex` in bodies); verbose-error PHP apps.

**Content-type NoSQL signals:** `application/json` bodies with nested object params; array-style params `param[]=value` or `{"key": {"$gt": ""}}`.

**Injection points checklist (CEH module):** URL params · form fields · HTTP headers (User-Agent, Cookie, Referer) · JSON/XML bodies · uploaded filenames · second-order stored data.

## 3. Common Root Causes (predicts where bugs hide)

1. **String concatenation instead of parameterized queries** — the #1 cause: `"SELECT * FROM items WHERE id=" + userId`.
2. **ORMs bypassed "for performance"** — dev drops to raw SQL for complex joins/reports: `db.query("SELECT " + userColumn + " FROM t")`.
3. **Search/filter/sort logic** — column names can't be bound, so devs hand-escape (and fail); allowlist absent.
4. **Third-party plugin/library vulns** — parent company owns the risk of a $20 plugin's unparameterized param.
5. **Legacy codebases** — pre-PDO/MySQLi PHP still serving acquired assets/regional subdomains.
6. **Internal tools promoted to external** — designed for trusted networks, minimal hardening, over-privileged DB connections (Airflow pattern: any authenticated user → full DB read/write).
7. **NoSQL false sense of security** — "we use MongoDB so no SQLi" → zero input validation → operator injection.
8. **Unescaped ORDER BY / GROUP BY** — non-bindable clauses, manually escaped incorrectly.
9. **"Trusted" header values** — User-Agent/Referer/X-Forwarded-For logged into DB without sanitization.

## 4. Real-World Case Studies (breaches)

- **Heartland Payment Systems (2008)** — SQLi in web app → 134M card numbers stolen. Lesson: validate/sanitize ALL inputs in payment paths.
- **Sony Pictures (2011)** — basic SQLi in authentication system → ~1M accounts compromised. Lesson: parameterize every auth query.
- **TalkTalk (2015)** — SQLi in a legacy system → 4M customer records accessed. Lesson: audit legacy/acquired systems continuously.

## 5. Disclosed Bounty/CVE Patterns (2021–2024) — Modern Families

The two SQLi families most under-represented in older material: **NoSQL operator injection** and **ORM raw-fragment injection**.

- **Rocket.Chat `getPasswordPolicy` (CVE-2021-22911, H1 #1130721)** — pre-auth blind MongoDB `$regex` injection via Meteor DDP: `{"msg":"method","method":"getPasswordPolicy","params":[{"token":{"$regex":"^a"}}]}` — brute-force password-reset token char-by-char → admin reset → RCE via integrations. Root cause: method didn't validate `token` was a string before Mongo `findOne`.
- **Mongoose `$where` via `populate({match})` (CVE-2024-53900 / CVE-2025-23061, GHSA-m7xq-9374-9rvx)** — attacker JSON forwarded into `populate({path:'author', match:{$where:"sleep(5000) || true"}})` reached server-side JS eval. Developers assumed ORM-level safety; <8.8.3 didn't strip `$where` inside `match`.
- **Django `QuerySet.values()` JSONField key as column alias (CVE-2024-42005, H1 #2646493, CVSS 9.8)** — `Item.objects.values('data__"); DROP TABLE x;--')` — user-supplied JSON-path key emitted unquoted as SQL alias. Pattern: any framework interpolation of *identifiers* (aliases, columns, table names), not just values.
- **Mozilla `mozilla.social` invite endpoint (H1 #2209130)** — boolean-blind SQLi differentiating "invalid code" vs "code accepted" responses on an OIDC-proxy Postgres lookup: `POST /invite {"code":"abc' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"}`. Pattern: auth-adjacent opaque short codes are still concatenated raw.
- **Uber `sctrack.email...com.cn`** — time-based blind on `uid` in a legacy regional tracking subdomain outside the primary WAF perimeter → schema enumeration + campaign-recipient PII.
- **Uber WordPress Huge IT Video Gallery** — unparameterized `album_id`; shared DB credentials let one plugin pivot beyond the CMS.

**Impact-chain vocabulary for reports** (pair SQLi findings with these): FILE/sysadmin privilege → RCE (`xp_cmdshell`, `COPY FROM PROGRAM`, `INTO OUTFILE` webshell); arbitrary read → harvest UUIDs → mass IDOR; `password_reset_tokens` read/insert → ATO without passwords; multi-tenant → cross-customer breach.

## 6. Modern Vectors & Trends (2024+)

- **GraphQL API injection** — args into resolvers (see `advanced-techniques.md` §8): `{ user(id: "1' UNION SELECT password FROM users--") { name } }`
- **NoSQL injection** — MongoDB/CouchDB operator/JS injection (see `advanced-techniques.md` §16)
- **JSON API injection** — nested objects/keys reaching query builders
- **JWT claim injection** — `{"user": "admin' UNION SELECT password FROM users--"}` when claims feed lookups
- **Cloud & container DB layers** — RDS/Azure SQL/Cloud SQL behind apps; metadata-service SSRF-SQLi hybrids
- **AI-assisted evasion** — comment-stuffed and unicode-normalized payloads crafted to slip signature + ML detectors (e.g. `' /*x*/ UNION /*y*/ SELECT ...`, Unicode look-alike keywords). Defenders: normalize before inspection. Detection models themselves (TF-IDF + classifier on query strings) produce false positives on legit analytics traffic — tune thresholds.

## 7. Practice Labs (skill-building path)

1. **DVWA** (`http://localhost/DVWA/vulnerabilities/sqli/`) — low → impossible security levels; practice quote-break → UNION → blind as protection rises.
2. **sqlilabs / sqli-labs Lessons 1–10** — error-based, quote/paren variations, then blind chains.
3. **PortSwigger Web Security Academy SQLi lab track** — UNION, subversion of logic, blind, advanced techniques.
4. **Build your own vulnerable app** — concatenate input in Python/PHP, then fix it with prepared statements; re-test both states to internalize detection deltas.

## 8. Reporting Notes

Use the Gate-0 questions in `SKILL.md` §Report Evidence Format before submitting. For bounty programs: extract only non-sensitive proof fields, never dump full tables; state remediation at the exact sink (file/function if known via JS/source hints); reference the root-cause category from §3 so triage can generalize the fix.
