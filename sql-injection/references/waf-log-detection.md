# Defensive Detection: SQLi in WAF / Application Logs

Load this file for the **blue-team side** of the skill: triaging whether SQLi attempts against an application actually occurred, which technique was used, and whether any attempt succeeded. Patterns distilled from mukul975/Anthropic-Cybersecurity-Skills (`detecting-sql-injection-via-waf-logs`), ModSecurity CRS rule IDs (942xxx SQLi family), OWASP WTE.

## 1. Log Sources to Collect

| Source | What it gives you |
|---|---|
| ModSecurity audit log (`modsec_audit.log`) | Rule ID + matched payload + full request |
| AWS WAF / Cloudflare / Azure Front Door event logs | Action (BLOCK/ALLOW), URI, args, IP, JA3 |
| Web server access logs | Status codes + response size deltas per payload |
| Application error logs / DB slow query logs | Server-side confirmation that a payload executed |
| Authentication logs | Successes correlated with bypass payloads (account takeover signal) |

Key correlation principle: **WAF block ≠ attack stopped at app** (evasion may have passed), and **no WAF hit ≠ no attack** (blind/time-based or encrypted-channel variants). Always cross-check with app/DB logs.

## 2. Detection Regex Patterns (grep/Splunk/KQL starting points)

```text
UNION\s+(ALL\s+)?SELECT                     -- UNION extraction
(ORDER|GROUP)\s+BY\s+\d+\s*(--|#|/\*)       -- column enumeration
(SLEEP|pg_sleep|WAITFOR\s+DELAY|BENCHMARK|randomblob)\s*\(   -- time-based probing
extractvalue\s*\(|updatexml\s*\(|EXP\s*\(~|CONVERT\s*\(\s*int   -- error-based probing
'\s*(OR|AND|\|\||&&)\s*('?1'?=?'?1           -- boolean/tautology
information_schema\.(tables|columns)        -- metadata harvesting
LOAD_FILE\s*\(|INTO\s+(OUT|DUMP)FILE|xp_cmdshell|sp_configure|UTL_HTTP|UTL_INADDR|DBMS_PIPE  -- escalation/OOB
%27|%22|%bf%27|%a8%27                       -- encoded quotes / wide-byte attempts
/\*(![0-9]{5})?.*\*/                        -- comment-obfuscated keywords
';\s*(SELECT|INSERT|UPDATE|DROP|EXEC)       -- stacked queries
SLEEP\(\d+\)\s*/\*                          -- polyglot signatures
ascii\s*\(\s*substring|substring\s*\(.*,\d+,\d+\)  -- blind character inference
benchmark\s*\(\s*[0-9]{6,}                  -- heavy-query DoS attempts
```

Splunk example:
```spl
index=waf (uri_query OR request_body) 
| regex field=request_body pattern="(?i)(union\s+select|sleep\(|waitfor delay|information_schema)"
| stats count by src_ip, uri, waf_action | sort -count
```

Cloudflare: filter `(http.request.uri.query contains "UNION SELECT") OR (ip.src eq ...)`. AWS WAF: inspect `terminatingRuleId` = SQLi match rules plus non-terminating inspection.

## 3. Classify the Technique

| Observed pattern | Technique stage | Intent |
|---|---|---|
| `'`, `"`, `')` errors only | Recon/probing | Fingerprint context |
| `OR 1=1`, `admin'--` on login endpoints | Auth bypass | Immediate account takeover |
| `ORDER BY n` increments | Column enumeration | UNION prep |
| `UNION SELECT NULL...` | Data extraction | Direct dump |
| `extractvalue/updatexml/CONVERT` | Error-based exfil | Extraction without display |
| `SUBSTRING(...,i,1)=c` repeated over same param | Boolean blind | Automated script extraction |
| `SLEEP(5)`/`WAITFOR DELAY` bursts | Time-based blind | Automated script extraction |
| DNS lookups to novel domains (resolved via OOB sink logs) | Out-of-band | Firewall-crossing exfil |
| High-volume near-identical params over minutes | sqlmap/burp automation | Campaign, not manual |

## 4. Success Determination (the part reports get wrong)

Attempt evidence alone is not impact. Grade each campaign:

1. **Blocked**: WAF action=BLOCK on every variant; app returns generic page; no server-side trace. → Note as attempted, low urgency.
2. **Partially evaded**: some BLOCKs mixed with ALLOWs carrying mutated payloads (`/**/`, case-mix) — verify app logs for query errors during that window.
3. **Likely successful**: response-size/content delta matching true/false payloads; 500s with DB error strings; auth success events after bypass payload; consistent multi-second latency spikes for time-based requests; data appearing in later outbound traffic/DNS names.
4. **Confirmed exfiltration**: sensitive values found outside the app (your OOB collector, leaked in responses, unexpected downloads).

Response-code heuristic: `200` on tautology vs `200-but-empty/redirect` on contradiction = boolean oracle active. Latency histogram shift ≈ sleep value = time oracle active.

## 5. Attacker Tracking & Campaign Correlation

- Cluster by source IP + JA3/fingerprint + payload-set signature; sqlmap leaves a recognizable payload library ordering and often `--batch` timing regularity.
- Multi-stage campaigns: recon quotes → ORDER BY → UNION → info_schema → dump. Seeing stage N means stage N+1 is coming — preemptively patch that parameter.
- Track distributed scans (many IPs, same payload) separately from targeted single-IP deep extraction (higher priority — someone chose this target).

## 6. Incident Report Skeleton

```markdown
## SQLi Attempt — <app> — <date range>
- Vectors observed: <params/endpoints>
- Techniques seen: <recon/blind/union/...>, first/last timestamps
- Volume: <requests, unique payloads, source IPs>
- Outcome classification: Blocked / Partially evaded / Likely successful / Confirmed exfil (+ evidence)
- Server-side corroboration: <app errors, auth events, latency, OOB hits>
- Actions taken: <rules deployed, param fixed, creds rotated if bypass succeeded>
- Remediation owner/deadline: <parameterized query fix tracking>
```

MITRE ATT&CK mapping: T1190 (Exploit Public-Facing App), T1505.003 (Web Shell, if write primitives succeeded), T1059.007 (script-generated injection loops), T1041 (exfil over C2 if OOB). OWASP WTE: A03 Injection. NIST CSF: DE.CM-1/DE.AE-2, RS.MA-1.

## 7. Hardening Signals Worth Alerting On Going Forward

Deploy detection-first rules for the *posture gaps* attackers probe: `xp_cmdshell` enable attempts, `secure_file_priv` reads, `CREATE USER`/`sp_addsrvrolemember` stacked statements, `LOAD_FILE('/etc/` patterns, and any DDL from the app's DB account — these should never appear from application traffic regardless of WAF state.

## 8. Access-Log Grep Recipes (quick triage)

Raw Apache/Nginx access logs — first-pass hunting before pulling WAF event data:

```bash
# Keyword presence in any request (high false-positive rate; triage by endpoint/UA/IP)
grep -iE "union.*select|select.*from|information_schema|sleep\(|benchmark\(|waitfor|pg_sleep|extractvalue|updatexml|load_file|into ?outfile|-- |#|%27|%2527" /var/log/apache2/access.log

# Tighter pattern set: hex literals, quoting, concat/char construction
grep -E "(0x[0-9a-f]{6,}|'.*'|\".*\"|concat\(|char\()" /var/log/apache2/access.log

# Time-based campaign signature: repeated sleep/delay payloads
awk '{print $4, $7}' /var/log/apache2/access.log | grep -iE "sleep|waitfor|pg_sleep|benchmark"

# Same-parameter hammering across many encodings of one keyword = filter-testing behavior
grep -oE "\?id=[^&]*" access.log | sort | uniq -c | sort -rn | head
```

Correlate hits with response-status deltas (200-with-data vs 500 vs 403) to separate blocked recon from successful evasions — see §4 success determination.

## 9. Hardening Recipes (mirror into remediation sections)

**Least-privilege DB account for the web user:**

```sql
CREATE USER 'webapp'@'localhost' IDENTIFIED BY '<strong-secret>';
GRANT SELECT, INSERT, UPDATE ON myapp.users TO 'webapp'@'localhost';
REVOKE FILE ON *.* FROM 'webapp'@'localhost';      -- kills LOAD_FILE/OUTFILE
REVOKE PROCESS, SUPER ON *.* FROM 'webapp'@'localhost';
-- MSSQL equivalent: deny sysadmin; do not grant CONTROL SERVER; keep xp_cmdshell disabled
-- PostgreSQL: no superuser, no pg_read_server_files/pg_write_server_files roles, no TO PROGRAM
```

**ModSecurity signature (CRS-style):**

```apache
SecRule ARGS "@detectSQLi" \
    "id:1001,phase:2,block,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'attack-sqli'"
```

**AWS WAF SQLi match statement (JSON outline):** `Statement.SqliMatchStatement` with `FieldToMatch.AllQueryArguments` + `TextTransformations: [URL_DECODE, HTML_ENTITY_DECODE]`, `Action: Block`. Add transforms for body/headers/cookies too — attackers migrate to whichever field isn't inspected (see header-injection probes in `SKILL.md` §9).

**Application error handling:** return generic messages; log the real exception server-side only (`return "An error occurred."` — never `str(e)` to the client). Verbose DB errors are a free fingerprinting oracle (§Detection regexes above rely on them leaking).

**Code-level examples for reports** (show developers the exact diff): vulnerable `query = f"SELECT * FROM users WHERE id = {user_id}"` → fixed `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`; equivalents via PDO `prepare/execute`, JDBC `PreparedStatement.setString`, C# `SqlCommand` parameters. Include this snippet pair in every finding's remediation block.
