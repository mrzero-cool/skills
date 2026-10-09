# Sources & References

Primary references used to build this skill. The four community skills below were merged into the procedure and `references/` files; upstream canonical sources are listed after them.

## Community Claude/Hack Skills (integrated)

1. **zebbern/claude-code-guide — sql-injection-testing SKILL** — https://github.com/zebbern/claude-code-guide/blob/main/skills/sql-injection-testing/SKILL.md
   Contributed: phase-based workflow (Detection → Exploitation → Auth Bypass → Filter Bypass), inputs/prerequisites + deliverables framing, evidence artifacts, constraints/guardrails (no destructive queries, stop on production data), worked examples format, troubleshooting matrix. → shaped `SKILL.md` intro/checklist and "Report Evidence" section.
2. **mukul975/Anthropic-Cybersecurity-Skills — detecting-sql-injection-via-waf-logs SKILL** — https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/skills/detecting-sql-injection-via-waf-logs/SKILL.md
   Contributed: defensive log-analysis angle, OWASP classification, campaign correlation, incident reporting, NIST CSF / MITRE ATT&CK tagging. → became `references/waf-log-detection.md`.
3. **yaklang/hack-skills — sqli-sql-injection SKILL (+ SCENARIOS.md, SQLMAP_ADVANCED.md)** — https://github.com/yaklang/hack-skills/tree/main/skills/sqli-sql-injection
   Contributed: routing-style progressive disclosure, DBMS clue→action table, OOB exfiltration, second-order, INSERT/UPDATE/DELETE contexts, parameterized-query bypass scenarios, WAF bypass matrix, tamper chain recipes, GraphQL/DB2/Cassandra coverage. → `references/advanced-techniques.md`, `references/sqlmap-advanced.md`, SKILL §0/§8/§10.
4. **NeaByteLab/SQL-Injection-Manual** — https://github.com/NeaByteLab/SQL-Injection-Manual (Guides 01–22, esp. 10 Advanced, 13 Alternative Contexts, 22 Cheat Sheet)
   Contributed: stacked-query support table, per-DBMS file read/write matrices, privilege checks, pivoting, JSON/XML/header/cookie injection + JSON-operator WAF bypass, multi-DBMS cheat-sheet tables. → `references/dbms-cheatsheet.md`, `references/advanced-techniques.md`, SKILL §9.

## Canonical Technique Sources

5. **HackTricks — SQL Injection** — https://hacktricks.wiki/en/pentesting-web/sql-injection/index.html (incl. MSSQL/PostgreSQL/Oracle/SQLite sub-pages)
6. **PayloadsAllTheThings — SQL Injection** — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection (README + MSSQL/MySQL/Oracle/PostgreSQL/SQLite/Cassandra/DB2/SQLmap pages)
7. **PortSwigger Web Security Academy — SQL Injection Cheat Sheet** — https://portswigger.net/web-security/sql-injection/cheat-sheet
8. **OWASP — SQL Injection Prevention Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
9. **pentestmonkey — SQL Injection Cheat Sheet** — https://pentestmonkey.net/cheat-sheet/sql-injection
10. **payloadbox/sql-injection-payload-list** — https://github.com/payloadbox/sql-injection-payload-list
11. **kleiton0x00/Advanced-SQL-Injection-Cheatsheet** — https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet
12. **Encod3d-Sec/TORCH SQLi cheatsheet** — https://raw.githubusercontent.com/Encod3d-Sec/TORCH/refs/heads/main/wiki/cheatsheets/sql-injection.md

## WAF Bypass & Automation

13. **sqlmap Tamper Scripts list** — https://github.com/sqlmapproject/sqlmap/wiki/Tamper-scripts
14. **sqlmap Usage wiki** — https://github.com/sqlmapproject/sqlmap/wiki/Usage
15. **PayloadsAllTheThings — Generic WAF Bypass page** — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/WAF%20Bypass%20and%20UNIONs
16. **G5 Cyber Security — SQLMap WAF Bypass guide** — https://blog.g5cybersecurity.com

## Skill Format

17. **Claude Code Skills documentation** — https://code.claude.com/docs/en/skills (frontmatter fields, progressive disclosure via `references/`)
