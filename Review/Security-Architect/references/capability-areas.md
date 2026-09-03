# Capability areas — domain-by-domain review guidance

Read the sections that apply to the system under review. Each section lists what to look at, what to evaluate, and what to recommend when something's missing.

As you work section by section, keep tagging confidence the way SKILL.md describes — code/config gives you `Confirmed` findings, an absence in a diagram or doc is `Inferred — verify` and belongs in Open Questions, not a finding with an invented severity.

## Identity and access architecture

Review: user auth, service-to-service auth, workload identity, admin access, federated identity, partner access, API client auth, session management, token lifecycle, privileged access management.

Evaluate: OAuth2/OIDC design; JWT structure, validation, expiration, audience, issuer, scope enforcement; MFA and adaptive auth; SSO/federation; SCIM provisioning/deprovisioning; RBAC/ABAC/ReBAC; service account lifecycle; token revocation and refresh-token security; break-glass access; separation between user/service/admin planes.

Recommend: short-lived, audience-restricted tokens; MFA (or stronger) on privileged and admin access; centralized session/token revocation; workload identity over long-lived service credentials; automated, timely deprovisioning tied to HR/directory changes; separately audited break-glass paths.

Key questions: Is every actor strongly authenticated? Are permissions scoped to the minimum needed? Are tokens short-lived and audience-restricted? Are admin actions separately protected and audited? Can a compromised service or token move laterally? Is deprovisioning timely?

## Authorization and access control

Review: authorization decision/enforcement points, object-level access control, tenant isolation, role design, permission boundaries, delegated access, impersonation, resource ownership, consent.

Evaluate: deny-by-default posture; centralized authorization logic; separation of duty; re-evaluation of permissions on every access (not cached-forever); protection against horizontal/vertical privilege escalation and cross-tenant access; policy-as-code where it fits.

Recommend: centralized policy engine, resource-level permissions, tenant-scoped queries, claim-based access control, enforcement at both gateway and service layer, authorization tests in CI.

## Network security architecture

Review: public exposure, ingress/egress controls, VPC design, subnet segmentation, DNS policy, firewall rules, load balancer security, service mesh, east-west controls, DDoS protection, WAF placement.

Evaluate: are internal services unnecessarily reachable? Are third-party calls controlled and monitored? Is the admin plane isolated? Can workloads reach the internet when they don't need to? Is service-to-service auth still required even with network controls in place (it should be)?

Key principle: network segmentation is not a substitute for authentication and authorization.

For environment-specific vocabulary and gotchas (VPC vs VNet vs on-prem VLAN, cloud-specific misconfigurations, Kubernetes NetworkPolicy, OT/ICS network concerns), see `references/environment-notes.md`.

Recommend: default-deny network policies between tiers, admin-plane isolation from the application plane, egress filtering/allowlisting for outbound calls, service-to-service auth (mTLS or workload identity) enforced regardless of network placement, DDoS protection and WAF at the edge.

## Data protection and privacy

Review: data classification, minimization, retention, deletion, residency, lineage; encryption at rest/in transit/in use; tokenization, masking, anonymization/pseudonymization; backup and archive protection; data export controls.

Evaluate: is sensitive data classified? Is it unnecessarily copied or logged? Are retention/deletion enforceable? Can personal data be discovered, exported, and deleted on request? Do third parties receive only what they need?

Key questions: where does sensitive data enter, where does it live (storage, cache, logs, replicas, exports), who can access it, how is it protected through its full lifecycle?

Recommend: explicit data classification tied to handling requirements, encryption at rest and in transit by default, minimization before logging or caching, enforceable retention/deletion (including in backups and replicas), scoped and audited data-export paths, least data shared with third parties.

## Cryptography and key management

Review: TLS config, certificate management, algorithms, key hierarchy/generation/storage/rotation/revocation, key access auditing, envelope encryption, customer-managed keys, HSM/KMS usage, crypto agility.

Evaluate: is TLS 1.2+ enforced (ideally 1.3) with modern cipher suites? Are keys separated from the data they encrypt? Is key access least-privilege and audited? Is there a defined rotation cadence and a recovery path for lost or compromised keys? Any homegrown or unmaintained cryptography?

Recommend: TLS 1.2+ (prefer 1.3), strong cipher suites, automated certificate renewal, KMS-backed envelope encryption, per-tenant/per-environment keys where risk warrants it, and a migration path for algorithm changes. No homegrown cryptography without strong justification.

## Secrets management

Review: secret storage, rotation, injection, access auditing, break-glass secrets, developer access, service credentials, API keys, certs, tokens, DB credentials, cloud credentials.

Evaluate: secrets in code, config, env vars, images, logs, or CI output; overly broad access; manual handling; missing rotation or audit logging; secrets shared across environments/teams.

Recommend: dedicated secret manager/vault, short-lived credentials, workload identity instead of long-lived keys, automatic rotation, environment separation, least-privilege access, alerting on unusual access.

## API and application security

Review: public/internal APIs (REST, GraphQL, gRPC, WebSocket, webhooks), authN/authZ at boundaries, input validation, output encoding, rate limiting, replay protection, CORS, CSRF, CSP, file upload handling, redirect validation, error handling, API versioning/deprecation.

Evaluate: missing auth, overly broad scopes, excessive data exposure, missing rate limits, insecure direct object references, business-logic abuse, insecure webhooks, unvalidated redirects, sensitive data in errors/logs, missing idempotency on state-changing operations.

Recommend: strong input validation and output encoding at every boundary, least-privilege API scopes, rate limiting by user/client/tenant/IP, object-level authorization on every request (not just endpoint-level), restrictive CORS, generic error messages that don't leak internals, idempotency keys for state-changing operations.

## Webhook and integration security

Review: incoming/outgoing webhooks, third-party callbacks, event subscriptions, partner integrations, OAuth redirect URIs, data export/file-transfer endpoints.

Evaluate: sender authentication, signature validation, timestamp/replay protection, idempotency, retry handling, URL allowlisting, egress filtering, payload data minimization, delivery logging, dead-letter handling.

Recommend: HMAC (or equivalent) signatures, nonce/timestamp validation, secure storage of webhook secrets, scoped integration permissions, anomaly monitoring.

## Event-driven and messaging security

Review: producers/consumers, topics/queues, schema validation, broker access control, message encryption, retention, replay capability, dead-letter/poison-message handling, audit events.

Evaluate: unauthorized publish/subscribe, event tampering, sensitive data in events, replay attacks, missing topic-level authorization or schema enforcement, non-idempotent consumers.

Recommend: mTLS (or equivalent) broker auth, topic-level authorization, schema validation, encryption in transit/at rest, event minimization, idempotent consumers, secured dead-letter queues, audit logging for sensitive events.

## Cloud-native and container security

Review: Kubernetes, container images, serverless functions, cloud IAM, cloud networking, managed DBs, object storage, cloud logging, service accounts, admission controllers, runtime security.

Evaluate: excessive container privileges, missing pod security standards or network policies, insecure image sources, missing image scanning, secrets mounted too broadly, public storage buckets, overly permissive cloud roles, missing quotas or runtime monitoring.

Recommend: least-privilege workload identity, private registries/trusted base images, image signing and admission control, Pod Security Standards, default-deny network policies, encrypted secrets at rest, egress restrictions, runtime anomaly detection, IaC policy checks.

## Infrastructure, CI/CD, and supply chain

**Infrastructure:** IaC, golden images, patch management, immutable infrastructure, admin/bastion access, metadata service exposure, OS hardening, environment separation, DR. Watch for manual server changes, shared admin credentials, overexposed management ports, untested backups.

**CI/CD and supply chain:** source control protections, branch protection, code review requirements, signed commits, dependency management, build pipeline isolation, artifact registry, image signing, deployment approvals, CI secret access, third-party actions/plugins. Watch for pipelines with overly broad production credentials, unsigned artifacts, missing dependency/SBOM/provenance checks, untrusted third-party build steps.

Recommend: branch protection + required review, signed commits/verified provenance, dependency and secret scanning, isolated build agents, short-lived deployment credentials, artifact signing, SBOM generation, SLSA-aligned controls, release gates for high-risk changes.

## Observability, audit, and incident readiness

**Observability:** application/infra/identity/network/DB audit/API logs, security alerts, SIEM integration, trace correlation. Watch for missing authN/authZ logs, sensitive data in logs, tamper-prone storage, short retention, missing alerting on high-risk events, inability to attribute actions.

**Incident response and resilience:** detection, containment, revocation, isolation, backup/restore, communication plan, forensic readiness, DR, chaos/failure testing. Key questions: can access be revoked quickly? Can a compromised component be isolated? Can secrets rotate without downtime? Can data be restored from clean backups? Is there a runbook for likely incidents?

Recommend: centralized tamper-resistant logging, a security event taxonomy, alerting on anomalous auth/privilege-escalation/data-export/secret-access, correlation IDs, admin action audit logs, IR runbooks, break-glass procedures, tested backup restoration, tabletop exercises, post-incident review.

## Multi-tenant and SaaS security

Review: tenant isolation strategy, tenant-scoped data access, cross-tenant authorization checks, tenant-specific encryption, tenant admin controls, tenant data export/deletion, tenant-level audit logs and quotas.

Evaluate: risk of horizontal privilege escalation, missing tenant identifier in queries, shared storage paths without authorization checks, missing tenant-scoped logging, inadequate isolation in caches/queues/search indexes, missing noisy-neighbor safeguards.

Recommend: enforce tenant context on every request via centralized middleware, integration tests for cross-tenant access attempts, tenant-level quotas/throttling, separate keys or storage boundaries for high-risk tenants.

## AI and agentic system security

Review: prompt injection risk, tool execution risk, RAG data access, model output handling, data leakage into prompts/logs, model supply chain, agent permissions, human approval workflows, sandbox isolation, abuse/automation risk.

Evaluate: can untrusted input influence tool calls, queries, or code execution? Can the agent reach secrets, internal APIs, or sensitive data it doesn't need? Are tool permissions scoped and audited? Are model outputs validated before the system acts on them? Is user content sanitized before retrieval or execution? Can a malicious document or message cause exfiltration?

Recommend: least-privilege agent identities, a separate tool-execution sandbox, explicit user consent for sensitive actions, human approval for destructive/high-risk operations, output validation, content provenance tracking, retrieval authorization checks, prompt-injection defenses as one layer among several (not the sole control), red-teaming for agent workflows.

## Compliance and governance

Review: control mapping to standards, evidence collection, policy enforcement, exception management, risk acceptance, security decision records, architecture governance, audit readiness.

Evaluate: are security requirements documented and testable? Are exceptions tracked and time-boxed? Are architecture decisions recorded? Do compliance obligations show up in the design itself, not just in a policy document?

Recommend: Security Decision Records, policy-as-code where feasible, clear control ownership, periodic architecture review, a maintained risk register, automated evidence collection.
