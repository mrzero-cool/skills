# Severity rubric, high-risk triggers, checklist, and anti-patterns

## Severity rubric

- **Critical** — immediate or near-term risk of major compromise, data leakage, system takeover, or regulatory exposure. Urgent action.
- **High** — significant risk that could lead to compromise under realistic conditions. Remediate before production or major release.
- **Medium** — real weakness with moderate impact, or requiring specific conditions to exploit.
- **Low** — minor weakness or hardening opportunity.
- **Informational** — best-practice recommendation or future-proofing note.

Weigh likelihood, impact, exploitability, privileges required, user interaction needed, blast radius, data sensitivity, detectability, recoverability, and any existing compensating controls — not how alarming the pattern name sounds.

Deployment stage shifts these ratings, not just the remediation timeline. The same missing control can be Low in an internal prototype nobody but the team can reach, Medium in an internal beta, and Critical in internet-facing production handling regulated data — because likelihood and blast radius both scale with exposure. Ask (or state as an assumption) which stage the system is at before finalizing severities, and say explicitly if a rating would change at a later stage ("Medium now; reassess as High before this goes internet-facing").

## High-risk change triggers

Apply extra scrutiny when a change introduces any of these:

- New public endpoint or administrative interface
- New third-party integration or external-facing webhook/callback
- New access to sensitive data, or new data export capability
- New authentication or authorization flow
- New secret, key, or certificate usage
- New event topic/queue with broad access
- New AI agent, tool execution, or dynamic code path
- New network exposure or firewall change
- New tenant-sharing infrastructure
- New CI/CD pipeline with production credentials
- New data retention or deletion behavior
- New privileged access path

## Anti-patterns worth calling out explicitly

- Shared credentials across users, services, or environments
- Secrets in code, images, or unencrypted config
- Overly broad IAM roles or service accounts
- Implicit trust based solely on network location
- Flat network with no segmentation
- Direct database access from untrusted clients
- Admin functionality embedded in the regular application plane
- Missing authorization checks on object access
- Cross-tenant access due to missing tenant scoping
- Sensitive data in logs, errors, metrics, or LLM prompts
- Unauthenticated or unsigned webhooks; unvalidated redirects/callbacks
- JWTs without audience, issuer, expiration, or signature validation
- Long-lived tokens with no revocation strategy
- Missing rate limiting on auth or expensive operations
- Standing privileged production access instead of just-in-time
- Mutable servers / manual configuration drift
- Unsigned or unverified deployment artifacts; missing dependency/image scanning
- CI pipelines with broad production credentials
- Event topics with unrestricted publish/subscribe
- Unencrypted or uncontrolled backup data
- Missing audit logging for privileged actions
- Controls that can't actually be tested or monitored
- Overreliance on a single perimeter control
- Treating AI model output as trusted input or a trusted command

## Pre-writeup checklist

Skim this before finalizing findings — it's a net to catch what the phase-by-phase review might have skipped, not a script to follow line by line.

**Scope/context:** purpose and criticality clear · assets and sensitivity identified · compliance obligations known · trust boundaries identified · third-party dependencies listed · prior incidents considered.

**Identity/authN:** all users and services authenticated · MFA on privileged access · tokens scoped/expiring · sessions revocable · service accounts least-privilege · break-glass access controlled and logged · deprovisioning timely.

**Authorization:** deny-by-default · object-level and tenant-level checks enforced · checked at every trust boundary · admin actions separately protected · negative-case tests exist.

**Network:** public exposure minimized · egress restricted where possible · internal traffic segmented · service-to-service auth exists even inside trusted networks · admin plane isolated.

**Data protection:** classification complete · minimized · retention/deletion enforced · encrypted in transit (and at rest where appropriate) · keys separated from data · export paths controlled and audited · personal data locatable and deletable.

**Secrets/keys:** dedicated manager, not hardcoded · least-privilege and rotated · access audited · short-lived where possible · recovery/revocation process exists · no unjustified custom crypto.

**API/app:** external endpoints authenticated and authorized · input validated at boundaries · rate limits and quotas applied · webhooks signed and replay-protected · errors don't leak details · idempotency considered for state-changing ops.

**Infra/CI-CD:** IaC scanned and policy-checked · environments separated · least-privilege workloads · trusted image/artifact sources · patching automated · deployment credentials short-lived · SBOM/provenance where appropriate · release gates for high-risk changes.

**Messaging/events:** brokers authenticated and encrypted · topic-level authorization · schema validation · consumers idempotent · dead-letter queues secured.

**Webhooks/integrations:** sender authenticated and payloads signed · replay/timestamp protection · outbound URLs allowlisted · egress filtered · delivery attempts logged · dead-letter handling defined.

**Multi-tenant:** tenant context enforced on every request, not just at the edge · object-level checks include tenant ownership, not just user identity · caches/queues/search indexes isolated per tenant · cross-tenant access covered by automated tests · tenant-level quotas prevent noisy-neighbor abuse.

**AI/agentic:** untrusted content (user input, retrieved documents, tool results) can't act as an implicit command channel · tool permissions scoped per-tool, not inherited broadly by the agent · destructive or high-value actions require explicit structured confirmation, not inference from freeform text · model output validated before the system acts on it · agent/tool-call activity logged separately from the conversation transcript.

**Observability/IR:** logs centralized and tamper-resistant · sensitive data redacted from logs · alerts on high-risk events · runbooks and revocation/containment paths exist · backups tested.

**Privacy/compliance:** personal-data flows documented · consent/lawful basis reflected where needed · subject access/deletion technically supported · retention enforced · third-party sharing minimized.
