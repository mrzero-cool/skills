# Input analysis — reading diagrams, documents, and mixed evidence

Read this at the start of a review whenever the input includes a diagram, a document, or a mix of artifacts, before applying the review method in SKILL.md. It's about how to read what you were given, not about scoring what it means — that's the Evidence handling section in SKILL.md, which this feeds into.

## Step 1: Identify the artifact set

- **Diagram only** — extract visible topology, components, flows, zones, actors, trust boundaries. An omitted control isn't a confirmed absence unless the diagram itself proves the absence (see SKILL.md's Evidence handling).
- **Diagram plus documents** — the diagram is the map, the documents are control evidence. Only promote an open question to a `Confirmed` finding when a document actually supports that conclusion, not because the diagram left it ambiguous.
- **Documents only** — reconstruct the architecture before judging it: actors, systems, data stores, flows, identities, trust boundaries, controls, assumptions, unresolved decisions, owners.
- **Architecture plus code/IaC/config** — code, IaC, IAM policies, bucket policies, security groups, and manifests are stronger evidence than diagrams or prose, and should raise your confidence accordingly. Per this skill's scope, keep the write-up at architecture level even when strong code-level evidence is present — line-by-line review belongs to a dedicated code/IaC skill; use the config here to confirm or rule out architectural findings, not to produce a line-item code review.

## Step 2: If there's a diagram, identify its type

Don't assume every diagram is a web/cloud topology — the review approach shifts with the notation:

- **C4 context/container/component** — people, systems, apps, services, databases, queues, internal components.
- **UML deployment/component/sequence/activity** — nodes, runtimes, modules, interfaces, workflows, call order.
- **Data-flow diagram** — processes, stores, external entities, flows, trust boundaries.
- **ERD/database architecture** — entities, schemas, relationships, storage ownership, data sensitivity.
- **Identity/access-flow diagram** — IdPs, tokens, claims, roles, sessions, consent, delegated access.
- **Integration/event/message-flow diagram** — webhooks, APIs, queues, topics, partners, file transfers, retries, dead letters.
- **Data pipeline/analytics/ML diagram** — ingestion, lake/warehouse, transforms, BI, model training/inference, exports, lineage.
- **Enterprise architecture** — business capabilities, platforms, shared services, ownership, governance, critical dependencies.
- **Mobile/client-server architecture** — mobile/desktop clients, APIs, local storage, sync, push services, device trust.
- **IoT/OT/embedded architecture** — devices, gateways, field networks, firmware, cloud ingestion, management plane, safety impact.
- **Cloud infrastructure diagram** — accounts, regions, VPCs, subnets, managed services, IAM, storage, compute, observability.
- **Network topology diagram** — zones, firewalls, routers, VPNs, subnets, endpoints, traffic paths.
- **Business process with technical controls** — human/system workflows, approvals, separation of duties, auditability, exception paths.

If the notation is ambiguous, state your likely interpretation and ask for the source diagram, legend, or a supporting document — don't silently pick one reading.

## Step 3: Extract review facts

Regardless of artifact type, pull out:

- Purpose, business criticality, users, administrators, service accounts, tenants, partners, devices, automated agents.
- Systems, services, apps, functions, data stores, queues, caches, files, external dependencies, control-plane services.
- Data flows, control flows, admin flows, async events, uploads/downloads, third-party callbacks, trust delegation.
- Trust boundaries: public/internal, tenant, admin/user, regulated-data, partner, environment, workload, device, physical.
- Security controls that are explicitly shown or stated.
- Ambiguous symbols, unlabeled arrows, missing protocols, unresolved design choices, missing evidence.

This is the raw material for the Context/scope and Asset/data-flow phases of the review method — do this extraction before starting phase 3 (threat modeling).

## Output guidance

A review that's clearly grounded in its input says so. Include, briefly:

- What artifacts were actually reviewed, and the diagram/document type if relevant.
- What was reconstructed from the artifacts (for documents-only input) versus what was directly visible.
- Confirmed strengths and confirmed gaps, kept distinct from open questions.
- The exact artifact that would convert a given open question into a confirmed finding (a specific policy, config file, or doc — not just "more information").