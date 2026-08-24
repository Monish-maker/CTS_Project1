"""Actionable remediation guidance for OWASP GenAI LLM Top 10 2026 findings."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelllm.core.enums import AttackCategory


@dataclass(frozen=True, slots=True)
class RemediationGuidance:
    """Concrete controls and checks used to resolve and retest a finding."""

    missing_control: str
    immediate_actions: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    validation_steps: tuple[str, ...]


_GUIDANCE: dict[AttackCategory, RemediationGuidance] = {
    AttackCategory.PROMPT_INJECTION: RemediationGuidance(
        "Trusted instructions and untrusted content are not strongly separated.",
        (
            "Disable or require approval for sensitive tool actions reachable from affected "
            "prompts.",
            "Block the verified payload pattern while a durable control is deployed.",
        ),
        (
            "Place system instructions, retrieved content, and user input in explicitly "
            "separated fields.",
            "Treat retrieved documents and tool output as untrusted data, never as executable "
            "instructions.",
            "Enforce authorization in application code for every tool call and sensitive "
            "operation.",
            "Add input-risk classification and output-policy checks around high-impact workflows.",
            "Use least-privilege tool credentials and require human approval for destructive "
            "actions.",
        ),
        (
            "Replay the linked attack jobs and confirm the controlled marker is not obeyed.",
            "Test direct, indirect, encoded, and role-confusion variants.",
            "Confirm blocked prompts cannot trigger tools or change application state.",
        ),
    ),
    AttackCategory.SENSITIVE_INFORMATION_DISCLOSURE: RemediationGuidance(
        "Sensitive data minimization, access control, or output redaction is insufficient.",
        (
            "Rotate any real credential or secret represented by the verified evidence.",
            "Restrict access to affected conversations, indexes, logs, and model context.",
        ),
        (
            "Remove credentials, personal data, and confidential values from prompts and model "
            "context.",
            "Apply tenant- and user-level authorization before retrieval and prompt construction.",
            "Redact sensitive patterns from model output and diagnostic errors.",
            "Use synthetic canaries to detect future disclosure without exposing real secrets.",
            "Define retention and deletion controls for prompts, responses, embeddings, and logs.",
        ),
        (
            "Repeat the disclosure path with synthetic canaries and confirm they remain "
            "inaccessible.",
            "Test unauthenticated, lower-privilege, cross-user, and cross-tenant contexts.",
            "Verify logs and reports redact authorization, cookies, tokens, and personal data.",
        ),
    ),
    AttackCategory.EXCESSIVE_AGENCY: RemediationGuidance(
        "Tool permissions or approval boundaries allow the model excessive authority.",
        (
            "Disable affected high-impact tools or place them behind mandatory human approval.",
            "Revoke broad service credentials and issue least-privilege replacements.",
        ),
        (
            "Authorize every tool invocation server-side using the authenticated user and "
            "requested resource.",
            "Use allow-listed tools, operations, parameters, destinations, and data scopes.",
            "Separate planning from execution and require confirmation for irreversible "
            "operations.",
            "Limit chained actions, execution duration, transaction size, and cumulative impact.",
            "Record tool requests and outcomes in tamper-resistant audit logs.",
        ),
        (
            "Replay the linked jobs using read-only, standard-user, and expired sessions.",
            "Confirm parameter changes cannot escalate an approved low-impact action.",
            "Verify destructive and multi-step actions require explicit human approval.",
        ),
    ),
    AttackCategory.SUPPLY_CHAIN: RemediationGuidance(
        "Model, dependency, plugin, or data provenance and integrity controls are incomplete.",
        (
            "Quarantine the affected model, plugin, dataset, or artifact until its provenance "
            "is verified.",
            "Pin the last known-good version and block unreviewed updates.",
        ),
        (
            "Maintain an inventory and software bill of materials for models, adapters, plugins, "
            "and libraries.",
            "Pin versions and verify signatures, checksums, licenses, provenance, and publisher "
            "identity.",
            "Scan model artifacts and dependencies before promotion between environments.",
            "Restrict remote code, custom loaders, and third-party plugin execution.",
            "Continuously monitor upstream advisories and define rollback procedures.",
        ),
        (
            "Rebuild from trusted sources and verify all artifact digests.",
            "Repeat provenance and manifest tests with unsigned and mismatched fixtures.",
            "Confirm deployment rejects altered artifacts and unapproved versions.",
        ),
    ),
    AttackCategory.DATA_AND_MODEL_POISONING: RemediationGuidance(
        "Training, tuning, or retrieval data lacks adequate provenance and integrity validation.",
        (
            "Remove or quarantine identified poisoned records and rebuild affected indexes.",
            "Suspend automated ingestion from the implicated source.",
        ),
        (
            "Require source provenance, integrity hashes, review status, and ownership for "
            "ingested data.",
            "Validate, deduplicate, and anomaly-scan training and retrieval content before use.",
            "Separate untrusted submissions from production training and knowledge pipelines.",
            "Use holdout evaluations and canary prompts to detect trigger-dependent behavior.",
            "Version datasets, embeddings, and models so contaminated releases can be rolled back.",
        ),
        (
            "Rebuild the affected model or index from a known-clean snapshot.",
            "Replay conflicting-source, hidden-trigger, and persistence tests.",
            "Confirm removed content no longer influences new sessions or retrieval results.",
        ),
    ),
    AttackCategory.UNBOUNDED_CONSUMPTION: RemediationGuidance(
        "Resource quotas, request bounds, or cost controls are insufficient.",
        (
            "Apply temporary per-user and per-tenant rate limits to the affected endpoint.",
            "Cap input size, output tokens, execution time, and concurrent work immediately.",
        ),
        (
            "Enforce quotas at the gateway and application layers using authenticated identities.",
            "Set model token, recursion, tool-call, retry, and wall-clock limits.",
            "Use bounded queues, backpressure, cancellation, and circuit breakers.",
            "Set cost alerts and reject requests when tenant or global budgets are exhausted.",
            "Cache safe repeated operations and prevent attacker-controlled fan-out.",
        ),
        (
            "Repeat oversized, recursive, amplification, and chained-operation tests.",
            "Confirm limits apply across retries and concurrent requests.",
            "Verify resource use and cost remain within documented budgets.",
        ),
    ),
    AttackCategory.MISINFORMATION: RemediationGuidance(
        "Grounding, uncertainty communication, or authoritative-source validation is insufficient.",
        (
            "Add a user-visible warning or human review step for affected high-impact decisions.",
            "Disable unsupported automatic actions based on the affected output.",
        ),
        (
            "Ground factual answers in approved sources and return traceable citations.",
            "Verify cited documents exist and support the generated claim.",
            "Require calibrated uncertainty or refusal when reliable evidence is unavailable.",
            "Use deterministic business rules for legal, medical, financial, and safety-critical "
            "decisions.",
            "Monitor contradiction, fabrication, and stale-knowledge rates with reviewed datasets.",
        ),
        (
            "Replay unsupported, contradictory, false-authority, and citation tests.",
            "Confirm nonexistent sources are not cited and uncertainty is communicated.",
            "Have domain reviewers validate representative high-impact answers.",
        ),
    ),
    AttackCategory.HIDDEN_CONTEXT_EXPOSURE: RemediationGuidance(
        "Hidden instructions, metadata, or tenant context can cross an intended trust boundary.",
        (
            "Remove secrets and credentials from system prompts and hidden context immediately.",
            "Rotate any exposed value and invalidate affected sessions.",
        ),
        (
            "Keep secrets outside model context and retrieve them only inside authorized "
            "server-side code.",
            "Isolate system instructions, tenants, users, sessions, and memory stores.",
            "Minimize hidden metadata and filter it before constructing prompts or responses.",
            "Apply output checks for prompt fragments, canaries, internal identifiers, and "
            "metadata.",
            "Treat system-prompt secrecy as defense in depth rather than the primary security "
            "control.",
        ),
        (
            "Replay direct, encoded, cross-tenant, and context-window extraction tests.",
            "Confirm synthetic hidden canaries cannot be recovered from any user role.",
            "Verify authorization remains effective even if instruction text is known.",
        ),
    ),
    AttackCategory.VECTOR_AND_EMBEDDING_WEAKNESSES: RemediationGuidance(
        "Retrieval authorization, tenant isolation, or indexed-content validation is insufficient.",
        (
            "Disable retrieval from affected collections or apply a restrictive server-side "
            "filter.",
            "Remove poisoned documents and rebuild impacted embeddings.",
        ),
        (
            "Authorize every retrieved record using tenant, user, role, and document metadata.",
            "Use separate collections or cryptographically enforced namespaces for strong "
            "isolation.",
            "Validate content provenance and strip active instructions before indexing.",
            "Apply retrieval thresholds, source allow lists, and result-count limits.",
            "Log document IDs and authorization decisions for every retrieval operation.",
        ),
        (
            "Repeat cross-tenant, semantic-collision, and poisoned-document retrieval tests.",
            "Confirm unauthorized document IDs never enter model context.",
            "Rebuild and compare the index against a trusted document inventory.",
        ),
    ),
    AttackCategory.IMPROPER_OUTPUT_HANDLING: RemediationGuidance(
        "Model output is passed downstream without context-aware validation or encoding.",
        (
            "Stop passing affected model output directly to browsers, shells, queries, or "
            "interpreters.",
            "Disable automatic execution of model-produced code and commands.",
        ),
        (
            "Treat all model output as untrusted input at every downstream boundary.",
            "Use context-specific HTML encoding, parameterized queries, and argument-safe "
            "process APIs.",
            "Validate structured output against strict schemas and reject unknown fields.",
            "Use allow lists for URLs, file paths, commands, tool names, and function arguments.",
            "Apply content security policy and sandboxing where generated content is rendered.",
        ),
        (
            "Replay HTML, command, query, and malformed structured-output tests.",
            "Confirm output remains inert in every downstream execution context.",
            "Add regression tests at the exact sink referenced by the finding.",
        ),
    ),
}


def remediation_for(category: AttackCategory) -> RemediationGuidance:
    """Return deterministic remediation guidance for one OWASP category."""
    return _GUIDANCE[category]
