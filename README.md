# OT/ICS Threat Hunt Plans

A purpose-built repository of high-fidelity OT/ICS threat hunt plans generated from current cybersecurity advisories and vendor product security bulletins.

This project is designed for SOC, OT security, and incident response teams that need to move from advisory to action quickly, with hunt content that is practical, structured, and ready for real environments.

## Why This Repo Exists

Industrial environments are increasingly targeted, but advisory information is often fragmented across CISA ICS notices, vendor disclosures, and vulnerability databases. This repository transforms those sources into hunt-ready plans that help teams:

- Translate CVEs and advisory language into concrete detection hypotheses.
- Align OT and IT telemetry for cross-domain investigation.
- Standardize hunt execution and reporting across facilities.
- Reduce time-to-hunt during active risk windows.

## What You Will Find Here

Each hunt plan is authored in Markdown for easy review, version control, and rapid collaboration.

Typical plan content includes:

- Objective and scoped hunt window.
- Threat hypotheses mapped to attacker behavior.
- Collection queries for endpoint, network, and OT data sources.
- Analysis queries for triage, enrichment, and anomaly detection.
- Detection logic and signatures (for example SIGMA, Suricata/Snort, YARA where applicable).
- False-positive baselines and validation guidance.
- Escalation criteria and completion/reporting criteria.

## Repository Structure

```text
.
|-- 2026/
|   `-- *.md
`-- README.md
```

Year-based folders organize hunt plans by publication and operational cycle.

## What Makes These Hunt Plans Different

- Advisory-anchored: built directly from current ICS/security disclosures.
- OT-realistic: tuned for BACnet/Modbus/industrial workflows and change windows.
- Detection-first: prioritizes actionable telemetry and investigation pivots.
- Collaboration-ready: GitHub-native Markdown for peer review and iteration.
- Execution-oriented: focused on analyst usability, not just documentation depth.

## Intended Audience

- OT SOC analysts
- ICS incident responders
- Security engineering teams supporting critical infrastructure
- Plant/site cyber defenders and OT network owners
- Purple team and threat hunting program leads

## How To Use This Repo

1. Select the hunt plan relevant to your environment and affected products.
2. Adapt hostnames, asset scopes, and maintenance windows to local operations.
3. Run collection and analysis steps in your security tooling.
4. Validate findings against known-good baselines and approved change records.
5. Escalate according to documented criteria and record outcomes in your case workflow.

## Quality Bar

Plans in this repository are expected to be:

- Technically faithful to source advisories.
- Explicit about assumptions and telemetry prerequisites.
- Structured for reproducibility across teams and sites.
- Written to support both retroactive and live-hunt operations.

## Roadmap

- Expand coverage across major OT/ICS vendor advisory streams.
- Add metadata headers for easier indexing and automation.
- Introduce template-driven plan generation for consistent formatting.
- Add crosswalks to ATT&CK for ICS and common SIEM platforms.

## Contribution Model

Contributions should preserve technical accuracy and operational clarity.

When proposing updates, prioritize:

- No drift from source advisory facts.
- Clear query syntax and tool compatibility notes.
- Precise escalation and completion criteria.
- Readable Markdown optimized for GitHub review.

## Operational Note

Threat hunt plans are decision-support artifacts. Final incident determination should include analyst validation, environment context, and approved operational change records.
