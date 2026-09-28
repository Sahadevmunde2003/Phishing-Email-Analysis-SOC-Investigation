# Project Roadmap

## Vision
Evolve the phishing email analyzer from an offline training utility into a practical SOC investigation platform that supports threat intelligence, analyst workflows, reporting, and controlled integrations.

## Phase 1 — Core Analysis & Usability
- [x] .eml parsing
- [x] Sender / Reply-To mismatch detection
- [x] Suspicious URL heuristics
- [x] Attachment inventory
- [x] IOC extraction
- [x] Risk scoring and severity
- [x] MITRE ATT&CK mapping
- [x] CLI interface
- [x] Local web GUI
- [x] HTML reporting
- [x] Raw email paste support
- [ ] Improve authentication-result parsing (SPF/DKIM/DMARC)
- [ ] Add structured JSON schema for analysis results
- [ ] Expand automated unit and integration tests

## Phase 2 — Threat Intelligence
- [ ] VirusTotal URL/domain reputation integration
- [ ] URLhaus lookup support
- [ ] Optional WHOIS/DNS enrichment
- [ ] Threat-intelligence confidence and source tracking
- [ ] Environment-variable based API configuration
- [ ] Keep offline analysis available when APIs are unavailable

> API keys must never be committed to the repository.

## Phase 3 — SOC Investigation Dashboard
- [ ] Investigation/case IDs
- [ ] Persistent case history with SQLite
- [ ] Search and filter investigations
- [ ] IOC timeline and analyst notes
- [ ] Severity and status tracking
- [ ] Export case bundles for handoff
- [ ] Dashboard metrics for investigations and findings

## Phase 4 — SIEM Integration
- [ ] Splunk HTTP Event Collector (HEC) integration
- [ ] Normalized event format for SIEM ingestion
- [ ] Configurable index/source/sourcetype
- [ ] Optional IOC and alert forwarding
- [ ] Integration health/error logging

## Phase 5 — Attachment & Artifact Analysis
- [ ] File hash calculation (MD5/SHA-1/SHA-256)
- [ ] MIME/type validation
- [ ] Suspicious macro/script indicator detection
- [ ] Archive inspection with safe limits
- [ ] Optional sandbox/reputation integration
- [ ] Artifact metadata in incident reports

## Phase 6 — Detection Intelligence
- [ ] Feature extraction pipeline for email classification
- [ ] Curated and documented training dataset
- [ ] Baseline ML phishing classifier
- [ ] Precision/recall/F1 evaluation
- [ ] Explainable classification indicators
- [ ] Compare heuristic and ML results

> ML accuracy should be reported from reproducible evaluation data rather than assumed or hard-coded.

## Phase 7 — Analyst Workflow & Controlled Response
- [ ] Analyst verdict: benign / suspicious / malicious
- [ ] Evidence and investigation notes
- [ ] Approval workflow for response actions
- [ ] Optional block/quarantine integrations
- [ ] Audit trail for response actions
- [ ] Safe-by-default controls

Automated deletion, blocking, or quarantine should remain disabled by default and require explicit analyst confirmation.

## Target Architecture

    PHISHING SOC PLATFORM
             |
     +-------+-------+
     |       |       |
    CLI     GUI    REST API
     |       |       |
     +-------+-------+
             |
      Analysis Engine
             |
    +--------+--------+--------+
    |                 |        |
Header Analysis   URL Analysis  Attachment Analysis
    |                 |        |
    +--------+--------+--------+
             |
    Threat Intelligence
             |
       +-----+-----+
       |           |
    IOC Store   MITRE ATT&CK
       |           |
       +-----+-----+
             |
        Risk Engine
             |
     +-------+-------+-------+
     |               |       |
 Dashboard         Reports  SIEM
     |               |       |
     +-------+-------+-------+
             |
      Analyst Decision
             |
     Controlled Response

## Suggested Implementation Order
1. Strengthen raw-email/header analysis and tests.
2. Add optional threat-intelligence lookups.
3. Add SQLite case history and analyst workflow.
4. Add Splunk HEC integration.
5. Add attachment/artifact analysis.
6. Build and evaluate ML detection using a documented dataset.
7. Add analyst-approved response integrations.

## Security & Privacy Principles
- Analyze only authorized emails and samples.
- Keep API credentials in environment variables or a secret manager.
- Do not upload email contents to third-party services unless explicitly enabled.
- Avoid logging sensitive email content unnecessarily.
- Treat external threat-intelligence results as evidence, not absolute truth.
- Preserve original evidence and analysis metadata for investigations.
