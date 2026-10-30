# Risk Register - EvidenceChain v0.1.1

- Input digest: `sha256:781d1dce03258e75687dacb76382bed268ba0b83313e1c84d24b8dd54173610e`
- **10** raw findings deduplicated into **8** unique risks (2 duplicates merged)
- Independent verdict: **PASS** (4 checks)

## 1. Executive summary

- Top priority: **R-001 Out-of-bounds write in image parser** (critical, CVSS 9.1, priority score 9.1, asset svc-frontend-02)
- Severity distribution: critical 2 / high 2 / medium 3 / low 1
- In short: 10 findings scattered across assessment stages are consolidated into 8 ranked, actionable conclusions. Every conclusion is traceable to the exact input artifact line (`file:line`). No network calls at any point.

## 2. Risk register (sorted by priority score)

| Rank | ID | Title | Asset | Severity | CVSS | Priority | Reachability | Stages | Evidence | Remediation |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | R-001 | Out-of-bounds write in image parser | svc-frontend-02 | critical | 9.1 | 9.1 | network | stage2_scan | stage2_scan.jsonl:1, stage2_scan.jsonl:2 | Upgrade image parser to 3.2.1 |
| 2 | R-002 | Backup snapshots stored on public bucket | bucket-backup-01 | high | 8.1 | 8.1 | network | stage1_recon, stage3_manual | stage1_recon.jsonl:2, stage3_manual.jsonl:2 | Make bucket private and rotate backup credentials |
| 3 | R-003 | HTTP/2 Rapid Reset request flood | svc-api-01 | high | 7.5 | 6.0 | network | stage2_scan | stage2_scan.jsonl:3 | Apply stream mitigation patch and raise worker limits |
| 4 | R-004 | Legacy TLS 1.0 permitted on edge gateway | gw-edge-01 | medium | 5.3 | 4.24 | network | stage1_recon | stage1_recon.jsonl:1 | Disable TLS 1.0/1.1 and require TLS 1.2+ |
| 5 | R-005 | Service account key committed to config repository | repo-config | critical | 9.0 | 2.7 | local | stage3_manual | stage3_manual.jsonl:1 | Revoke and rotate the key, then purge repository history |
| 6 | R-006 | Weak cipher suite negotiated on legacy endpoint | svc-api-01 | medium | 5.9 | 1.77 | adjacent | stage3_manual | stage3_manual.jsonl:3 | Restrict to ECDHE-RSA-AES256-GCM |
| 7 | R-007 | Debug logging enabled in edge agent | gw-edge-01 | medium | 4.3 | 1.29 | adjacent | stage1_recon | stage1_recon.jsonl:3 | Disable verbose logging in production |
| 8 | R-008 | Missing HSTS header on public endpoint | gw-edge-01 | low | 3.1 | 0.62 | network | stage2_scan | stage2_scan.jsonl:4 | Add Strict-Transport-Security header |

## 3. Independent verdict

| Check | Result | Detail |
|---|---|---|
| ordering_matches_recomputed | PASS | order matches recomputation |
| no_duplicate_keys | PASS | no duplicate dedup keys |
| evidence_present | PASS | every conclusion carries an evidence row |
| cvss_within_range | PASS | all CVSS scores within 0..10 |
