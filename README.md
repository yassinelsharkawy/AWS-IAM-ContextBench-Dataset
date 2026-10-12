# AWS-IAM-ContextBench-Dataset

An empirical benchmark of **534 real-world AWS experimental observations** designed for evaluating context-aware risk scoring, machine-learning-based alert triage, and interpretable authorization event prioritization.

This dataset accompanies the IEEE conference research paper:  
**"Evaluating Behavioral Context for Interpretable IAM Policy Risk Scoring in Cloud Environments"**

Paper link: https://arxiv.org/abs/2610.07345

Peer-reviewed and accepted at IEEE Conference ID# 71863; to appear in the IEEE Xplore proceedings.

---

## 1. Overview & Motivation

In cloud security operations centers (SOCs), security analysts triage hundreds of Identity and Access Management (IAM) policy modifications daily. Traditional security tooling relies almost exclusively on static policy analysis—evaluating JSON permission documents, reachability graphs, and wildcard grants.

However, static analysis evaluates only what an identity is *permitted* to do, not the *operational context* under which the authorization event took place. An administrative role attached by an automated CI/CD pipeline presents vastly different operational urgency than the identical policy attached through an unmapped user-agent, without multi-factor authentication (MFA), preceded by reconnaissance API errors.

**AWS-IAM-ContextBench** bridges this gap by decoupling:
- **Intrinsic Security Risk (`gt_security_risk_score`)**: The intrinsic severity and reachability of authorization syntax (invariant between matched pairs).
- **Analyst Review Priority (`gt_analyst_priority_score`)**: The operational urgency with which a security analyst must investigate an authorization event given surrounding behavioral and environmental context.

---

## 2. Benchmark Architecture & Key Invariants

The dataset consists of **534 validated experimental runs** executed against live AWS services in a dedicated research account:

| Dimension / Property | Count | Description / Experimental Invariant |
|:---|:---:|:---|
| **Total Valid Observations** | **534** | Fully audited, leakage-controlled live AWS experimental executions |
| **Type-A Matched Pairs** | **208** (416 samples) | Matched pairs with identical policy syntax, effective authorizations, and infrastructure topology, differing solely in CloudTrail behavioral context |
| **Type-B Environment Pairs** | **39** (78 samples) | Matched policy and behavioral context across distinct infrastructure environments |
| **Unpaired Structural Variants** | **40** | Additional boundary cases and structural policy variants |
| **Scenario Families** | **13** | S01–S13 spanning privilege escalation, data exfiltration, and boundary governance |
| **Policy Lineages** | **96** | Independent policy evolution chains used as grouping units for leakage-free cross-validation |
| **AWS Environments** | **16** | Distinct infrastructure topologies with varying role hierarchies, boundaries, and secrets |
| **Behavior Patterns** | **12** | CloudTrail execution profiles (5 benign operational baselines, 7 adversarial sequences) |
| **Target Variable** | Continuous | Reference review urgency score ($\mu = 20.29, \sigma = 7.84$, range $[4.60, 53.90]$) |

### Controlled Matched-Pair Formulation (Type-A Invariant)
For each Type-A matched pair $(i, j)$:
$$x_{\text{policy}}^{(i)} = x_{\text{policy}}^{(j)}, \qquad x_{\text{env}}^{(i)} = x_{\text{env}}^{(j)}, \qquad x_{\text{behavior}}^{(i)} \neq x_{\text{behavior}}^{(j)}$$
where sample $i$ represents an action executed under suspicious behavioral context (e.g., unauthorized CLI, failed enumeration errors, no MFA) and sample $j$ represents the identical policy applied during benign administration.

---

## 3. Scenario Coverage

The 534 observations cover 13 distinct scenario families across three primary cloud threat categories:

1. **Privilege Escalation**
   - `S01`: `AttachRolePolicy` escalation to administrative roles.
   - `S02`: `CreatePolicyVersion` granting direct administrative privileges.
   - `S03`: `SetDefaultPolicyVersion` rolling forward to over-privileged historical versions.
   - `S04`: `PassRole` combined with compute execution (EC2/Lambda).
   - `S12`: Cross-Principal trust escalation via assume-role policy alteration.
2. **Sensitive Data Exfiltration & Storage Exposure**
   - `S05`: S3 Bucket Policy exposure and public resource modification.
   - `S06`: AWS KMS Key Policy alteration exposing cryptographic keys.
   - `S07`: AWS Secrets Manager resource-policy access expansion.
   - `S08`: AWS Systems Manager (SSM) Parameter Store exposure.
3. **IAM Governance, Defense Evasion & Remediation**
   - `S09`: Policy version rollback and audit evasion.
   - `S10`: Trust policy expansion across unmapped external accounts.
   - `S11`: IAM Permissions Boundary removal or circumvention.
   - `S13`: Automated least-privilege remediation and privilege reduction.

---

## 4. Dataset Schema & Feature Groups

The dataset contains **111 total fields** structured into three modeling tiers and evaluation ground truths:

### A. Identifier & Provenance Metadata (Excluded from ML Training)
`sample_id`, `pair_id`, `pair_type`, `scenario_id`, `scenario_family`, `policy_lineage_id`, `policy_hash`, `structural_policy_hash`, `environment_id`, `environment_hash`, `context_id`, `context_hash`, `creation_timestamp`, `aws_region`, `data_origin`.

### B. Policy-Centric Features ($M_0$ Tier — 15 Features)
- **Document Syntax**: `policy_statement_count`, `policy_action_count`, `policy_resource_count`, `policy_has_wildcard_action`, `policy_has_wildcard_resource`, `policy_has_condition`, `policy_has_deny`, `policy_version_count`.
- **Effective Authorization**: `effective_allowed_action_count`, `effective_denied_action_count`, `effective_allowed_resource_count`, `effective_permission_count`, `effective_sensitive_action_count`, `effective_permission_expansion`, `effective_permission_reduction`.

### C. Environment Topology Features ($M_1$ Tier — 13 Additional Features)
- Infrastructure context: `environment_resource_count`, `environment_privileged_role_count`, `environment_sensitive_resource_count`, `environment_has_admin_role`, `environment_has_kms`, `environment_has_secrets_manager`, `environment_has_ssm`, `environment_has_lambda`, `environment_has_permissions_boundary`, `environment_has_cross_account_trust`, `environment_trust_openness`, `environment_reachable_privesc_paths`.

### D. CloudTrail Behavioral Context Features ($M_2$ Tier — 14 Additional Features)
- Operational audit signals: `event_count`, `primary_event_count`, `preceding_context_count`, `following_context_count`, `error_count`, `unique_event_names`, `unique_error_codes`, `cloudtrail_window_seconds`, `source_novelty`, `user_agent_novelty`, `mfa_observability`, `failed_iam_activity`, `recent_assume_role_activity`, `role_chain_length`, `unusual_sequence`.

### E. Reference Targets
- `gt_analyst_priority_score` (Continuous float, $[4.60, 53.90]$): Primary regression target representing analyst review urgency.
- `gt_analyst_priority_label` (Categorical: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`): Triage queue priority tier.
- `gt_security_risk_score` (Continuous float): Secondary metric measuring pure authorization severity.

---

## 5. Quick Start & Usage

### Loading the Dataset (Python / pandas)
```python
import pandas as pd

df = pd.read_csv("aws_iam_contextbench_real_valid.csv")
print(f"Loaded {len(df)} experimental observations.")

type_a_pairs = df[df["pair_type"] == "TYPE_A"]
print(f"Type-A observations: {len(type_a_pairs)} across {type_a_pairs['pair_id'].nunique()} pairs.")

sample_pair = df[df["pair_id"] == "p_s01_002"]
print(sample_pair[["sample_id", "context_type", "policy_action_count", "gt_analyst_priority_score"]])
```

### Recommended Cross-Validation Protocol
To prevent data leakage across related policies and paired experiments, evaluations **must** use grouped cross-validation on `policy_lineage_id`:

```python
from sklearn.model_selection import StratifiedGroupKFold

sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

for fold, (train_idx, val_idx) in enumerate(sgkf.split(df, df["scenario_family"], groups=df["policy_lineage_id"])):
    train_data = df.iloc[train_idx]
    val_data = df.iloc[val_idx]
    
    train_lineages = set(train_data["policy_lineage_id"])
    val_lineages = set(val_data["policy_lineage_id"])
    assert len(train_lineages.intersection(val_lineages)) == 0, "Lineage leakage detected!"
    print(f"Fold {fold}: Train={len(train_data)}, Val={len(val_data)}, Zero Lineage Leakage Verified.")
```

---

## 6. Data Integrity, Safety & Sanitization

- **Real AWS Execution**: 100% of samples were generated through real API interactions against live AWS services.
- **Zero Real Credentials**: All AWS Account IDs, STS session tokens, IAM secret keys, and customer identifiers have been completely sanitized and replaced with synthetic research placeholders (verified in `final_dataset_release_check.md` Check 03).
- **Leakage Prevention**: Provenance fields (hashes, timestamps, identifiers) are explicitly decoupled from feature extraction pipelines.

---

## 7. Citation

If you use this benchmark in your research, please cite:

```bibtex
@misc{elsharkawy2026evaluatingbehavioralcontextinterpretable,
      title={Evaluating Behavioral Context for Interpretable IAM Policy Risk Scoring in Cloud Environments}, 
      author={Yassin Elsharkawy},
      year={2026},
      eprint={2610.07345},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2610.07345}, 
}
```

---

## 8. License

This dataset is released under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** license.  
You are free to share and adapt the material for any purpose, provided appropriate credit is given.
