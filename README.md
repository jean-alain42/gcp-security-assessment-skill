# GCP Security Assessment Skill (sec-ass)

This repository contains an autonomous **Antigravity CLI Skill** designed for performing security assessments on Google Cloud Platform (GCP) projects. It bridges the power of **Prowler** with Antigravity's AI reasoning to provide actionable security recommendations, and publishes results directly to the DoiT Console.

## Features
- **Automated Prowler Scans**: Executes security best-practice checks against any GCP Project ID.
- **AI-Driven Analysis**: Automatically analyzes CSV findings and generates structured reports.
- **GKE Remote MCP Audits**: Leverages the GKE Remote MCP Server to perform real-time, zero-trust internal audits of Kubernetes Pod Security, Network Policies, and RBAC bindings without needing local `kubectl` access.
- **Actionable Recommendations**: Provides resource-specific `gcloud` and `gsutil` commands for remediation.
- **Professional PDF Reports**: Converts Markdown findings into a finalized PDF document.
- **DoiT Console Insights**: Integrates with the `dci` CLI to seamlessly publish aggregated resource-level findings as interactive security insights directly to the DoiT Console.
- **Autonomous Structure**: Fully self-contained logic within the `.antigravity/skills/` directory.


## Prerequisites
- **Antigravity CLI**
- **GKE Remote MCP Server** (`gke-read-only-troubleshooter` configured in Antigravity) — *Optional, required for GKE workload, network policy, and RBAC auditing.*
- [Prowler](https://github.com/prowler-cloud/prowler) installed and configured in your environment.
- [DoiT CLI (dci)](https://help.doit.com/docs/cli) installed and authenticated.
- Node.js & npm.
- `pandoc` and `weasyprint` (for PDF generation).


## Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/doitintl/gcp-security-assessment-automation.git .
   ```

2. **Setup Dependencies**:
   Ensure you have the required tools installed:
   ```bash
   # Verify Antigravity CLI is ready
   antigravity status

   # Install Prowler
   brew install prowler

   # Install PDF dependencies (optional, for PDF generation)
   brew install pandoc weasyprint
   ```

3. **Install Skill Packages**:
   ```bash
   cd .antigravity/skills/sec-ass/
   npm install
   cd ../../../
   ```

## Getting Started

The easiest way to use this tool is via the interactive **GCP Security Auditor** agent. 

1. **Start Antigravity**:
   ```bash
   antigravity chat
   ```

2. **Trigger the Assessment**:
   Just type:
   > "Please do a security assessment on my project [YOUR_PROJECT_ID]"

The agent will autonomously guide you through the 5-phase workflow:
1.  **Pre-Assessment**: Validation of environment and permissions.
2.  **Security Scan**: Running Prowler to identify vulnerabilities.
3.  **Analysis**: Deep-dive into findings and AI-driven recommendations.
4.  **Reporting**: Generation of the final PDF report.
5.  **Insights Publication**: Publishing aggregated resource results and findings directly to the DoiT Console as an interactive Insight.

### Standalone Insights Publishing
If you have already performed a scan and only wish to publish the insights using the standalone publisher, run:
```bash
npx tsx ./.antigravity/skills/sec-ass-insight/scripts/post_insight.ts --projectId [YOUR_PROJECT_ID]
```

## 🚀 GKE Remote MCP Server Integration (New!)

The skill features deep integration with the Google-managed **GKE Remote MCP Server** (`gke-read-only-troubleshooter`). This allows the **Antigravity Auditor** agent to audit and analyze cluster-internal security postures remotely without requiring local cluster connections.

### Key Remote MCP Audit Capabilities:
- **Zero-Trust Remote Querying**: Inspects clusters directly via the remote GCP control plane. No local `kubectl` configuration, Kubeconfig context setup, or VPN/bastion access is required inside the agent's execution shell.
- **Workload & Pod Security Audits**: Real-time extraction and AI-driven analysis of active Kubernetes Pods to identify privileged containers, host namespace sharing, and insecure configurations.
- **Lateral Isolation Verification**: Checks Kubernetes `NetworkPolicies` to ensure workloads are properly segmented and isolated, preventing lateral movement in the event of a breach.
- **RBAC Entitlement Analysis**: Audits `ClusterRoleBindings` and role mappings to identify over-privileged identities, wildcard permissions (`*`), and privilege escalation paths.
- **Seamless Offline Audit Mode**: Collected cluster-internal data is compiled and fed directly into the `analyzeResults` deep-dive auditing engine to generate comprehensive security insights.

## Scope of Assessment

The tool currently vets:
- **Compute Engine**: Firewalls, OS Login, 2FA.
- **IAM**: Least privilege, Service Accounts.
- **Storage & SQL**: Public exposure, Encryption, Backups.
- **Deep-Dives**: GKE Hardening, VPC Service Controls, DNSSEC, Org Policies.

## Project Structure
- `.antigravity/skills/sec-ass/`: The core skill logic and scripts.
- `.antigravity/skills/sec-ass-insight/`: Standalone skill for publishing security insights.
- `assessments/`: (Generated) Directory where scan results, reports, and payloads are stored.
- `ANTIGRAVITY.md`: Workspace configuration for the Security Auditor agent.

## License
MIT
