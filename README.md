# GCP Security Assessment Skill (sec-ass)

This repository contains an autonomous **Gemini CLI Skill** designed for performing security assessments on Google Cloud Platform (GCP) projects. It bridges the power of **Prowler** with Gemini's AI reasoning to provide actionable security recommendations.

## Features
- **Automated Prowler Scans**: Executes security best-practice checks against any GCP Project ID.
- **AI-Driven Analysis**: Automatically analyzes CSV findings and generates structured reports.
- **Actionable Recommendations**: Provides resource-specific `gcloud` and `gsutil` commands for remediation.
- **Professional PDF Reports**: Converts Markdown findings into a finalized PDF document.
- **Autonomous Structure**: Fully self-contained logic within the `.gemini/skills/` directory.

## Prerequisites
- [Gemini CLI](https://www.npmjs.com/package/@google/gemini-cli) (v1.x)
- [Prowler](https://github.com/prowler-cloud/prowler) installed and configured in your environment.
- Node.js & npm.
- `pandoc` and `weasyprint` (for PDF generation).

## Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/doitintl/gcp-security-auditor-skill.git .
   ```

2. **Setup Dependencies**:
   Ensure you have the required tools installed:
   ```bash
   # Install Gemini CLI
   npm install -g @google/gemini-cli

   # Install Prowler
   brew install prowler

   # Install PDF dependencies (optional, for PDF generation)
   brew install pandoc weasyprint
   ```

3. **Install Skill Packages**:
   ```bash
   cd .gemini/skills/sec-ass/
   npm install
   cd ../../../
   ```

## Getting Started

The easiest way to use this tool is via the interactive **GCP Security Auditor** agent. 

1. **Start Gemini**:
   ```bash
   gemini chat
   ```

2. **Trigger the Assessment**:
   Just type:
   > "Please do a security assessment on my project [YOUR_PROJECT_ID]"

The agent will autonomously guide you through the 4-phase workflow:
1.  **Pre-Assessment**: Validation of environment and permissions.
2.  **Security Scan**: Running Prowler to identify vulnerabilities.
3.  **Analysis**: Deep-dive into findings and AI-driven recommendations.
4.  **Reporting**: Generation of the final PDF report.

## Scope of Assessment
The tool currently vets:
- **Compute Engine**: Firewalls, OS Login, 2FA.
- **IAM**: Least privilege, Service Accounts.
- **Storage & SQL**: Public exposure, Encryption, Backups.
- **Deep-Dives**: GKE Hardening, VPC Service Controls, DNSSEC, Org Policies.

## Project Structure
- `.gemini/skills/sec-ass/`: The core skill logic and scripts.
- `assessments/`: (Generated) Directory where scan results and reports are stored.
- `GEMINI.md`: Workspace configuration for the Security Auditor agent.

## License
MIT
