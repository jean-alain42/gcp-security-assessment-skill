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

## Installation

1. Clone this repository into your Gemini workspace:
   ```bash
   git clone <repo-url> .
   ```
2. Install skill-specific dependencies:
   ```bash
   cd .gemini/skills/sec-ass/
   npm install
   ```

## Usage

### 1. Interactive Mode (Recommended)
Simply start the Gemini chat. The **GCP Security Auditor** personality will guide you through the assessment:
```bash
gemini chat
```

### 2. Direct Skill Commands
You can also invoke the skill phases directly from your terminal:

*   **Initialize Assessment**:
    ```bash
    gemini sec-ass:preAssessment --projectId <PROJECT_ID>
    ```
*   **Run Security Scan**:
    ```bash
    gemini sec-ass:runProwler --projectId <PROJECT_ID>
    ```
*   **Process Results**:
    ```bash
    gemini sec-ass:analyzeResults --projectId <PROJECT_ID>
    ```
*   **Generate PDF Report**:
    ```bash
    gemini sec-ass:generatePDF --projectId <PROJECT_ID>
    ```

## Project Structure
- `.gemini/skills/sec-ass/`: The core skill logic and scripts.
- `assessments/`: (Generated) Directory where scan results and reports are stored.
- `GEMINI.md`: Workspace configuration for the Security Auditor agent.

## License
MIT
