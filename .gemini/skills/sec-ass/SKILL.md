# GCP Security Assessment (sec-ass)

This skill provides a comprehensive security assessment for Google Cloud Platform (GCP) projects. It uses Prowler for scanning and provides AI-driven analysis of findings.

## Workflow Phases

The assessment is divided into four main phases:

1. **preAssessment**: Prepares the workspace and validates the GCP project.
2. **runProwler**: Executes a Prowler scan against the target project.
3. **analyzeResults**: Processes findings into a detailed Markdown report.
4. **generatePDF**: Finalizes the assessment into a PDF document.

## Tasks

### preAssessment
Initializes the assessment session.
- **Command**: `npx tsx ./.gemini/skills/sec-ass/scripts/agent_bridge.js preAssessment --projectId {{projectId}}`
- **Description**: Creates the assessment directory and initializes the session.

### runProwler
Generates and runs the Prowler scan.
- **Command**: `npx tsx ./.gemini/skills/sec-ass/scripts/agent_bridge.js runProwler --projectId {{projectId}}`
- **Description**: Generates a bash script and executes Prowler (this may take several minutes).

### analyzeResults
Parses Prowler CSV output and creates Report.md.
- **Command**: `npx tsx ./.gemini/skills/sec-ass/scripts/agent_bridge.js analyzeResults --projectId {{projectId}}`
- **Description**: Processes the CSV findings into a structured Markdown report.

### generatePDF
Converts the reports to PDF.
- **Command**: `npx tsx ./.gemini/skills/sec-ass/scripts/agent_bridge.js generatePDF --projectId {{projectId}}`
- **Description**: Generates the final PDF report.
