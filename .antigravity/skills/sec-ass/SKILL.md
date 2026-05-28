# GCP Security Assessment (sec-ass)

This skill provides a comprehensive security assessment for Google Cloud Platform (GCP) projects. It uses Prowler for scanning, provides AI-driven analysis of findings, and publishes results directly to the DoiT Console as Insights.

## Workflow Phases

The assessment is divided into five main phases:

1. **preAssessment**: Prepares the workspace and validates the GCP project.
2. **runProwler**: Executes a Prowler scan against the target project.
3. **analyzeResults**: Processes findings into a detailed Markdown report.
4. **generatePDF**: Finalizes the assessment into a PDF document.
5. **postInsight**: Publishes the findings as an Insight and resource results to the DoiT Console.

## Tasks

### preAssessment
Initializes the assessment session.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js preAssessment --projectId {{projectId}}`
- **Description**: Creates the assessment directory and initializes the session.

### runProwler
Generates and runs the Prowler scan.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js runProwler --projectId {{projectId}}`
- **Description**: Generates a bash script and executes Prowler (this may take several minutes).

### analyzeResults
Parses Prowler CSV output and creates Report.md.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js analyzeResults --projectId {{projectId}}`
- **Description**: Processes the CSV findings into a structured Markdown report.

### generatePDF
Converts the reports to PDF.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js generatePDF --projectId {{projectId}}`
- **Description**: Generates the final PDF report.

### postInsight
Publishes the security findings as an Insight to the DoiT Console.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js postInsight --projectId {{projectId}}`
- **Description**: Aggregates vulnerable resources from Prowler and uploads findings to the DoiT Console using the `dci` CLI.
