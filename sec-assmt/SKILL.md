---
name: sec-assmt
description: Provides a comprehensive security assessment for Google Cloud Platform (GCP) projects. It uses Prowler for scanning, provides AI-driven analysis of findings, translates remediations into DCI Composer Recipes, and publishes results directly to the DoiT Console as Insights using SSO authentication.
---

# GCP Security Assessment (sec-assmt)

This skill provides a comprehensive security assessment for Google Cloud Platform (GCP) projects. It uses Prowler for scanning, provides AI-driven analysis of findings, translates remediations into **DoiT DCI Composer Recipes**, and publishes results directly to the DoiT Console as Insights.

## Core Capabilities
* **Infrastructure Auditing:** Runs comprehensive Prowler scanning across IAM, storage, networks, compute, and databases.
* **GKE Internal Auditing:** Integrates with the Google-managed **GKE Remote MCP Server** to perform real-time internal container audits, analyzing Pod Security Standards, RBAC over-privileging, secrets, and lateral isolation network policies.
* **DCI Composer Recipe Generation:** Translates `gcloud` remediation commands and security findings into standard DoiT DCI Composer Recipes.
* **Automated Insights Publishing:** Publishes findings and Composer recipes directly to the DoiT Console using `dci` CLI with active SSO OAuth authentication.

## Workflow Phases

1. **preAssessment**: Prepares the workspace and validates the GCP project.
2. **runProwler**: Executes a Prowler scan against the target project.
3. **analyzeResults**: Processes findings into a detailed Markdown report.
4. **generatePDF**: Finalizes the assessment into a PDF document.
5. **postInsight**: Publishes the findings as an Insight to the DoiT Console.
6. **createRecipe**: Translates a `gcloud` remediation command into a DCI Composer Recipe and publishes it to the DoiT Console.

## Tasks

### preAssessment
Initializes the assessment session.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js preAssessment --projectId {{projectId}}`

### runProwler
Generates and runs the Prowler scan.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js runProwler --projectId {{projectId}}`

### analyzeResults
Parses Prowler CSV output and creates Report.md.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js analyzeResults --projectId {{projectId}}`

### generatePDF
Converts the reports to PDF.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js generatePDF --projectId {{projectId}}`

### postInsight
Publishes the security findings as an Insight to the DoiT Console.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js postInsight --projectId {{projectId}}`

### createRecipe
Translates a `gcloud` remediation command into a DCI Composer Recipe and publishes it to the DoiT Console.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/create_composer_recipe.ts --gcloud "{{gcloudCommand}}" --projectId "{{projectId}}"`
