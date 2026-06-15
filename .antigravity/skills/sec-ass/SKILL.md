---
name: sec-ass
description: Provides a comprehensive security assessment for Google Cloud Platform (GCP) projects. It uses Prowler for scanning, provides AI-driven analysis of findings, and publishes results directly to the DoiT Console as Insights.
---

# GCP Security Assessment (sec-ass)

This skill provides a comprehensive security assessment for Google Cloud Platform (GCP) projects. It uses Prowler for scanning, provides AI-driven analysis of findings, and publishes results directly to the DoiT Console as Insights.

## Core Capabilities
*   **Infrastructure Auditing:** Runs comprehensive Prowler scanning across IAM, storage, networks, compute, and databases.
*   **GKE Internal Auditing:** Integrates with the Google-managed **GKE Remote MCP Server** to perform real-time internal container audits, analyzing Pod Security Standards, RBAC over-privileging, secrets, and lateral isolation network policies.
*   **Automated Insights Publishing:** Publishes findings directly to the DoiT Console as rich, interactive Insights.

## Workflow Phases

The assessment is divided into five main phases:

1. **preAssessment**: Prepares the workspace and validates the GCP project (including checks for active GKE clusters and MCP server availability).
2. **runProwler**: Executes a Prowler scan against the target project.
3. **analyzeResults**: Processes findings into a detailed Markdown report, appending the GKE internal MCP audit findings if available.
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
- **Agent Integration (GKE Remote MCP)**: Before running this command, if the target project contains GKE clusters, the AI agent should use the `gke-read-only-troubleshooter` MCP tools to query the cluster resources and cache them to avoid local shell or kubectl requirements. For each cluster:
  1. Call `get_k8s_resource` with `resourceType: "pod"` and `outputFormat: "JSON"` to retrieve pods.
  2. Call `get_k8s_resource` with `resourceType: "networkpolicy"` and `outputFormat: "JSON"` to retrieve network policies.
  3. Call `get_k8s_resource` with `resourceType: "clusterrolebinding"` and `outputFormat: "JSON"` to retrieve RBAC bindings.
  4. Write the results into a file named `assessments/{{projectId}}/gke_mcp_data_{{clusterName}}.json` with the following structure:
     ```json
     {
       "pods": <parsed pods JSON object>,
       "networkpolicies": <parsed network policies JSON object>,
       "clusterrolebindings": <parsed clusterrolebindings JSON object>
     }
     ```
     This allows the `analyzeResults` deep-dive module to perform a comprehensive offline internal Kubernetes audit.


### generatePDF
Converts the reports to PDF.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js generatePDF --projectId {{projectId}}`
- **Description**: Generates the final PDF report.

### postInsight
Publishes the security findings as an Insight to the DoiT Console.
- **Command**: `npx tsx ./.antigravity/skills/sec-ass/scripts/agent_bridge.js postInsight --projectId {{projectId}}`
- **Description**: Aggregates vulnerable resources from Prowler and uploads findings to the DoiT Console using the `dci` CLI.
