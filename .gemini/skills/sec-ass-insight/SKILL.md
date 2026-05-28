# DoiT Security Insight Publisher (sec-ass-insight)

This skill publishes the results of a GCP security assessment (performed by the `sec-ass` skill) directly to the DoiT Console as a rich, interactive **Insight** with resource-level security risks using the `dci` CLI.

## Workflow Integration

This skill is designed to run after a security assessment is completed:
1. Run `sec-ass:preAssessment`, `sec-ass:runProwler`, and `sec-ass:analyzeResults`.
2. Run `sec-ass-insight:postInsight` to publish the results as an Insight in the DoiT Console.

## Tasks

### postInsight
Publishes the security assessment findings to the DoiT Console as an Insight and resource results.
- **Command**: `npx tsx ./.gemini/skills/sec-ass-insight/scripts/post_insight.ts --projectId {{projectId}}`
- **Description**: Parses Prowler CSV results, aggregates findings, builds the JSON payloads, and calls the `dci` CLI to post both the main Insight and resource-specific security risks.
