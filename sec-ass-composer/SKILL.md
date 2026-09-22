---
name: sec-ass-composer
description: Translates GCP security remediations and gcloud commands into DoiT DCI Composer Recipes, and publishes them directly to the DoiT Console using the dci CLI with SSO authentication (no local server runtime required).
---

# DoiT DCI Composer Recipe Generator (sec-ass-composer)

This skill translates GCP security assessment findings and `gcloud` remediation commands into **DoiT DCI Composer Recipes**, and publishes them directly to the DoiT Console as interactive Insights and security rule definitions.

## Key Capabilities

* **`gcloud` Remediation to Recipe Translation**: Automatically parses `gcloud` commands and maps them to standard DCI Composer Recipe JSON specifications (with target resource classes such as `gcpStorageBucket`, `gcpComputeInstance`, `gcpSQLInstance`, `gcpIAMServiceAccountKey`, `gcpKMSCryptoKey`, etc., and property conditions).
* **Direct DoiT Console Publishing**: Uses the `dci` CLI (`dci post-insight-result`) with active **SSO OAuth authentication** (`dci login`). No paste tokens or manual token management required.
* **100% Serverless Agent Runtime**: Runs directly within the AI Agent + Skill environment without needing any local HTTP server (such as `http://localhost:8888`) or external local daemon.

## Tasks

### createRecipe
Translates a `gcloud` remediation command into a DCI Composer Recipe and publishes it to the DoiT Console.

- **Command**: `npx tsx ~/.gemini/skills/sec-ass/scripts/create_composer_recipe.ts --gcloud "{{gcloudCommand}}" --projectId "{{projectId}}"`
- **Parameters**:
  - `--gcloud`: The exact `gcloud` remediation command (e.g. `gcloud storage buckets update gs://my-bucket --uniform-bucket-level-access`).
  - `--title`: *(Optional)* Custom title for the Composer Recipe.
  - `--description`: *(Optional)* Custom description for the Composer Recipe.
  - `--severity`: *(Optional)* Severity level (`critical`, `high`, `medium`, `low`). Default is `high`.
  - `--projectId`: *(Optional)* GCP Project ID.
  - `--resourceId`: *(Optional)* Specific target resource ID.

## Workflow Example

```bash
# Example 1: Translate a Cloud Storage remediation command to a Composer Recipe
npx tsx ~/.gemini/skills/sec-ass/scripts/create_composer_recipe.ts \
  --gcloud "gcloud storage buckets update gs://prod-data-bucket --uniform-bucket-level-access" \
  --projectId "my-gcp-project"

# Example 2: Translate a Cloud SQL SSL enforcement remediation command
npx tsx ~/.gemini/skills/sec-ass/scripts/create_composer_recipe.ts \
  --gcloud "gcloud sql instances patch my-db-instance --require-ssl" \
  --title "Enforce SSL/TLS Connections on Cloud SQL" \
  --severity "critical" \
  --projectId "my-gcp-project"
```
