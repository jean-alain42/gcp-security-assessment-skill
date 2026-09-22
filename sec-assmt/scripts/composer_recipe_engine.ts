import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface ComposerCheck {
    property: string;
    propertyPath: string;
    operator: string;
    value: any;
    negate?: boolean;
}

export interface ComposerRemediation {
    description: string;
    gcloudCommand: string;
}

export interface ComposerRecipe {
    key: string;
    title: string;
    description: string;
    cloudProvider: "gcp";
    resourceClass: string;
    resourceTitle: string;
    categories: string[];
    severity: "critical" | "high" | "medium" | "low";
    checks: ComposerCheck[];
    remediation: ComposerRemediation;
}

// Authoritative property paths & exact display titles from graph_model.json
const GCP_RESOURCE_MAP: Record<string, { resourceClass: string; resourceTitle: string; defaultProperty: string; defaultPropertyPath: string; negate?: boolean; value: any }> = {
    storage: {
        resourceClass: "gcpStorageBucket",
        resourceTitle: "Cloud Storage Bucket",
        defaultProperty: "iamConfiguration.publicAccessPrevention",
        defaultPropertyPath: "storage-storageBucketsList.items[item]/iamConfiguration.publicAccessPrevention",
        negate: true,
        value: "enforced"
    },
    bucket: {
        resourceClass: "gcpStorageBucket",
        resourceTitle: "Cloud Storage Bucket",
        defaultProperty: "iamConfiguration.publicAccessPrevention",
        defaultPropertyPath: "storage-storageBucketsList.items[item]/iamConfiguration.publicAccessPrevention",
        negate: true,
        value: "enforced"
    },
    compute: {
        resourceClass: "gcpComputeInstance",
        resourceTitle: "Compute Engine Instance",
        defaultProperty: "canIpForward",
        defaultPropertyPath: "compute-instancesList.items[item]/canIpForward",
        negate: false,
        value: false
    },
    instance: {
        resourceClass: "gcpComputeInstance",
        resourceTitle: "Compute Engine Instance",
        defaultProperty: "canIpForward",
        defaultPropertyPath: "compute-instancesList.items[item]/canIpForward",
        negate: false,
        value: false
    },
    sql: {
        resourceClass: "gcpSqlInstance",
        resourceTitle: "Cloud SQL Instance",
        defaultProperty: "settings.ipConfiguration.requireSsl",
        defaultPropertyPath: "sql-sqlInstancesList.items[item]/settings.ipConfiguration.requireSsl",
        negate: false,
        value: false
    },
    firewall: {
        resourceClass: "gcpComputeFirewall",
        resourceTitle: "VPC Firewall Rule",
        defaultProperty: "sourceRanges",
        defaultPropertyPath: "compute-firewallsList.items[item].sourceRanges[item]/$value",
        negate: false,
        value: "0.0.0.0/0"
    }
};

export function resolveComposerToken(explicitToken?: string): string | undefined {
    if (explicitToken && explicitToken.trim()) return explicitToken.trim();
    if (process.env.COMPOSER_BEARER_TOKEN && !process.env.COMPOSER_BEARER_TOKEN.includes("YOUR_")) return process.env.COMPOSER_BEARER_TOKEN.trim();

    const credentialsPath = path.resolve(__dirname, "../credentials.json");
    if (fs.existsSync(credentialsPath)) {
        try {
            const creds = JSON.parse(fs.readFileSync(credentialsPath, "utf-8"));
            if (creds.composer_bearer_token && !creds.composer_bearer_token.includes("YOUR_")) return creds.composer_bearer_token.trim();
        } catch { }
    }

    const homeTokenPath = path.resolve(process.env.HOME || "", ".dci_composer_token");
    if (fs.existsSync(homeTokenPath)) {
        try {
            const token = fs.readFileSync(homeTokenPath, "utf-8").trim();
            if (token && !token.includes("YOUR_")) return token;
        } catch { }
    }

    return undefined;
}

export function translateGcloudToComposerRecipe(
    gcloudCommand: string,
    context?: { title?: string; description?: string; severity?: "critical" | "high" | "medium" | "low"; resourceId?: string }
): ComposerRecipe {
    const cleanCmd = gcloudCommand.trim();
    const lowerCmd = cleanCmd.toLowerCase();

    let resourceClass = "gcpStorageBucket";
    let resourceTitle = "Cloud Storage Bucket";
    let defaultProperty = "iamConfiguration.publicAccessPrevention";
    let defaultPropertyPath = "storage-storageBucketsList.items[item]/iamConfiguration.publicAccessPrevention";
    let negate = true;
    let value: any = "enforced";

    for (const [key, mapping] of Object.entries(GCP_RESOURCE_MAP)) {
        if (lowerCmd.includes(key)) {
            resourceClass = mapping.resourceClass;
            resourceTitle = mapping.resourceTitle;
            defaultProperty = mapping.defaultProperty;
            defaultPropertyPath = mapping.defaultPropertyPath;
            negate = mapping.negate ?? false;
            value = mapping.value;
            break;
        }
    }

    const rawTitle = context?.title || extractTitleFromGcloud(cleanCmd);
    const key = `composer-recipe-${rawTitle.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
    const severity = context?.severity || "high";

    const checks: ComposerCheck[] = [
        {
            property: defaultProperty,
            propertyPath: defaultPropertyPath,
            operator: "=",
            value,
            negate
        }
    ];

    return {
        key,
        title: rawTitle,
        description: context?.description || `DCI Composer Recipe automatically generated from gcloud remediation command: \`${cleanCmd}\``,
        cloudProvider: "gcp",
        resourceClass,
        resourceTitle,
        categories: ["Security"],
        severity,
        checks,
        remediation: {
            description: `Execute the following gcloud command to remediate non-compliant resources across your project:`,
            gcloudCommand: cleanCmd
        }
    };
}

function extractTitleFromGcloud(cmd: string): string {
    if (cmd.includes("storage buckets update")) return "Enable Uniform Bucket Level Access";
    if (cmd.includes("compute instances update")) return "Harden Compute Engine Instance Configuration";
    if (cmd.includes("sql instances patch")) return "Enforce SSL TLS on Cloud SQL Instances";
    if (cmd.includes("firewall-rules")) return "Restrict Permissive Compute Firewall Rules";
    return "Remediate GCP Security Vulnerability";
}

/**
 * Pushes the recipe directly to the Native DCI Composer Rules API (/operate/composer)
 */
export async function pushToComposerNativeAPI(
    recipe: ComposerRecipe,
    customerId: string = "EE8CtpzYiKp0dVAESVrB",
    explicitToken?: string
): Promise<{ success: boolean; url?: string; recipeId?: number; error?: string }> {
    const bearerToken = resolveComposerToken(explicitToken);
    if (!bearerToken) {
        return { success: false, error: "COMPOSER_BEARER_TOKEN not found in environment, credentials.json, ~/.dci_composer_token, or Chrome storage." };
    }

    const nodeId = `${recipe.resourceClass}-1`;
    const check = recipe.checks[0];

    const properties: Record<string, any> = {};
    properties[check.propertyPath] = {
        conditions: [
            [
                { isNull: false },
                { negate: check.negate ?? false, operator: check.operator, value: check.value }
            ]
        ],
        group: 1
    };

    const query: Record<string, any> = {};
    query[nodeId] = {
        id: nodeId,
        title: recipe.resourceTitle,
        resourceClass: recipe.resourceClass,
        filtersGroups: {
            id: 1,
            operator: "and",
            childrenGroups: []
        },
        arrayParentToContainsCondition: {},
        properties: properties,
        comparisons: {},
        relations: {}
    };

    const filterResource: Record<string, any> = {};
    filterResource[nodeId] = properties;

    const queryGroups: Record<string, any> = {};
    queryGroups[nodeId] = { id: 1, operator: "and", childrenGroups: [] };

    const timestamp = Date.now();
    const canvasData: Record<string, any> = {};
    canvasData[nodeId] = {
        id: `composer-canvas-${recipe.resourceClass.toLowerCase()}-${timestamp}-001`,
        x: 200,
        y: 150
    };

    const visualizationState = {
        canvasState: {
            createdInDCI: true,
            canvasData: canvasData
        },
        filtersState: {
            resource: filterResource,
            queryGroups: queryGroups,
            relation: {},
            arrayParentToContainsCondition: {}
        }
    };

    const stepsHtml = `<ol><li>${recipe.remediation.description}</li><li><code>${recipe.remediation.gcloudCommand}</code></li></ol>`;

    const payload = {
        title: recipe.title,
        description: recipe.description,
        severity: recipe.severity || "high",
        provider: "gcp",
        pillars: {
            cost: false,
            security: true,
            compliance: "",
            operations: false,
            performance: false
        },
        customer: customerId,
        author: "ja.mignon@doit.com",
        lastUpdatedBy: "ja.mignon@doit.com",
        isPublic: true,
        issuedResource: nodeId,
        query: query,
        visualizationState: visualizationState,
        manualRemediation: {
            steps: stepsHtml
        }
    };

    const url = `https://console.doit.com/dci-composer/api/query/rule?customerId=${customerId}`;
    try {
        const resp = await fetch(url, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${bearerToken}`,
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(payload)
        });

        if (resp.ok) {
            const resData: any = await resp.json();
            const recipeId = resData.id;
            const recipeUrl = `https://console.doit.com/customers/${customerId}/operate/composer/recipes/${recipeId || ""}`;
            return { success: true, url: recipeUrl, recipeId };
        } else {
            const errText = await resp.text();
            return { success: false, error: `HTTP ${resp.status}: ${errText}` };
        }
    } catch (err: any) {
        return { success: false, error: err.message };
    }
}

/**
 * Publishes a DCI Composer Recipe directly to DoiT Console Insights using `dci` CLI (OAuth SSO session).
 */
export function publishRecipeToDoiTConsole(
    recipe: ComposerRecipe,
    affectedResources?: Array<{ resourceId: string; location?: string; projectId?: string }>
): { success: boolean; insightKey: string } {
    const insightKey = recipe.key;

    const mdxContent = `# DCI Composer Recipe: ${recipe.title}

> **Source**: Auto-generated by DoiT Security Assessment & DCI Composer Recipe Engine

### 🎯 Recipe Overview
* **Target Resource Class**: \`${recipe.resourceClass}\`
* **Cloud Provider**: \`${recipe.cloudProvider.toUpperCase()}\`
* **Severity**: \`${recipe.severity.toUpperCase()}\`
* **Category**: \`${recipe.categories.join(", ")}\`

---

### 🔍 Composer Rule Specification (JSON)

\`\`\`json
${JSON.stringify(recipe, null, 2)}
\`\`\`

---

### 🛠️ Remediation Instructions (\`gcloud\` CLI)

Run the following command to remediate non-compliant resources:

\`\`\`bash
${recipe.remediation.gcloudCommand}
\`\`\`

---
*Created via \`dci\` CLI using authenticated SSO session.*
`;

    const insightPayload = {
        categories: recipe.categories,
        cloudProvider: recipe.cloudProvider,
        key: insightKey,
        title: `[Composer Recipe] ${recipe.title}`,
        shortDescription: recipe.description,
        detailedDescriptionMdx: mdxContent,
        status: "actionable"
    };

    const tmpDir = path.resolve("./tmp_recipe");
    fs.mkdirSync(tmpDir, { recursive: true });

    const insightPayloadPath = path.join(tmpDir, `${insightKey}_insight.json`);
    fs.writeFileSync(insightPayloadPath, JSON.stringify(insightPayload, null, 2));

    console.log(`[COMPOSER-RECIPE] Publishing Recipe Insight "${insightKey}" to DoiT Console via dci CLI...`);

    try {
        const cmd = `dci post-insight-result public-api "${insightKey}" < "${insightPayloadPath}"`;
        execSync(cmd, { stdio: "inherit" });
        console.log(`✔ Success: DCI Composer Recipe Insight published.`);
    } catch (err: any) {
        console.error(`✖ Error publishing Recipe Insight:`, err.message);
        return { success: false, insightKey };
    }

    return { success: true, insightKey };
}
