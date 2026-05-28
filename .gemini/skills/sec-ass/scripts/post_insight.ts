import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { parseArgs } from "node:util";

// Simple self-contained CSV Parser to avoid external dependency issues
function parseCSV(content: string): Record<string, string>[] {
    const lines = content.split(/\r?\n/);
    if (lines.length === 0) return [];
    
    // Parse headers
    const headers = parseCSVLine(lines[0]);
    const results: Record<string, string>[] = [];
    
    for (let i = 1; i < lines.length; i++) {
        if (!lines[i].trim()) continue;
        const values = parseCSVLine(lines[i]);
        const row: Record<string, string> = {};
        
        headers.forEach((header, index) => {
            row[header] = values[index] || "";
        });
        results.push(row);
    }
    
    return results;
}

function parseCSVLine(line: string): string[] {
    const result: string[] = [];
    let current = "";
    let inQuotes = false;
    
    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            result.push(current.trim());
            current = "";
        } else {
            current += char;
        }
    }
    result.push(current.trim());
    
    // Remove enclosing quotes if present
    return result.map(val => {
        if (val.startsWith('"') && val.endsWith('"')) {
            return val.slice(1, -1);
        }
        return val;
    });
}

async function main() {
    const { values } = parseArgs({
        options: {
            projectId: { type: "string" }
        }
    });

    const projectId = values.projectId;
    if (!projectId) {
        console.error("✖ Error: --projectId is required");
        process.exit(1);
    }

    const assessmentDir = path.resolve(`assessments/${projectId}`);
    const csvPath = path.join(assessmentDir, "prowler_results", "output.csv");
    const reportPath = path.join(assessmentDir, "Report.md");

    if (!fs.existsSync(csvPath)) {
        console.error(`✖ Error: Prowler CSV results not found at: ${csvPath}`);
        console.error(`Please run the security assessment first: sec-ass:runProwler --projectId ${projectId}`);
        process.exit(1);
    }

    console.log(`[PUBLISHER] Reading Prowler CSV output...`);
    const csvContent = fs.readFileSync(csvPath, "utf-8");
    const rows = parseCSV(csvContent);

    // Filter for failing findings
    const failedRows = rows.filter(row => {
        const status = row.STATUS || "";
        return status.toUpperCase() === "FAIL";
    });

    console.log(`[PUBLISHER] Found ${failedRows.length} failed security checks.`);

    // Group and aggregate findings by resource
    const resourceMap: Record<string, {
        resourceId: string;
        resourceType: string;
        location: string;
        critical: number;
        high: number;
        medium: number;
        low: number;
        recommendations: Set<string>;
    }> = {};

    failedRows.forEach(row => {
        const resourceId = row.RESOURCE_ARN || row.RESOURCE_UID || row.RESOURCE_ID || "unknown-resource";
        const resourceType = row.RESOURCE_TYPE || row.SERVICE_NAME || "gcp-resource";
        const location = row.REGION || "global";
        const severity = (row.SEVERITY || "low").toLowerCase();
        const recommendation = row.REMEDIATION_RECOMMENDATION_TEXT || row.CHECK_TITLE || "";

        if (!resourceMap[resourceId]) {
            resourceMap[resourceId] = {
                resourceId,
                resourceType,
                location,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                recommendations: new Set()
            };
        }

        const res = resourceMap[resourceId];
        if (severity === "critical") res.critical++;
        else if (severity === "high") res.high++;
        else if (severity === "medium") res.medium++;
        else res.low++;

        if (recommendation) {
            res.recommendations.add(recommendation);
        }
    });

    let detailedDescription = "";
    if (fs.existsSync(reportPath)) {
        console.log(`[PUBLISHER] Loading Report.md as MDX detailed description...`);
        detailedDescription = fs.readFileSync(reportPath, "utf-8");
    } else {
        console.log(`[PUBLISHER] Report.md not found, generating fallback description...`);
        detailedDescription = `# GCP Security Assessment: ${projectId}\n\n` +
            `This is an automated Prowler security scan summary.\n\n` +
            `### Summary of Failed Controls\n` +
            `- Total Failed Controls: ${failedRows.length}\n` +
            `- Total Vulnerable Resources: ${Object.keys(resourceMap).length}\n`;
    }

    const insightKey = `gcp-security-assessment-${projectId}`;
    const insightPayload = {
        categories: ["Security"],
        cloudProvider: "gcp",
        key: insightKey,
        title: `GCP Security Assessment: ${projectId}`,
        shortDescription: `Automated Prowler security audit with ${failedRows.length} failed controls across resources.`,
        detailedDescriptionMdx: detailedDescription,
        status: "actionable"
    };

    const insightPayloadPath = path.join(assessmentDir, "insight_payload.json");
    fs.writeFileSync(insightPayloadPath, JSON.stringify(insightPayload, null, 2));

    console.log(`[PUBLISHER] Posting main Insight to DoiT Console...`);
    try {
        const cmd = `dci post-insight-result public-api "${insightKey}" < "${insightPayloadPath}"`;
        execSync(cmd, { stdio: "inherit" });
        console.log(`✔ Success: Main Insight created/updated.`);
    } catch (err: any) {
        console.error(`✖ Error posting main Insight:`, err.message);
        process.exit(1);
    }

    const resourceResults = Object.values(resourceMap).map(res => {
        const recommendationStr = Array.from(res.recommendations)
            .slice(0, 3)
            .join("; ");

        return {
            account: projectId,
            cloudProvider: "gcp",
            resourceId: res.resourceId,
            resourceType: res.resourceType.toLowerCase(),
            location: res.location,
            result: {
                critical: res.critical,
                high: res.high,
                medium: res.medium,
                low: res.low,
                recommendation: recommendationStr.substring(0, 490) || "Review resource configuration"
            },
            resultType: "security_risk"
        };
    });

    const resourcePayload = { resourceResults };
    const resourcePayloadPath = path.join(assessmentDir, "resource_payload.json");
    fs.writeFileSync(resourcePayloadPath, JSON.stringify(resourcePayload, null, 2));

    console.log(`[PUBLISHER] Posting ${resourceResults.length} resource-level findings...`);
    try {
        const cmd = `dci post-insight-resource-results public-api "${insightKey}" < "${resourcePayloadPath}"`;
        execSync(cmd, { stdio: "inherit" });
        console.log(`✔ Success: Resource-level results created/updated.`);
    } catch (err: any) {
        console.error(`✖ Error posting resource results:`, err.message);
        process.exit(1);
    }

    console.log(`\n🎉 Security assessment published successfully to the DoiT Console!`);
}

main().catch(err => {
    console.error("✖ Fatal Error:", err);
    process.exit(1);
});
