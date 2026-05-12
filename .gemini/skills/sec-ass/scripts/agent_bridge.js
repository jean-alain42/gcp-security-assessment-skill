import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_ROOT = path.resolve(__dirname, "..");
const LIB_DIR = path.join(SKILL_ROOT, "lib");

async function preAssessment(projectId, customerName) {
    const assessmentDir = path.resolve(`assessments/${projectId}`);
    fs.mkdirSync(assessmentDir, { recursive: true });
    
    fs.writeFileSync(path.join(assessmentDir, ".session.json"), JSON.stringify({
        project_id: projectId,
        customer: customerName || "Unknown",
        current_step: "run-prowler"
    }, null, 2));

    return { status: "Success", assessmentDir };
}

async function runProwler(projectId) {
    const assessmentDir = path.resolve(`assessments/${projectId}`);
    fs.mkdirSync(assessmentDir, { recursive: true });
    
    const scriptPath = path.join(assessmentDir, "run-prowler.sh");
    const content = `#!/bin/bash\nmkdir -p prowler_results\nprowler gcp --project-id ${projectId} -M csv -o prowler_results -F output\n`;
    fs.writeFileSync(scriptPath, content, { mode: 0o755 });

    console.log(`[BRIDGE] Executing Prowler scan for ${projectId}...`);
    try {
        execSync(`bash ./run-prowler.sh`, { 
            cwd: assessmentDir,
            stdio: 'inherit' 
        });
    } catch (e) {
        const csvPath = path.join(assessmentDir, "prowler_results", "output.csv");
        if (fs.existsSync(csvPath)) {
            console.log(`[BRIDGE] Prowler finished with findings.`);
            return { status: "Success", message: "Prowler scan completed with findings." };
        }
        throw e;
    }
    return { status: "Success", message: "Prowler scan completed." };
}

async function analyzeResults(projectId) {
    const assessmentDir = path.resolve(`assessments/${projectId}`);
    const csvPath = path.join(assessmentDir, "prowler_results", "output.csv");
    const outPath = path.join(assessmentDir, "Report.md");
    const headerPath = path.join(assessmentDir, "ReportHeader.md");
    
    fs.writeFileSync(headerPath, `# Summary\nAssessment for GCP Project: ${projectId}\n\n## Methodology\nScanned using Prowler GCP.\n`);

    const processorScript = path.join(LIB_DIR, "process-prowler-results.ts");
    const templatePath = path.join(LIB_DIR, "templates/finding-template.md");

    try {
        console.log(`[BRIDGE] Processing CSV results...`);
        execSync(`npx tsx "${processorScript}" "${csvPath}" "${outPath}" --template "${templatePath}"`, { 
            cwd: assessmentDir,
            stdio: 'inherit' 
        });
        return { status: "Success", reportPath: outPath, headerPath };
    } catch (e) {
        return { status: "Failed", error: e.message };
    }
}

async function generatePDF(projectId) {
    const assessmentDir = path.resolve(`assessments/${projectId}`);
    const pdfScript = path.join(LIB_DIR, "convert-to-pdf/convert-to-pdf.sh");

    try {
        console.log(`[BRIDGE] Generating final PDF report...`);
        execSync(`bash "${pdfScript}" .`, { 
            cwd: assessmentDir, 
            stdio: 'inherit' 
        });
        return { status: "Success", directory: assessmentDir };
    } catch (e) {
        return { status: "Failed", error: e.message };
    }
}

async function main() {
    const { values, positionals } = parseArgs({
        options: {
            projectId: { type: "string" },
            customerName: { type: "string" },
        },
        allowPositionals: true
    });

    const phase = positionals[0];
    const projectId = values.projectId;

    if (!projectId) {
        console.error("✖ Error: --projectId is required");
        process.exit(1);
    }

    try {
        let result;
        switch (phase) {
            case "preAssessment":
                result = await preAssessment(projectId, values.customerName);
                break;
            case "runProwler":
                result = await runProwler(projectId);
                break;
            case "analyzeResults":
                result = await analyzeResults(projectId);
                break;
            case "generatePDF":
                result = await generatePDF(projectId);
                break;
            default:
                console.error(`✖ Error: Unknown phase "${phase}"`);
                process.exit(1);
        }
        console.log(JSON.stringify(result, null, 2));
    } catch (error) {
        console.error(`✖ Error in phase ${phase}:`, error);
        process.exit(1);
    }
}

main().catch(err => {
    console.error("✖ Fatal Error:", err);
    process.exit(1);
});
