#!/usr/bin/env ts-node
// @ts-nocheck
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import Papa from 'papaparse';

interface ProwlerRow {
  CHECK_ID: string;
  STATUS: string;
  SEVERITY: string;
  ACCOUNT_ID: string;
  REGION: string;
  RESOURCE_ARN: string;
  SERVICE_NAME: string;
  RESOURCE_TYPE: string;
  SUBSERVICE_NAME: string;
  CHECK_TITLE: string;
  STATUS_EXTENDED: string;
  DESCRIPTION: string;
  RISK: string;
  REMEDIATION_RECOMMENDATION_TEXT: string;
  REMEDIATION_RECOMMENDATION_URL: string;
  COMPLIANCE: string;
}

interface AggregatedFinding {
  CHECK_ID: string;
  STATUS: string;
  SEVERITY: string;
  SERVICE_NAME: string;
  RESOURCE_TYPE: string;
  SUBSERVICE_NAME: string;
  CHECK_TITLE: string;
  DESCRIPTION: string;
  RISK: string;
  REMEDIATION_RECOMMENDATION_TEXT: string;
  REMEDIATION_RECOMMENDATION_URL: string;
  COMPLIANCE: string;
  RESOURCES: Array<{
    RESOURCE_ARN: string;
    EXTENDED_STATUS: string;
  }>;
}

function normalizeRow(row: any): ProwlerRow {
  const isNewFormat = 'RESOURCE_UID' in row && !('RESOURCE_ARN' in row);
  if (isNewFormat) {
    return {
      ...row,
      RESOURCE_ARN: row.RESOURCE_UID || '',
      ACCOUNT_ID: row.ACCOUNT_UID || '',
    } as ProwlerRow;
  }
  return row as ProwlerRow;
}

function loadAndFilterCSV(filePath: string, severities: string[] = ['high', 'critical']): ProwlerRow[] {
  const csvContent = fs.readFileSync(filePath, 'utf-8');
  const parsed = Papa.parse<any>(csvContent, {
    header: true,
    skipEmptyLines: true,
  });
  return parsed.data
    .map(normalizeRow)
    .filter(row => row.STATUS === 'FAIL' && severities.includes(row.SEVERITY.toLowerCase()));
}

function aggregateData(csvData: ProwlerRow[]): Record<string, AggregatedFinding> {
  const result: Record<string, AggregatedFinding> = {};
  for (const row of csvData) {
    const displayTitle = fixCheckTitle(row.CHECK_TITLE);
    // Deduplicate by Service + Fixed Title to merge redundant checks (like Cloud SQL public IP)
    const findingKey = `${row.SERVICE_NAME}:${displayTitle}`;

    const resourceARNandStatus = {
      RESOURCE_ARN: row.RESOURCE_ARN,
      EXTENDED_STATUS: row.STATUS_EXTENDED,
    };
    const elem: AggregatedFinding = {
      CHECK_ID: row.CHECK_ID,
      STATUS: row.STATUS,
      SEVERITY: row.SEVERITY,
      SERVICE_NAME: row.SERVICE_NAME,
      RESOURCE_TYPE: row.RESOURCE_TYPE,
      SUBSERVICE_NAME: row.SUBSERVICE_NAME,
      CHECK_TITLE: displayTitle,
      DESCRIPTION: row.DESCRIPTION,
      RISK: row.RISK,
      REMEDIATION_RECOMMENDATION_TEXT: row.REMEDIATION_RECOMMENDATION_TEXT,
      REMEDIATION_RECOMMENDATION_URL: row.REMEDIATION_RECOMMENDATION_URL,
      COMPLIANCE: row.COMPLIANCE,
      RESOURCES: [],
    };
    if (!result[findingKey]) {
      result[findingKey] = elem;
    }
    if (!result[findingKey].RESOURCES) {
      result[findingKey].RESOURCES = [];
    }
    
    // Normalize resource ARN for comparison (extract name if it's a full path)
    const normalizedName = resourceARNandStatus.RESOURCE_ARN.split('/').pop();
    const isResourceDuplicate = result[findingKey].RESOURCES.some(
      r => r.RESOURCE_ARN.split('/').pop() === normalizedName
    );
    
    if (!isResourceDuplicate) {
      result[findingKey].RESOURCES.push(resourceARNandStatus);
    }
  }
  return result;
}

function getAIRecommendation(checkId: string, finding: AggregatedFinding): string {
  // Try to extract human-readable names from the extended status if the ARN is just an ID
  const resourceNames = finding.RESOURCES.map(r => {
    const nameMatch = r.EXTENDED_STATUS.match(/(?:Firewall|Instance|Bucket|Account|Project)\s+([^\s]+)/i);
    return nameMatch ? nameMatch[1] : r.RESOURCE_ARN.split('/').pop();
  });
  
  if (finding.SERVICE_NAME === 'compute') {
    if (checkId.includes('firewall_rdp_access_from_the_internet_allowed')) {
      return `To remove the overly permissive RDP firewall rule, you can use the gcloud command-line tool or the GCP Console.\n\n**Using gcloud:**\n\`gcloud compute firewall-rules delete ${resourceNames.join(' ')}\`\n\n**Using GCP Console:**\n1. Go to the Firewall Rules page in the GCP Console.\n2. Select the firewall rule (e.g., \`${resourceNames[0] || 'default-allow-rdp'}\`).\n3. Click Delete.`;
    }
    if (checkId.includes('firewall_ssh_access_from_the_internet_allowed')) {
      return `To remove the overly permissive SSH firewall rule, you can use the gcloud command-line tool or the GCP Console.\n\n**Using gcloud:**\n\`gcloud compute firewall-rules delete ${resourceNames.join(' ')}\`\n\n**Using GCP Console:**\n1. Go to the Firewall Rules page in the GCP Console.\n2. Select the firewall rule (e.g., \`${resourceNames[0] || 'allow-ssh'}\`).\n3. Click Delete.`;
    }
    if (checkId.includes('os_login_2fa_enabled')) {
      return `Enable OS Login and enforce 2FA at the project level:\n\`gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE,enable-oslogin-2fa=TRUE\``;
    }
  }

  if (finding.SERVICE_NAME === 'cloudstorage' && checkId.includes('public_access')) {
    return `To secure the buckets, enforce Public Access Prevention:\n${resourceNames.map(name => `\`gcloud storage buckets update gs://${name} --public-access-prevention\``).join('\n')}`;
  }

  if (finding.SERVICE_NAME === 'cloudsql') {
    let rec = "To secure your Cloud SQL instances, execute the following commands:\n";
    if (checkId.includes('automated_backups')) {
      rec += resourceNames.map(name => `1. **Enable Backups:** \`gcloud sql instances patch ${name} --backup-start-time 02:00\``).join('\n');
    } else if (checkId.includes('ssl_connections')) {
      rec += resourceNames.map(name => `1. **Enforce SSL:** \`gcloud sql instances patch ${name} --require-ssl\``).join('\n');
    } else if (checkId.includes('public_ip') || checkId.includes('private_ip')) {
      rec += resourceNames.map(name => `1. **Secure Access:** Remove the public IP and enable private connectivity (PSA or PSC).\n   - Remove public IP: \`gcloud sql instances patch ${name} --no-assign-ip\`\n   - Enable Private IP: \`gcloud sql instances patch ${name} --network=[VPC_NETWORK]\` (Ensure Service Networking is enabled).`).join('\n');
    } else if (checkId.includes('local_infile')) {
      rec += resourceNames.map(name => `1. **Set local_infile off:** \`gcloud sql instances patch ${name} --database-flags local_infile=off\``).join('\n');
    } else if (checkId.includes('enable_pgaudit')) {
      rec += resourceNames.map(name => `1. **Enable pgAudit:** \`gcloud sql instances patch ${name} --database-flags cloudsql.enable_pgaudit=on\``).join('\n');
    }
    return rec;
  }

  if (finding.SERVICE_NAME === 'iam' && checkId.includes('no_administrative_privileges')) {
    return `Audit and down-scope the identified service accounts. Example to remove editor role:\n\`gcloud projects remove-iam-policy-binding [PROJECT_ID] --member='serviceAccount:[SA_EMAIL]' --role='roles/editor'\``;
  }

  return "*[AI will provide GCP-specific recommendations here]*";
}

function fixCheckTitle(title: string): string {
  // Prowler titles often say "Ensure XXX is set to Y" or "Check if XXX is Y"
  // We want to turn them into affirmative finding titles like "XXX is not set to Y"
  let fixed = title.replace(/^Ensure\s+/i, '');
  fixed = fixed.replace(/^Check if\s+/i, '');
  
  // Specific handling for Cloud SQL Public IP titles to avoid double negatives
  if (fixed.includes('public IP address') || fixed.includes('no public IP addresses')) {
    return "Cloud SQL database instance has a public IP address assigned";
  }

  fixed = fixed.replace(/\s+is enabled$/i, ' is disabled');
  fixed = fixed.replace(/\s+is configured$/i, ' is not configured');
  fixed = fixed.replace(/\s+has no\s+/i, ' has ');
  fixed = fixed.replace(/\s+has\s+/i, ' does not have ');
  fixed = fixed.replace(/\s+does not have\s+/i, ' has '); // Fix for cases like "does not have a public IP" -> "has a public IP"
  
  // Specific overrides for the user's report
  if (fixed.includes('RDP')) return "Firewall rule allows ingress from 0.0.0.0/0 to TCP port 3389 (RDP)";
  if (fixed.includes('SSH') && fixed.includes('Internet')) return "Firewall rule allows ingress from 0.0.0.0/0 to TCP port 22 (SSH)";
  
  return fixed;
}

const PILLAR_MAPPING: Record<string, string> = {
  'apikeys': 'IAM Security',
  'artifacts': 'Data Security',
  'cloudsql': 'Data Security',
  'cloudstorage': 'Data Security',
  'compute': 'VM Security',
  'gcr': 'GKE Security',
  'iam': 'IAM Security',
  'logging': 'Security Operations',
  'monitoring': 'Security Operations',
  'dns': 'Network Security',
  'vpc': 'Network Security',
  'firewall': 'Network Security',
};

function getPillarName(serviceName: string, checkId: string): string {
  if (checkId.includes('firewall') || checkId.includes('vpc') || checkId.includes('dns')) return 'Network Security';
  if (checkId.includes('gke') || checkId.includes('kubernetes')) return 'GKE Security';
  return PILLAR_MAPPING[serviceName.toLowerCase()] || 'Other Resources';
}

function generateMarkdownReport(aggregatedData: Record<string, AggregatedFinding>, templatePath: string): string {
  const template = fs.readFileSync(templatePath, 'utf-8');
  const pillars: Record<string, string> = {
    'Resource Management': '',
    'VM Security': '',
    'Network Security': '',
    'IAM Security': '',
    'GKE Security': '',
    'K8s Security': '',
    'Data Security': '',
    'Security Operations': '',
    'Other Resources': ''
  };

  for (const [findingKey, finding] of Object.entries(aggregatedData)) {
    let resourcesList = '';
    for (const resource of finding.RESOURCES) {
      resourcesList += `- \`${resource.RESOURCE_ARN}\`\n`;
      resourcesList += `  ${resource.EXTENDED_STATUS}\n`;
    }
    
    const displayTitle = finding.CHECK_TITLE;
    const aiRecommendation = getAIRecommendation(finding.CHECK_ID, finding);
    
    // Deduplicate lines in AI recommendation (especially for merged findings)
    const uniqueRecLines = Array.from(new Set(aiRecommendation.split('\n')));
    const finalAiRec = uniqueRecLines.join('\n');

    const pillarName = getPillarName(finding.SERVICE_NAME, finding.CHECK_ID);

    let findingMarkdown = template
      .replace('{{CHECK_TITLE}}', displayTitle)
      .replace('{{SEVERITY}}', finding.SEVERITY.charAt(0).toUpperCase() + finding.SEVERITY.slice(1))
      .replace('{{SERVICE_NAME}}', finding.SERVICE_NAME)
      .replace('{{RISK}}', finding.RISK)
      .replace('{{REMEDIATION_RECOMMENDATION_TEXT}}', finding.REMEDIATION_RECOMMENDATION_TEXT)
      .replace('{{REMEDIATION_RECOMMENDATION_URL}}', finding.REMEDIATION_RECOMMENDATION_URL || '')
      .replace('{{RESOURCES_LIST}}', resourcesList.trim())
      .replace('*[AI will provide GCP-specific recommendations here]*', finalAiRec);

    if (!finding.REMEDIATION_RECOMMENDATION_URL) {
      findingMarkdown = findingMarkdown.replace('**More info:** \n\n', '');
    }
    
    pillars[pillarName] += findingMarkdown + '\n';
  }

  let finalMarkdown = '## Findings by Security Pillar\n\n';
  for (const [pillar, content] of Object.entries(pillars)) {
    if (content.trim()) {
      finalMarkdown += `## ${pillar}\n\n${content}\n---\n\n`;
    }
  }
  return finalMarkdown;
}

function main() {
  const args = process.argv.slice(2);
  let severities = ['high', 'critical'];
  let templateOverride: string | null = null;
  const positionalArgs: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--severity' && i + 1 < args.length) {
      severities = args[++i].split(',').map(s => s.trim().toLowerCase());
    } else if (args[i] === '--template' && i + 1 < args.length) {
      templateOverride = args[++i];
    } else {
      positionalArgs.push(args[i]);
    }
  }
  if (positionalArgs.length === 0) {
    console.error('Usage: tsx process-prowler-results.ts <path-to-prowler-csv> [output-path]');
    process.exit(1);
  }
  const csvFilePath = positionalArgs[0];
  const outputPath = positionalArgs[1];
  if (!fs.existsSync(csvFilePath)) {
    console.error(`Error: File not found: ${csvFilePath}`);
    process.exit(1);
  }
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const templatePath = templateOverride
    ? path.resolve(templateOverride)
    : path.resolve(scriptDir, 'templates/finding-template.md');
  if (!fs.existsSync(templatePath)) {
    console.error(`Error: Template file not found: ${templatePath}`);
    process.exit(1);
  }
  const filteredData = loadAndFilterCSV(csvFilePath, severities);
  const aggregatedData = aggregateData(filteredData);
  const markdownReport = generateMarkdownReport(aggregatedData, templatePath);
  const finalOutputPath = outputPath || csvFilePath.replace('.csv', '-report.md');
  fs.writeFileSync(finalOutputPath, markdownReport);
  console.log(`Report generated: ${finalOutputPath}`);
}

main();
