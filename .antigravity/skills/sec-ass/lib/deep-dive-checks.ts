import { execSync } from "node:child_process";

export function auditOrgPolicies(projectId: string): string {
  try {
    console.log(`[DEEP-DIVE] Auditing Organization Policies for ${projectId}...`);
    const output = execSync(`gcloud resource-manager org-policies list --project=${projectId} --format="table(constraint, booleanPolicy.enforced, listPolicy.allowedValues)"`, { encoding: 'utf-8' });
    
    if (output.trim().split('\n').length <= 1) {
      return `### Organization Policy Audit\n\n*No active project-level Organization Policy overrides were found. Standard organization-level guardrails may still apply.*`;
    }

    return `### Organization Policy Audit\n\n**Findings:**\n\`\`\`\n${output}\n\`\`\`\n\n**Note:** Organization policies provide top-down guardrails. Ensure sensitive constraints like \`compute.disableExternalIPs\` or \`iam.disableServiceAccountKeyCreation\` are enforced to match a Zero Trust architecture.`;
  } catch (e) {
    return `### Organization Policy Audit\n\n*Error: Could not retrieve Org Policies. Ensure you have the 'roles/orgpolicy.policyViewer' or 'roles/viewer' role.*`;
  }
}

export function auditNetworkTopology(projectId: string): string {
  try {
    console.log(`[DEEP-DIVE] Auditing Network Topology (VPC-SC & DNSSEC) for ${projectId}...`);
    const vpcSc = execSync(`gcloud access-context-manager perimeters list --project=${projectId} --format="table(name, title, status.resources)" 2>/dev/null || echo "No VPC-SC Access Context Manager access or perimeters found."`, { encoding: 'utf-8' });
    const dnsSec = execSync(`gcloud dns managed-zones list --project=${projectId} --format="table(name, dnsName, dnssecConfig.state)"`, { encoding: 'utf-8' });

    return `### Network Topology & Flow Audit\n\n**VPC Service Controls (VPC-SC):**\n\`\`\`\n${vpcSc}\n\`\`\`\n\n**Cloud DNSSEC Status:**\n\`\`\`\n${dnsSec}\n\`\`\``;
  } catch (e) {
    return `### Network Topology & Flow Audit\n\n*Error: Could not retrieve detailed network topology. Ensure necessary APIs (Access Context Manager, DNS) are enabled.*`;
  }
}

export function auditGKEHardening(projectId: string): string {
  try {
    console.log(`[DEEP-DIVE] Auditing GKE Hardening for ${projectId}...`);
    const clusters = execSync(`gcloud container clusters list --project=${projectId} --format="value(name, zone)"`, { encoding: 'utf-8' }).trim();
    
    if (!clusters) {
      return `### GKE Security Deep-Dive\n\n*No GKE clusters found in this project.*`;
    }

    let results = "";
    for (const line of clusters.split('\n')) {
      const [name, zone] = line.split('\t');
      const details = execSync(`gcloud container clusters describe ${name} --zone=${zone} --project=${projectId} --format="json(securityConfig, binaryAuthorization)"`, { encoding: 'utf-8' });
      results += `#### Cluster: ${name}\n\`\`\`json\n${details}\n\`\`\`\n`;
    }

    return `### GKE Security Deep-Dive\n\n${results}`;
  } catch (e) {
    return `### GKE Security Deep-Dive\n\n*Error: Could not retrieve GKE details. Ensure GKE API is enabled and you have container.viewer permissions.*`;
  }
}

export function auditIAMRecommender(projectId: string): string {
  try {
    console.log(`[DEEP-DIVE] Analyzing IAM Role Recommendations for ${projectId}...`);
    const output = execSync(`gcloud recommender insights list --project=${projectId} --location=global --insight-type=google.iam.policy.Insight --format="table(content.content.serviceAccount, content.content.currentRole, content.content.recommendedRole)"`, { encoding: 'utf-8' });
    
    if (output.trim().split('\n').length <= 1) {
      return `### IAM Least Privilege Analysis\n\nNo over-privileged roles were automatically identified by the GCP Recommender at this time. Always review manual assignments for 'Admin' or 'Owner' roles.`;
    }

    return `### IAM Least Privilege Analysis\n\n**GCP Recommendations:**\n\`\`\`\n${output}\n\`\`\`\n\n**Action:** Down-scope these identities to the recommended roles to minimize the blast radius of a credential compromise.`;
  } catch (e) {
    return `### IAM Least Privilege Analysis\n\n*Error: Could not retrieve IAM recommendations. Ensure the Recommender API is enabled and you have 'roles/recommender.iamViewer'.*`;
  }
}
