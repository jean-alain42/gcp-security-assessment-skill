import { execSync } from "node:child_process";

export function auditOrgPolicies(projectId: string): string {
  try {
    console.log(`[DEEP-DIVE] Auditing Organization Policies for ${projectId}...`);
    // We use --format=json for easier parsing or just table for the report
    const output = execSync(`gcloud resource-manager org-policies list --project=${projectId} --format="table(constraint, booleanPolicy.enforced, listPolicy.allowedValues)"`, { encoding: 'utf-8' });
    
    return `### Organization Policy Audit\n\n**Findings:**\n\`\`\`\n${output}\n\`\`\`\n\n**Note:** Organization policies provide top-down guardrails. Ensure sensitive constraints like \`compute.disableExternalIPs\` or \`iam.disableServiceAccountKeyCreation\` are enforced to match a Zero Trust architecture.`;
  } catch (e) {
    return `### Organization Policy Audit\n\n*Error: Could not retrieve Org Policies. Ensure you have the 'roles/orgpolicy.policyViewer' or 'roles/viewer' role.*`;
  }
}

export function auditIAMRecommender(projectId: string): string {
  try {
    console.log(`[DEEP-DIVE] Analyzing IAM Role Recommendations for ${projectId}...`);
    // The recommender API identifies over-privileged accounts
    const output = execSync(`gcloud recommender insights list --project=${projectId} --location=global --insight-type=google.iam.policy.Insight --format="table(content.content.serviceAccount, content.content.currentRole, content.content.recommendedRole)"`, { encoding: 'utf-8' });
    
    if (!output.trim()) {
      return `### IAM Least Privilege Analysis\n\nNo over-privileged roles were automatically identified by the GCP Recommender at this time. Always review manual assignments for 'Admin' or 'Owner' roles.`;
    }

    return `### IAM Least Privilege Analysis\n\n**GCP Recommendations:**\n\`\`\`\n${output}\n\`\`\`\n\n**Action:** Down-scope these identities to the recommended roles to minimize the blast radius of a credential compromise.`;
  } catch (e) {
    return `### IAM Least Privilege Analysis\n\n*Error: Could not retrieve IAM recommendations. Ensure the Recommender API is enabled and you have 'roles/recommender.iamViewer'.*`;
  }
}
