import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

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
      console.log(`[DEEP-DIVE] Auditing external config for GKE cluster: ${name}...`);
      
      // 1. External GCP Control Plane Audit
      const details = execSync(`gcloud container clusters describe ${name} --zone=${zone} --project=${projectId} --format="json(securityConfig, binaryAuthorization, privateClusterConfig)"`, { encoding: 'utf-8' });
      
      results += `#### Cluster: ${name} (GCP-Plane Config)\n\`\`\`json\n${details}\n\`\`\`\n`;

      // 2. Internal Kubernetes Configuration Audit (Leveraging GKE Remote MCP / kubectl capabilities)
      try {
        results += `\n##### Internal Cluster Security Assessment (${name})\n`;

        // Check if pre-cached MCP data exists
        const mcpDataFile = path.resolve(`assessments/${projectId}/gke_mcp_data_${name}.json`);
        let mcpData: any = null;

        if (fs.existsSync(mcpDataFile)) {
          console.log(`[DEEP-DIVE] Found cached MCP data at ${mcpDataFile}, using GKE Remote MCP offline data...`);
          try {
            mcpData = JSON.parse(fs.readFileSync(mcpDataFile, 'utf-8'));
          } catch (parseErr: any) {
            console.error(`[DEEP-DIVE] Error parsing MCP data file: ${parseErr.message}`);
          }
        }

        // If no cached MCP data, configure kubectl as fallback
        if (!mcpData) {
          try {
            console.log(`[DEEP-DIVE] No MCP cached data. Attempting local kubectl configuration...`);
            execSync(`gcloud container clusters get-credentials ${name} --zone=${zone} --project=${projectId}`, { stdio: 'ignore' });
          } catch (credErr: any) {
            console.warn(`[DEEP-DIVE] Failed to get credentials for cluster ${name}: ${credErr.message}`);
          }
        }

        // Check for Pod Security (Privileged Containers)
        try {
          let podList: any = null;
          if (mcpData && mcpData.pods) {
            podList = mcpData.pods;
          } else {
            const pods = execSync(`kubectl get pods --all-namespaces -o json`, { encoding: 'utf-8' });
            podList = JSON.parse(pods);
          }

          let privilegedPods: string[] = [];
          let rootPods: string[] = [];
          
          if (podList && podList.items) {
            for (const pod of podList.items) {
              const ns = pod.metadata.namespace;
              const podName = pod.metadata.name;
              const containers = pod.spec.containers || [];
              const initContainers = pod.spec.initContainers || [];
              
              for (const c of [...containers, ...initContainers]) {
                const secCtx = c.securityContext || {};
                if (secCtx.privileged === true) {
                  privilegedPods.push(`${ns}/${podName} (${c.name})`);
                }
                if (secCtx.runAsUser === 0) {
                  rootPods.push(`${ns}/${podName} (${c.name})`);
                }
              }
            }
          }

          results += `*   **Pod Security (Privileged Containers):**\n`;
          if (privilegedPods.length > 0) {
            results += `    *   ⚠️ **Warning:** The following containers are running with \`privileged: true\` (bypasses isolation boundaries):\n`;
            privilegedPods.forEach(p => results += `        *   \`${p}\`\n`);
          } else {
            results += `    *   ✅ **Success:** No pods running in privileged mode detected.\n`;
          }

          if (rootPods.length > 0) {
            results += `    *   ⚠️ **Warning:** The following containers are running as Root (\`runAsUser: 0\`):\n`;
            rootPods.forEach(p => results += `        *   \`${p}\`\n`);
          }
        } catch (podErr) {
          results += `*   **Pod Security:** *Unable to audit pods. Verify cluster is active and credentials or MCP data are correct.*\n`;
        }

        // Check for Network Isolation (Network Policies)
        try {
          let netpolList: any = null;
          if (mcpData && mcpData.networkpolicies) {
            netpolList = mcpData.networkpolicies;
          } else {
            const netpols = execSync(`kubectl get networkpolicies --all-namespaces -o json`, { encoding: 'utf-8' });
            netpolList = JSON.parse(netpols);
          }

          const count = netpolList.items ? netpolList.items.length : 0;
          
          results += `*   **Network Isolation (Network Policies):**\n`;
          if (count === 0) {
            results += `    *   ⚠️ **Warning:** Zero Network Policies detected in the cluster. Lateral communication is unrestricted between all pods.\n`;
          } else {
            results += `    *   ✅ **Success:** Detected \`${count}\` active Network Policies providing network-level isolation.\n`;
          }
        } catch (netErr) {
          results += `*   **Network Isolation:** *Unable to audit network policies.*\n`;
        }

        // Check for RBAC exposure (cluster-admin bindings)
        try {
          let crbList: any = null;
          if (mcpData && mcpData.clusterrolebindings) {
            crbList = mcpData.clusterrolebindings;
          } else {
            const crbs = execSync(`kubectl get clusterrolebindings -o json`, { encoding: 'utf-8' });
            crbList = JSON.parse(crbs);
          }

          let adminBindings: string[] = [];
          
          if (crbList && crbList.items) {
            for (const crb of crbList.items) {
              if (crb.roleRef && crb.roleRef.name === 'cluster-admin') {
                const subjects = crb.subjects || [];
                subjects.forEach((s: any) => {
                  adminBindings.push(`${s.kind}: \`${s.name}\` (Namespace: \`${s.namespace || 'all'}\`)`);
                });
              }
            }
          }

          results += `*   **RBAC Least-Privilege (Cluster Admin Bindings):**\n`;
          if (adminBindings.length > 0) {
            results += `    *   ⚠️ **Notice:** Detected the following identities bound to \`cluster-admin\` role:\n`;
            adminBindings.forEach(b => results += `        *   ${b}\n`);
          } else {
            results += `    *   ✅ **Success:** No excessive cluster-admin bindings found.\n`;
          }
        } catch (rbacErr) {
          results += `*   **RBAC Least-Privilege:** *Unable to audit RBAC ClusterRoleBindings.*\n`;
        }

      } catch (mcpErr) {
        results += `\n*Note: Could not run internal GKE cluster audit. GKE Remote MCP server or kubectl client is unavailable.*\n`;
      }
      results += `\n---\n`;
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
