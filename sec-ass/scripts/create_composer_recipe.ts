import { parseArgs } from "node:util";
import { translateGcloudToComposerRecipe, publishRecipeToDoiTConsole, pushToComposerNativeAPI, resolveComposerToken } from "./composer_recipe_engine.js";

async function main() {
    const { values } = parseArgs({
        options: {
            gcloud: { type: "string" },
            title: { type: "string" },
            description: { type: "string" },
            severity: { type: "string" },
            projectId: { type: "string" },
            token: { type: "string" },
            customerId: { type: "string" }
        }
    });

    const gcloudCmd = values.gcloud;
    if (!gcloudCmd) {
        console.error("✖ Error: --gcloud remediation command is required.");
        process.exit(1);
    }

    const customerId = values.customerId || "EE8CtpzYiKp0dVAESVrB";

    console.log(`[RECIPE-BUILDER] Translating gcloud remediation into DCI Composer Recipe...`);
    const recipe = translateGcloudToComposerRecipe(gcloudCmd, {
        title: values.title,
        description: values.description,
        severity: (values.severity as any) || "high"
    });

    console.log(`\n--- Generated DCI Composer Recipe ---`);
    console.log(JSON.stringify(recipe, null, 2));

    // 1. Publish to Insights via dci CLI (OAuth SSO)
    console.log(`\n[RECIPE-BUILDER] 1. Publishing Insight via dci CLI (SSO Auth)...`);
    publishRecipeToDoiTConsole(recipe);

    // 2. Automated POST to Native Composer Engine API (/operate/composer)
    console.log(`\n[RECIPE-BUILDER] 2. Executing automated POST to Native Composer Engine (/operate/composer)...`);
    const nativeResult = await pushToComposerNativeAPI(recipe, customerId, values.token);

    if (nativeResult.success) {
        console.log(`🎉 Success! Native Composer Recipe Created! View at: ${nativeResult.url}`);
    } else {
        console.log(`ℹ Notice on Native Rules POST: ${nativeResult.error}`);
        console.log(`To enable automatic POST to /operate/composer, store your session token once in ~/.dci_composer_token:`);
        console.log(`  echo "YOUR_TOKEN" > ~/.dci_composer_token`);
    }
}

main().catch(err => {
    console.error("✖ Fatal Error:", err);
    process.exit(1);
});
