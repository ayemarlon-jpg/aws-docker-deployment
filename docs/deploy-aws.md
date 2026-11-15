# Put PhishGuard online (AWS)

When you're done, PhishGuard has a public HTTPS address that anyone can open, such as
`https://phishguard.abc123xyz.us-east-1.cs.amazonlightsail.com`. Every time code is merged into `main`, the new version deploys automatically.

You only do this setup once. It takes about 15 minutes and four steps:

1. Create the hosting in AWS by uploading one file.
2. Tell GitHub how to reach it by pasting two values.
3. Add your Claude API key.
4. Run the first deploy with one click.

**Cost:** the hosting is an AWS Lightsail container service. The default `micro` size has a fixed monthly price (about $10/month at the time of writing; see AWS's Lightsail pricing page). Claude API usage is billed separately by Anthropic. Each visitor can run 20 AI checks per hour and the whole site 500 per day, and you can change these limits. Rule-based checks are free and unlimited.

---

## Step 1: Create the hosting in AWS

1. Sign in to the [AWS console](https://console.aws.amazon.com/). Create an account first if you don't have one.
2. In the top-right corner, pick the region you want, for example **US East (N. Virginia) us-east-1**.
3. Download the template from GitHub: open `infra/aws-lightsail.yml` in this repository and click **Download raw file**.
4. Open **CloudFormation** (search for it in the top search bar), then **Create stack → With new resources (standard)**.
5. Choose **Upload a template file**, select `aws-lightsail.yml`, and click **Next**.
6. **Stack name:** `phishguard`. Leave the parameters at their defaults unless:
   - your GitHub repository has a different name. Change `GitHubRepository` to `owner/name`.
   - your account already connects to GitHub Actions through an identity provider. Set `CreateGitHubOIDCProvider` to `false`. If you're not sure, leave it as `true`; if the stack then fails with "already exists", delete the stack and retry with `false`.
7. Click **Next**, then **Next** again. Tick **"I acknowledge that AWS CloudFormation might create IAM resources"** and click **Submit**.
8. Wait until the status shows **CREATE_COMPLETE**. This takes about 2–5 minutes.
9. Open the **Outputs** tab and keep it open. You need `DeployRoleArn` and `Region` in the next step, and `PublicUrl` is your future web address.

**What this created:**
- An empty Lightsail container service, which is where PhishGuard will run.
- A deploy role that **only** this repository's `main` branch can use, through GitHub's short-lived tokens. No AWS passwords or keys are stored in GitHub.

## Step 2: Tell GitHub how to reach AWS

In your GitHub repository, go to **Settings → Secrets and variables → Actions → Variables** and click **New repository variable** for each of these:

| Name | Value |
|---|---|
| `AWS_ROLE_ARN` | The `DeployRoleArn` output, starting with `arn:aws:iam::` |
| `AWS_REGION` | The `Region` output, for example `us-east-1` |

These are optional but recommended for the Microsoft listing:

| Name | Value |
|---|---|
| `PHISHGUARD_PROVIDER_NAME` | Your company name, as it should appear on the privacy page and in Outlook |
| `PHISHGUARD_SUPPORT_EMAIL` | Your support email address |
| `PHISHGUARD_AI_LIMIT_PER_IP_HOUR` | AI checks per visitor per hour (default `20`) |
| `PHISHGUARD_AI_LIMIT_PER_DAY` | AI checks for the whole site per day (default `500`) |

## Step 3: Add your Claude API key

Go to **Settings → Secrets and variables → Actions → Secrets → New repository secret**:

| Name | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your key from https://console.anthropic.com/ (Settings → API keys) |

Without it, the site still works, but only the rule-based checks run.

These secrets are optional:
- `PHISHGUARD_API_KEY`: makes the API require an access key. Leave it unset for a public demo, since visitors would need the key.
- `PHISHGUARD_WEBHOOK_URL`: a Slack or Teams webhook that receives phishing alerts.

> Secrets are passed to the container as environment variables, which are visible to anyone with access to your Lightsail console. Keep your AWS account access limited to people you trust.

## Step 4: Deploy

Go to **Actions → Deploy to AWS → Run workflow → Run workflow**. Don't use **Re-run** on an older run that was skipped: a re-run reuses that run's old settings, so it won't see the variables you just added.

It takes about 5–10 minutes: tests, then build, upload, start-up and a health check. When it finishes, the run's summary page shows:

- **Web app:** your public address. Share it with anyone.
- **Outlook add-in manifest:** `<address>/addin/manifest.xml`. Use this for testing in Outlook and for the Microsoft listing (see `docs/microsoft-marketplace.md`).

From now on, **every merge into `main` deploys automatically**.

---

## Using your own domain (optional)

To use an address like `app.yourcompany.com`:
1. Open the [Lightsail console](https://lightsail.aws.amazon.com/), go to **Containers**, choose `phishguard`, then the **Custom domains** tab.
2. Create a certificate for your domain and add the DNS records it shows at your domain provider.
3. Attach the domain to the service once the certificate is validated.
4. In GitHub, add the repository variable `PHISHGUARD_PUBLIC_URL` = `https://app.yourcompany.com` and run **Deploy to AWS** again. The Outlook manifest and the health check will then use your domain. Do this **before** submitting to Microsoft, because the manifest's URLs are part of the listing.

## Troubleshooting

| Problem | Fix |
|---|---|
| The deploy job is skipped | `AWS_ROLE_ARN` isn't set, or it has a typo in the name. |
| `Not authorized to perform sts:AssumeRoleWithWebIdentity` | The `GitHubRepository` parameter doesn't match this repo, or you ran the workflow from a branch other than `main`. |
| The stack fails with "provider already exists" | Delete the stack and recreate it with `CreateGitHubOIDCProvider = false`. |
| The deployment shows FAILED | In the Lightsail console, open the `phishguard` service and the **Logs** tab to see why the container didn't start. |
| The page loads but says "Rules only" | `ANTHROPIC_API_KEY` isn't set. Add it and run the workflow again. |

## Turning it off

To stop paying for hosting, delete the `phishguard` stack in CloudFormation. That removes the container service and the deploy role.
