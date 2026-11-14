# Publishing PhishGuard on Microsoft AppSource

This guide takes PhishGuard from this repository to a listing that any Microsoft 365 user or admin can install from Outlook or the Microsoft 365 admin center.

**What's already built:**
- An Outlook add-in that adds a **Check for phishing** button to every email, on desktop, web and mobile (`phishguard/addin/`).
- A manifest generated for your domain at `https://<your-domain>/addin/manifest.xml`.
- Icons (16, 32, 64, 80, 128 and 300 px) in `phishguard/addin/assets/`.
- Privacy policy, terms of use and support pages at `/privacy`, `/terms` and `/support`.

**What only you can do:** create the Partner Center account, verify your identity and company, host the service on a public HTTPS domain, and submit the listing.

Microsoft changes Partner Center screens and policies regularly. If a step doesn't match what you see, follow Microsoft's current documentation ("Publish Office Add-ins to AppSource" and the "Commercial marketplace certification policies").

---

## Step 1: Set up the business side (allow 1–3 weeks)

1. **Get a business identity.** Microsoft verifies the publisher. A registered business (for example an LLC) with a matching website and email domain makes verification much easier than a personal account.
2. **Get a domain and a business email**, for example `phishguard.app` and `support@phishguard.app`. Don't use a Gmail address: verification and the support contact should be on your domain.
3. **Join the Microsoft AI Cloud Partner Program** at https://partner.microsoft.com. Then, in **Partner Center**, enroll in the **Marketplace offers** program. Use your business details exactly as they appear on official documents.
4. **Complete verification.** Microsoft emails the contact address and may ask for company documents. Your listing can't be published until this is done.

## Step 2: Host PhishGuard on a public HTTPS domain

The add-in runs inside Outlook, which loads it from your server, so the server must be reachable over HTTPS with a valid certificate.

1. Deploy the container to AWS, as described in the README (ECS Fargate or App Runner behind HTTPS).
2. Point a subdomain such as `app.phishguard.app` at it. Use AWS Certificate Manager for a free certificate.
3. Set these environment variables, keeping secrets in AWS Secrets Manager:

   | Variable | Example |
   |---|---|
   | `PHISHGUARD_PUBLIC_BASE_URL` | `https://app.phishguard.app` |
   | `PHISHGUARD_PROVIDER_NAME` | Your company name, exactly as verified in Partner Center |
   | `PHISHGUARD_SUPPORT_EMAIL` | `support@phishguard.app` |
   | `PHISHGUARD_HOSTING_REGION` | `the United States (us-east-1)` |
   | `PHISHGUARD_LEGAL_EFFECTIVE_DATE` | The date you publish the policies |
   | `ANTHROPIC_API_KEY` | Your Claude API key, so the AI verdict runs |

4. Check that these open in a browser:
   - `https://app.phishguard.app/addin/manifest.xml`, which should show your domain in every URL
   - `https://app.phishguard.app/addin/taskpane.html`
   - `/privacy`, `/terms`, `/support`

> **Keep `PHISHGUARD_ADDIN_ID` the same forever.** It identifies your add-in to Microsoft. The default ID in `config.py` is fine to use; just never change it after you submit. Increase `PHISHGUARD_ADDIN_VERSION` (for example `1.0.1.0`) whenever you resubmit.

## Step 3: Review the legal pages

`phishguard/legal/privacy.html` and `terms.html` are **starting templates, not legal advice**. Have them reviewed for the countries you sell in. Microsoft checks that the privacy policy accurately describes what happens to user data. In particular, it must say that email content is sent to Anthropic for AI analysis; the template already does. If you add storage, analytics or new sub-processors, update the policy first.

## Step 4: Test the add-in in your own Outlook

1. Download your manifest: `curl -o manifest.xml https://app.phishguard.app/addin/manifest.xml`
2. Validate it with Microsoft's tool (needs Node.js):
   ```bash
   npx office-addin-manifest validate manifest.xml
   ```
   Fix anything it reports before submitting.
3. Sideload it:
   - **Outlook on the web or new Outlook:** go to https://aka.ms/olksideload, open **My add-ins → Custom add-ins → Add a custom add-in → Add from file**, and choose `manifest.xml`.
   - **For a whole organization:** go to the Microsoft 365 admin center, **Settings → Integrated apps → Upload custom apps**.
4. Open an email and select **Check for phishing**. Test:
   - [ ] Outlook on the web, new Outlook for Windows, classic Outlook for Windows, Outlook for Mac, and Outlook mobile (iOS/Android)
   - [ ] A phishing email, a normal email, an email with attachments, and a very long email
   - [ ] Light and dark themes
   - [ ] What happens when the server is down: the pane must show a friendly error, never a blank pane
   - [ ] If you set `PHISHGUARD_API_KEY`, the access-key prompt and Settings flow

Microsoft's reviewers test on several Outlook clients, and a blank pane or crash on any of them is a common reason for rejection.

## Step 5: Create the listing in Partner Center

In **Partner Center → Marketplace offers → New offer → Office add-in**:

1. **Upload `manifest.xml`.**
2. **Write the listing:**
   - **Name:** PhishGuard (check that no existing listing uses the same name).
   - **Summary** (short): "Check any email for phishing in one click, with AI explanations."
   - **Description:** what it does, who it's for, what data it uses, and the fact that verdicts are guidance. Don't claim "100% protection" or similar guarantees; reviewers reject absolute claims.
   - **Category:** Security / Productivity.
   - **Screenshots:** 1366×768 PNG, at least one. Show the pane next to a phishing email and a safe email. The demo screenshots from this project are a good starting point, but they must show the add-in inside Outlook.
   - **Icons:** use `icon-300.png` for the store logo if a 300×300 image is requested.
   - **Privacy policy URL:** `https://app.phishguard.app/privacy`
   - **Support URL:** `https://app.phishguard.app/support`
   - **End-user license agreement:** link `https://app.phishguard.app/terms`, or choose Microsoft's standard contract.
3. **Testing notes for reviewers:** explain how to test, for example: "Open any email and select Check for phishing. To see a phishing verdict, forward yourself the sample in this note." If you require an access key, **you must give the reviewers a working key here**, otherwise they can't test the add-in and will reject it.
4. **Licensing:** the simplest path is to list the add-in as **free**. Charge for the service through your own website, with the access key, or link a paid SaaS offer later (see below).
5. **Submit.** Validation usually takes from a few days to a couple of weeks. If it's rejected, the report lists the policy it failed; fix it, increase the version, and resubmit.

## Step 6: After approval

- Users can install it from **Outlook → Get Add-ins** by searching for "PhishGuard".
- Admins can deploy it to everyone from the **Microsoft 365 admin center → Integrated apps → Get apps**.
- To update the add-in's look or behavior, change the files on your server; users pick it up the next time it loads. **Manifest changes**, such as new buttons, permissions or URLs, need a version bump and a new Partner Center submission.

---

## Charging money

| Option | How it works | Effort |
|---|---|---|
| **Free listing + your own billing** (recommended first) | The listing is free. Customers subscribe on your website (for example with Stripe) and get an organization access key (`PHISHGUARD_API_KEY`). | Lowest: works with today's code if each customer runs their own deployment. Multi-customer keys need building. |
| **Linked SaaS offer** | Publish a separate "SaaS" offer in Partner Center and link the add-in to it, so Microsoft handles purchase and invoicing per user or per tenant. | Higher: needs a landing page and Microsoft's SaaS Fulfillment API with Entra ID sign-in. |

## Gaps to close before a large-scale launch

- **Multi-customer accounts:** today one deployment shares one access key. To sell to many organizations from a single deployment, add per-organization keys or Microsoft (Entra ID) sign-in, with usage tracking per organization.
- **AI cost control:** for high volume, send only unclear emails to Claude and use a cheaper model where accuracy holds.
- **Optional Microsoft 365 App Compliance:** after launch, completing Microsoft's Publisher Attestation and Microsoft 365 Certification makes security-conscious buyers far more comfortable, which matters for a security product.
