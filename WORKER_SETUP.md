# Cloudflare Worker Setup — 5 minutes

This proxy keeps your GitHub token server-side so it never appears in public code.

## Step 1 — Create a Cloudflare account
Go to cloudflare.com → Sign up (free, no credit card needed)

## Step 2 — Create the Worker
1. Go to **Workers & Pages** in the Cloudflare dashboard
2. Click **Create** → **Create Worker**
3. Name it `quanthub-proxy` (or anything you like)
4. Click **Deploy** (deploys a hello world placeholder)
5. Click **Edit code**
6. Select all the placeholder code and delete it
7. Paste the entire contents of `cloudflare-worker.js`
8. Click **Deploy**

## Step 3 — Add your GitHub token as a secret
1. In your Worker, go to **Settings** → **Variables and Secrets**
2. Click **Add** → **Secret**
3. Name: `GITHUB_TOKEN` · Value: your token (ghp_...)
4. Click **Add**
5. Add another secret:
   - Name: `ADMIN_PIN` · Value: `7777` (or your PIN)
6. Add one more:
   - Name: `ALLOWED_ORIGIN` · Value: `https://krausshauss.github.io`
7. Click **Deploy** again to apply secrets

## Step 4 — Get your Worker URL
Your Worker URL appears at the top of the Worker page:
`https://quanthub-proxy.YOURNAME.workers.dev`

## Step 5 — Add Worker URL to index.html
Open `index.html`, find this line near the top of the script:
```
const WORKER_URL = '';
```
Paste your Worker URL between the quotes:
```
const WORKER_URL = 'https://quanthub-proxy.YOURNAME.workers.dev';
```
Save and upload `index.html` to GitHub.

## Step 6 — Upload both files to GitHub repo
- `index.html` (with WORKER_URL filled in)
- `data.json` (the empty `{}` placeholder)

## That's it!
- Page loads → fetches data.json via Worker → scorecard appears
- Load New Data → PIN → upload CSVs → Worker commits data.json to repo
- All viewers see updated data within ~60 seconds
- Your GitHub token never appears in any file
