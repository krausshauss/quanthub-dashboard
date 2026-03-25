# QuantHub Sales Rep Scorecard

Standalone HTML scorecard for QuantHub Higher Education sales team.  
Built by Dark Yeti Inc. — for internal use only.

## Setup (GitHub Pages)

1. Create a new GitHub repository (can be private with GitHub Pro, or public)
2. Upload `index.html` to the repository root
3. Go to **Settings → Pages → Source → Deploy from branch → main → / (root)**
4. GitHub will provide a URL: `https://yourusername.github.io/repo-name`
5. In HubSpot: **Dashboard → Add widget → External content / Custom widget → paste URL**

## Weekly Update

1. Export HubSpot Higher Education pipeline as CSV
2. Open `index.html` in VS Code or any text editor
3. Find the `SCORECARD_DATA` block near the top of the `<script>` tag
4. Update values for each rep: `cw_amount`, `pipeline_value`, `active_deals`, `stale_7d`, activity counts, deal list
5. Update `WEEK_LABEL` and `EXPORT_DATE`
6. Commit and push — GitHub Pages auto-deploys in ~30 seconds
7. HubSpot iframe refreshes on next dashboard load

## Scoring Weights

| Pillar | Weight |
|---|---|
| CW Revenue to Quota | 40% |
| Deal Velocity | 25% |
| Qualified Activity | 20% |
| Deal Quality | 15% |
| Expansion Bonus | up to +8 pts |

## Notes

- SMS/text touches are self-reported in standup — enter manually in `text_touches_week`
- Matthew Fickling is on extended leave — his AUDIT deals remain visible in pipeline tab
- UNC Pembroke deal (MK) needs HubSpot amount/stage update ASAP
