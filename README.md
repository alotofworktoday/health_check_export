# CrowdStrike Falcon Health Check

Generates an interactive HTML + Excel report with the health status of a CrowdStrike Falcon tenant. Built for consultants, partners, and MSSPs who need to deliver a professional health check to their clients.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![FalconPy](https://img.shields.io/badge/CrowdStrike-FalconPy-red)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Health Score (0-100)** — Weighted score across 6 categories with animated donut chart
- **Professional cover page** — Gradient design with client name, date, KPIs, and confidentiality notice
- **Risk vs Friction matrix** — Maps each prevention setting to its security risk (if OFF) and operational friction (if ON), helping clients prioritize what to enable
- **Policy compliance bars** — Visual % of prevention settings enabled per platform (Windows/Mac/Linux)
- **MITRE ATT&CK mapping** — Detections broken down by tactic
- **NG SIEM visibility** — Data connectors status, ingest volume vs. limit
- **Print-optimized** — One-click PDF export with proper page breaks

## Report Sections

| Section | Description |
|---------|-------------|
| **Executive Summary** | Health Score donut, score breakdown by category, KPI cards (sensors, RFM, inactive, critical detections), platform distribution, severity/status charts, policy compliance bars |
| **Sensor Health** | Sensor age by platform (N/N-1/N-2/N-3+), version distribution, OS versions, sensor update policies |
| **Prevention Policies** | ON/OFF matrix per setting per policy (Windows / Mac / Linux tabs) |
| **Risk vs Friction** | Each prevention setting mapped to: risk if disabled, operational friction if enabled, current state across policies |
| **NG SIEM** | Data connectors, connection status, daily ingest volume, inferred sources from XDR alerts |
| **Detections / Alerts** | Severity breakdown, MITRE tactics, top 10 affected hosts, daily trend, full detail table with search |
| **Hosts** | Full inventory with OS, sensor version, last seen, assigned policies, searchable |

## Health Score Breakdown

| Category (weight) | What it measures |
|--------------------|-----------------|
| Sensor Freshness (25%) | % of sensors on version N or N-1 |
| Policy Compliance (25%) | % of prevention settings set to ON |
| Sensor Activity (15%) | % of sensors active in last 14 days |
| Detection Resolution (15%) | % of detections in closed/resolved state |
| RFM Free (10%) | % of sensors NOT in Reduced Functionality Mode |
| NG SIEM Usage (10%) | NG SIEM active + connector health |

## Output

- `health_check.html` — Self-contained report (Bootstrap 5 + Chart.js via CDN), shareable as a single file
- `health_check.xlsx` — Multi-sheet Excel with raw data + Health Score sheet

## Requirements

```
pip install crowdstrike-falconpy pandas openpyxl python-dotenv
```

## Setup

1. Copy the example config:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your credentials:
   ```env
   FALCON_CLIENT_ID=your_client_id
   FALCON_CLIENT_SECRET=your_client_secret
   CS_CLIENT_NAME=Client Name
   ```

3. If your tenant is not on US-1, set the base URL:
   ```env
   # US-1 (default): https://api.crowdstrike.com
   # US-2:           https://api.us-2.crowdstrike.com
   # EU-1:           https://api.eu-1.crowdstrike.com
   # GOV:            https://api.laggar.gcw.crowdstrike.com
   CS_BASE_URL=https://api.us-2.crowdstrike.com
   ```

### Required API Client Scopes

| Scope | Permission | Purpose |
|-------|------------|---------|
| Hosts | Read | List sensors, versions, platforms |
| Prevention Policies | Read | Prevention policy settings matrix |
| Alerts | Read | Detections and alerts (API v2) |
| Detections | Read | Fallback if Alerts API is unavailable |

### NG SIEM (optional)

The NG SIEM search API (LogScale/Humio) requires special enablement by your CrowdStrike TAM for API client credentials. Until then, data can be entered manually in `.env`:

```env
CS_NGSIEM_LIMIT_GB=10
CS_NGSIEM_AVG_GB=0.76
CS_NGSIEM_TODAY_MB=1.1
CS_NGSIEM_CONNECTORS=Netskope SSE:Active:8.55MB,Entra ID:Error:0B,Windows and AD:Idle:0B
```

Connector format is `Name:Status:Ingest24h` separated by commas. Values can be copied from the Falcon UI at **Next-Gen SIEM > Data connectors**.

## Usage

```bash
python health_check_export_v3.py
```

The script will:
1. Verify API token scopes at startup
2. Pull sensors, policies, and detections
3. Try the Alerts v2 API; fall back to Detections if unavailable
4. Infer NG SIEM connectors from XDR alerts + manual `.env` overrides
5. Compute health score and risk matrix
6. Generate `health_check.html` and `health_check.xlsx`

## MSSP / Multi-tenant

To target a child tenant (member CID):

```env
FALCON_MEMBER_CID=child_tenant_cid
```

## Project Structure

```
crwd-falconpy/
├── health_check_export_v3.py   # Main script
├── .env.example                # Config template
├── .env                        # Credentials (not tracked by Git)
├── .gitignore                  # Excludes .env, .xlsx, .html
└── README.md
```

## Notes

- The HTML report is **self-contained**: CSS (Bootstrap 5.3) and JS (Chart.js 4) are loaded via CDN. It can be shared as a single file.
- NG SIEM data is populated manually via `.env` until CrowdStrike enables direct API access for client credentials.
- The script auto-detects whether the tenant uses the legacy Detections API or the newer Alerts v2 API.
- The Risk vs Friction matrix includes 18+ prevention settings with curated descriptions based on CrowdStrike best practices.

## License

MIT
