# CrowdStrike Falcon Health Check

Generates an interactive HTML + Excel report with the health status of a CrowdStrike Falcon tenant. Built for consultants, partners, and MSSPs who need to deliver a professional health check to their clients.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![FalconPy](https://img.shields.io/badge/CrowdStrike-FalconPy-red)

## Report Sections

| Section | Description |
|---------|-------------|
| **Executive Summary** | KPIs: total sensors, active sensors, sensor version, OS coverage |
| **Sensor Health** | Version distribution, outdated sensors, platforms (Win/Mac/Linux) |
| **Prevention Policies** | ON/OFF matrix per setting per policy (Windows / Mac / Linux tabs) |
| **NG SIEM** | Data connectors, connection status, daily ingest volume vs. limit |
| **Detections / Alerts** | Severity breakdown, top affected hosts, timeline trend, per-detection detail |
| **Hosts** | Full inventory with OS, sensor version, last seen, assigned policies |

## Output

- `health_check.html` — self-contained report (Bootstrap 5 + Chart.js via CDN), shareable by email or opened in any browser
- `health_check.xlsx` — multi-sheet Excel for detailed analysis

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
5. Generate `health_check.html` and `health_check.xlsx`

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

## License

MIT
