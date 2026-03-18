# CrowdStrike Falcon Health Check

<<<<<<< HEAD
Generates an interactive HTML + Excel report with the health status of a CrowdStrike Falcon tenant. Built for consultants, partners, and MSSPs who need to deliver a professional health check to their clients.
=======
Genera un reporte interactivo HTML + Excel con el estado de salud de un tenant CrowdStrike Falcon. Pensado para consultores, partners y MSSPs que necesitan entregar un health check profesional a sus clientes.
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![FalconPy](https://img.shields.io/badge/CrowdStrike-FalconPy-red)

<<<<<<< HEAD
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
=======
## Qué incluye el reporte

| Sección | Descripción |
|---------|-------------|
| **Resumen ejecutivo** | KPIs: total de sensores, sensores activos, versión del sensor, cobertura por OS |
| **Sensor Health** | Distribución por versión, sensores desactualizados, plataformas (Win/Mac/Linux) |
| **Políticas de prevención** | Matriz ON/OFF por setting y por política (tabs Windows / Mac / Linux) |
| **NG SIEM** | Conectores de datos, estado de conexión, volumen de ingesta diaria vs límite |
| **Detecciones / Alertas** | Severidad, top hosts afectados, tendencia temporal, detalle por detección |
| **Hosts** | Listado completo con OS, versión de sensor, última conexión, políticas asignadas |

## Output

- `health_check.html` — reporte self-contained (Bootstrap 5 + Chart.js), compartible por email o abriendo en cualquier browser
- `health_check.xlsx` — Excel con múltiples hojas para análisis detallado

## Requisitos
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac

```
pip install crowdstrike-falconpy pandas openpyxl python-dotenv
```

<<<<<<< HEAD
## Setup

1. Copy the example config:
=======
## Configuración

1. Copiá el archivo de ejemplo:
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac
   ```bash
   cp .env.example .env
   ```

<<<<<<< HEAD
2. Edit `.env` with your credentials:
   ```env
   FALCON_CLIENT_ID=your_client_id
   FALCON_CLIENT_SECRET=your_client_secret
   CS_CLIENT_NAME=Client Name
   ```

3. If your tenant is not on US-1, set the base URL:
=======
2. Editá `.env` con tus credenciales:
   ```env
   FALCON_CLIENT_ID=tu_client_id
   FALCON_CLIENT_SECRET=tu_client_secret
   CS_CLIENT_NAME=Nombre del Cliente
   ```

3. Si tu tenant no está en US-1, configurá la URL base:
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac
   ```env
   # US-1 (default): https://api.crowdstrike.com
   # US-2:           https://api.us-2.crowdstrike.com
   # EU-1:           https://api.eu-1.crowdstrike.com
   # GOV:            https://api.laggar.gcw.crowdstrike.com
   CS_BASE_URL=https://api.us-2.crowdstrike.com
   ```

<<<<<<< HEAD
### Required API Client Scopes

| Scope | Permission | Purpose |
|-------|------------|---------|
| Hosts | Read | List sensors, versions, platforms |
| Prevention Policies | Read | Prevention policy settings matrix |
| Alerts | Read | Detections and alerts (API v2) |
| Detections | Read | Fallback if Alerts API is unavailable |

### NG SIEM (optional)

The NG SIEM search API (LogScale/Humio) requires special enablement by your CrowdStrike TAM for API client credentials. Until then, data can be entered manually in `.env`:
=======
### Scopes requeridos en el API Client

| Scope | Permiso | Para qué |
|-------|---------|----------|
| Hosts | Read | Listar sensores, versiones, plataformas |
| Prevention Policies | Read | Matriz de políticas de prevención |
| Alerts | Read | Detecciones y alertas (API v2) |
| Detections | Read | Fallback si Alerts no está disponible |

### NG SIEM (opcional)

La API de búsqueda de NG SIEM (LogScale/Humio) requiere habilitación especial por parte del TAM de CrowdStrike para clientes con API credentials. Mientras tanto, los datos se cargan manualmente en el `.env`:
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac

```env
CS_NGSIEM_LIMIT_GB=10
CS_NGSIEM_AVG_GB=0.76
CS_NGSIEM_TODAY_MB=1.1
CS_NGSIEM_CONNECTORS=Netskope SSE:Active:8.55MB,Entra ID:Error:0B,Windows and AD:Idle:0B
```

<<<<<<< HEAD
Connector format is `Name:Status:Ingest24h` separated by commas. Values can be copied from the Falcon UI at **Next-Gen SIEM > Data connectors**.

## Usage
=======
El formato de conectores es `Nombre:Estado:Ingesta24h` separados por coma. Los datos se pueden copiar desde la UI de Falcon en **Next-Gen SIEM > Data connectors**.

## Uso
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac

```bash
python health_check_export_v3.py
```

<<<<<<< HEAD
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
=======
El script:
1. Verifica los scopes del API token al inicio
2. Descarga sensores, políticas y detecciones
3. Intenta la API de Alerts v2; si falla, usa Detections como fallback
4. Infiere conectores NG SIEM desde alertas XDR + datos manuales del `.env`
5. Genera `health_check.html` y `health_check.xlsx`

## MSSP / Multi-tenant

Para apuntar a un tenant hijo (child CID):

```env
FALCON_MEMBER_CID=el_cid_del_tenant_hijo
```

## Estructura

```
crwd-falconpy/
├── health_check_export_v3.py   # Script principal
├── .env.example                # Template de configuración
├── .env                        # Credenciales (no se sube a Git)
├── .gitignore                  # Excluye .env, .xlsx, .html
└── README.md
```

## Notas

- El reporte HTML es **self-contained**: incluye CSS (Bootstrap 5.3) y JS (Chart.js 4) via CDN. Se puede compartir como archivo único.
- Los datos de NG SIEM se actualizan manualmente en `.env` hasta que CrowdStrike habilite el acceso vía API client credentials.
- El script detecta automáticamente si el tenant usa la API de Detections (legacy) o Alerts v2.

## Licencia
>>>>>>> 925aa7a65ab6740a0be60e6a10a7a0e14b9b8cac

MIT
