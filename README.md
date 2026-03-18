# CrowdStrike Falcon Health Check

Genera un reporte interactivo HTML + Excel con el estado de salud de un tenant CrowdStrike Falcon. Pensado para consultores, partners y MSSPs que necesitan entregar un health check profesional a sus clientes.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![FalconPy](https://img.shields.io/badge/CrowdStrike-FalconPy-red)

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

```
pip install crowdstrike-falconpy pandas openpyxl python-dotenv
```

## Configuración

1. Copiá el archivo de ejemplo:
   ```bash
   cp .env.example .env
   ```

2. Editá `.env` con tus credenciales:
   ```env
   FALCON_CLIENT_ID=tu_client_id
   FALCON_CLIENT_SECRET=tu_client_secret
   CS_CLIENT_NAME=Nombre del Cliente
   ```

3. Si tu tenant no está en US-1, configurá la URL base:
   ```env
   # US-1 (default): https://api.crowdstrike.com
   # US-2:           https://api.us-2.crowdstrike.com
   # EU-1:           https://api.eu-1.crowdstrike.com
   # GOV:            https://api.laggar.gcw.crowdstrike.com
   CS_BASE_URL=https://api.us-2.crowdstrike.com
   ```

### Scopes requeridos en el API Client

| Scope | Permiso | Para qué |
|-------|---------|----------|
| Hosts | Read | Listar sensores, versiones, plataformas |
| Prevention Policies | Read | Matriz de políticas de prevención |
| Alerts | Read | Detecciones y alertas (API v2) |
| Detections | Read | Fallback si Alerts no está disponible |

### NG SIEM (opcional)

La API de búsqueda de NG SIEM (LogScale/Humio) requiere habilitación especial por parte del TAM de CrowdStrike para clientes con API credentials. Mientras tanto, los datos se cargan manualmente en el `.env`:

```env
CS_NGSIEM_LIMIT_GB=10
CS_NGSIEM_AVG_GB=0.76
CS_NGSIEM_TODAY_MB=1.1
CS_NGSIEM_CONNECTORS=Netskope SSE:Active:8.55MB,Entra ID:Error:0B,Windows and AD:Idle:0B
```

El formato de conectores es `Nombre:Estado:Ingesta24h` separados por coma. Los datos se pueden copiar desde la UI de Falcon en **Next-Gen SIEM > Data connectors**.

## Uso

```bash
python health_check_export_v3.py
```

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

MIT
