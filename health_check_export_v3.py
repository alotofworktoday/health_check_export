import os, logging, itertools, json
from datetime import datetime, timedelta, timezone
import pandas as pd
from dotenv import load_dotenv
from falconpy import APIHarnessV2, Hosts, Detects, Alerts, APIError, FoundryLogScale
load_dotenv()

# ---------------------------
# Configuración
# ---------------------------
CID  = os.getenv("FALCON_CLIENT_ID")  or os.getenv("CS_CLIENT_ID")
SEC  = os.getenv("FALCON_CLIENT_SECRET") or os.getenv("CS_CLIENT_SECRET")
BASE = os.getenv("FALCON_BASE_URL") or os.getenv("CS_BASE_URL") or "https://api.crowdstrike.com"
MCID = os.getenv("FALCON_MEMBER_CID")
CLIENT_NAME = os.getenv("CS_CLIENT_NAME", "")          # Nombre del cliente (opcional)
LIMIT    = int(os.getenv("CS_PAGE_LIMIT", "5000"))
OUT_XLSX = os.getenv("CS_OUT_XLSX", "health_check.xlsx")
OUT_HTML = os.getenv("CS_OUT_HTML", "health_check.html")

# NG SIEM — datos manuales (cargados del .env) para cuando la API no es accesible
# Leer desde el .env: CS_NGSIEM_LIMIT_GB, CS_NGSIEM_AVG_GB, CS_NGSIEM_TODAY_MB
# CS_NGSIEM_CONNECTORS = "Netskope SSE:Active:8.55MB, Entra ID:Error:0B, Windows and AD:Idle:0B, VSQualys:Pending:0B, Test-Forti:Pending:0B"
NGSIEM_LIMIT_GB  = float(os.getenv("CS_NGSIEM_LIMIT_GB", "0"))
NGSIEM_AVG_GB    = float(os.getenv("CS_NGSIEM_AVG_GB", "0"))
NGSIEM_TODAY_MB  = float(os.getenv("CS_NGSIEM_TODAY_MB", "0"))
NGSIEM_CONNECTORS_RAW = os.getenv("CS_NGSIEM_CONNECTORS", "")  # "name:status:ingest24h, ..."

if not CID or not SEC:
    raise SystemExit("Definí FALCON_CLIENT_ID / FALCON_CLIENT_SECRET en el entorno.")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

TRUE_SET  = {"true", "on", "enabled", "enable", "1", True, 1}
FALSE_SET = {"false", "off", "disabled", "disable", "0", False, 0}

def norm_bool(v):
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"yes","y"}: return "ON"
        if s in {"no","n"}:  return "OFF"
        if s in TRUE_SET:    return "ON"
        if s in FALSE_SET:   return "OFF"
        return v.upper()
    if isinstance(v, bool):  return "ON" if v else "OFF"
    if isinstance(v, (int, float)): return "ON" if v else "OFF"
    return str(v)

def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i+n]

# ---------------------------
# API helpers
# ---------------------------
def query_combined(api, collection, flt):
    r = api.command(collection, filter=flt, limit=LIMIT)
    if r.status_code != 200:
        raise APIError(code=r.status_code, message=str(r.body))
    return r.data or []

def get_policies_via_ids(api, query_op, get_op, flt):
    kw = {"limit": LIMIT, "filter": flt}
    q = api.command(query_op, **kw)
    if q.status_code != 200:
        raise APIError(code=q.status_code, message=str(q.body))
    ids = q.body.get("resources", []) or []
    out = []
    for i in range(0, len(ids), 100):
        got = api.command(get_op, ids=ids[i:i+100])
        if got.status_code == 200:
            out += got.body.get("resources", []) or []
    return out

def fetch_all_aids(hosts, flt=None):
    aids, after = [], None
    while True:
        kw = {"limit": LIMIT}
        if flt:
            kw["filter"] = flt
        if after:
            kw["after"] = after
        r = hosts.query_devices_by_filter_scroll(**kw)
        if r.get("status_code") != 200:
            raise APIError(code=r.get("status_code"), message=str(r))
        body = r.get("body", {})
        pagination = body.get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)
        page = body.get("resources", []) or []
        aids.extend(page)
        after = pagination.get("after") or ""
        logging.info("fetch_all_aids: page=%d fetched=%d total_api=%d has_after=%s",
                     len(page), len(aids), total, bool(after))
        if not page or not after or (total and len(aids) >= total):
            break
    return aids

def fetch_host_details(hosts, aids):
    rows = []
    for chunk in chunked(aids, 100):
        det = hosts.get_device_details(ids=chunk)
        if det.get("status_code") != 200:
            continue
        rows.extend(det.get("body", {}).get("resources", []) or [])
    return rows

# ---------------------------
# Flatten settings (políticas)
# ---------------------------
def flatten_policy_settings(policy):
    base = {
        "policy_id":      policy.get("id"),
        "policy_name":    policy.get("name"),
        "platform_name":  policy.get("platform_name"),
        "policy_enabled": policy.get("enabled"),
        "description":    policy.get("description", "")
    }
    rows = []
    if isinstance(policy.get("settings"), dict):
        for k, v in policy["settings"].items():
            rows.append({**base, "category": "", "setting_id": k,
                         "setting_name": k, "value_raw": v, "value_norm": norm_bool(v)})
    for key in ("prevention_settings", "settings_blocks", "rules", "configuration", "policy_settings"):
        if isinstance(policy.get(key), list):
            for blk in policy[key]:
                cat = blk.get("name") or blk.get("category") or ""
                for s in blk.get("settings", []):
                    rows.append({
                        **base,
                        "category":     cat,
                        "setting_id":   s.get("id"),
                        "setting_name": s.get("name") or s.get("label") or s.get("key") or s.get("id"),
                        "value_raw":    s.get("value"),
                        "value_norm":   norm_bool(s.get("value"))
                    })
    if not rows:
        rows.append({**base, "category": "", "setting_id": "", "setting_name": "",
                     "value_raw": None, "value_norm": None})
    return rows

# ---------------------------
# Sensor age buckets
# ---------------------------
def version_key(ver):
    parts = []
    for p in (ver or "").split("."):
        try: parts.append(int(p))
        except: parts.append(0)
    return tuple(parts + [0]*4)[:4]

def sensor_age_counts_exact(df_hosts, platform):
    d = df_hosts[df_hosts["platform_name"].str.lower() == platform.lower()].copy()
    if d.empty or "agent_version" not in d:
        return {"N": 0, "N-1": 0, "N-2": 0, "N-3_plus": 0, "Unsupported": 0}
    counts = d.groupby("agent_version").size().reset_index(name="cnt")
    counts["k"] = counts["agent_version"].apply(version_key)
    counts = counts.sort_values("k")
    unique = counts["agent_version"].tolist()
    if not unique:
        return {"N": 0, "N-1": 0, "N-2": 0, "N-3_plus": 0, "Unsupported": 0}
    N   = unique[-1]
    N_1 = unique[-2] if len(unique) >= 2 else None
    N_2 = unique[-3] if len(unique) >= 3 else None
    older = set(unique[:-3]) if len(unique) > 3 else set()
    mc = dict(zip(counts["agent_version"], counts["cnt"]))
    return {
        "N":        mc.get(N, 0),
        "N-1":      mc.get(N_1, 0) if N_1 else 0,
        "N-2":      mc.get(N_2, 0) if N_2 else 0,
        "N-3_plus": sum(mc.get(v, 0) for v in older),
        "Unsupported": 0
    }

# ---------------------------
# Detections
# ---------------------------
def list_detect_ids(detects, time_filter="created_timestamp:>='-180d'",
                    page_limit=500, max_ids=20000):
    ids, offset = [], 0
    while True:
        q = detects.query_detects(filter=time_filter, limit=page_limit, offset=offset) if time_filter \
            else detects.query_detects(limit=page_limit, offset=offset)
        if q.get("status_code") != 200:
            break
        page = (q.get("body", {}) or {}).get("resources", []) or []
        if not page:
            break
        ids.extend(page)
        offset += len(page)
        if max_ids is not None and len(ids) >= max_ids:
            ids = ids[:max_ids]; break
    return ids

def export_detections(detects, time_filter="created_timestamp:>='-90d'",
                      max_ids=20000, chunk_size=100):
    empty_cols = ["detection_id","created_timestamp","status","severity","user_name",
                  "device_id","hostname","platform_name","os_version","local_ip","site_name","ou",
                  "behavior_id","tactic","technique","objective","indicator","filename",
                  "sha256","md5","command_line"]
    ids = list_detect_ids(detects, time_filter=time_filter, max_ids=max_ids)
    if not ids:
        return pd.DataFrame(columns=empty_cols)
    rows = []
    for i in range(0, len(ids), chunk_size):
        chunk = ids[i:i+chunk_size]
        det = detects.get_detect_summaries(ids=chunk)
        if det.get("status_code") != 200:
            continue
        for r in (det.get("body", {}) or {}).get("resources", []) or []:
            det_id = r.get("detection_id") or r.get("id") or ""
            dev    = r.get("device", {}) or {}
            base   = {
                "detection_id":  det_id,
                "created_timestamp": r.get("created_timestamp",""),
                "status":   r.get("status",""),
                "severity": r.get("severity",""),
                "user_name":r.get("user_name",""),
                "device_id":    dev.get("device_id") or dev.get("aid",""),
                "hostname":     dev.get("hostname",""),
                "platform_name":dev.get("platform_name",""),
                "os_version":   dev.get("os_version",""),
                "local_ip":     dev.get("local_ip",""),
                "site_name":    dev.get("site_name",""),
                "ou":           dev.get("ou",""),
            }
            behaviors = r.get("behaviors") or []
            if not behaviors:
                rows.append({**base, "behavior_id":"","tactic":"","technique":"",
                             "objective":"","indicator":"","filename":"","sha256":"","md5":"","command_line":""})
                continue
            for b in behaviors:
                rows.append({**base,
                    "behavior_id":  b.get("id",""),
                    "tactic":       b.get("tactic",""),
                    "technique":    b.get("technique",""),
                    "objective":    b.get("objective",""),
                    "indicator":    b.get("indicator",""),
                    "filename":     b.get("filename",""),
                    "sha256":       b.get("sha256",""),
                    "md5":          b.get("md5",""),
                    "command_line": b.get("command_line",""),
                })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["created_timestamp"] = pd.to_datetime(df["created_timestamp"], errors="coerce", utc=True)
        sev_map = {"INFORMATIONAL":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
        df["severity_num"] = df["severity"].map(lambda s: sev_map.get(str(s).upper(), pd.NA))
    return df

# ---------------------------
# Alerts API (nuevo) — fallback cuando Detects devuelve vacío
# ---------------------------
def export_alerts(alerts_cli: Alerts,
                  days_back: int = 90,
                  max_ids: int = 20000,
                  chunk_size: int = 100) -> pd.DataFrame:
    """
    Usa la API de Alerts v2 (XDR + thirdparty).
    Requiere composite_ids para el detalle. Mapea al mismo schema
    que export_detections() para compatibilidad con el resto del código,
    más campos XDR extras (source_product, source_vendor, alert_name).
    """
    empty_cols = ["detection_id","created_timestamp","status","severity","user_name",
                  "device_id","hostname","platform_name","os_version","local_ip","site_name","ou",
                  "behavior_id","tactic","technique","objective","indicator","filename",
                  "sha256","md5","command_line","alert_name","source_product","source_vendor","alert_type"]

    # Alerts API requiere timestamp absoluto en ISO 8601
    since = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    time_filter = f"created_timestamp:>='{since}'"
    logging.info("Alerts filter: %s", time_filter)

    # Query composite_ids
    ids, offset = [], 0
    while True:
        q = alerts_cli.query_alerts_v2(filter=time_filter, limit=500, offset=offset)
        if q.get("status_code") != 200:
            logging.warning("Alerts query_alerts_v2 status %s: %s", q.get("status_code"),
                            (q.get("body",{}).get("errors") or [{}])[0].get("message",""))
            break
        page = (q.get("body", {}) or {}).get("resources", []) or []
        if not page:
            break
        ids.extend(page)
        offset += len(page)
        if max_ids and len(ids) >= max_ids:
            ids = ids[:max_ids]; break

    logging.info("Alerts total IDs: %d", len(ids))
    if not ids:
        return pd.DataFrame(columns=empty_cols)

    rows = []
    for i in range(0, len(ids), chunk_size):
        chunk = ids[i:i+chunk_size]
        # ⚠ La API de Alerts v2 usa composite_ids, NO ids
        det = alerts_cli.get_alerts_v2(composite_ids=chunk)
        if det.get("status_code") != 200:
            logging.warning("get_alerts_v2 chunk %d status %s", i, det.get("status_code"))
            continue
        for r in (det.get("body", {}) or {}).get("resources", []) or []:
            # Endpoint info: XDR alerts NO tienen device dict — usan host_names/source_hosts
            host_names    = r.get("host_names") or r.get("source_hosts") or []
            hostname      = host_names[0] if host_names else ""
            source_prods  = r.get("source_products") or []
            source_vendors= r.get("source_vendors") or []
            user_names    = r.get("user_names") or []
            users         = r.get("users") or []
            user_name     = (user_names or users or [""])[0] if (user_names or users) else (r.get("user_name") or "")

            # Intenta extraer host detail si hay un device dict (alerts de endpoint)
            dev  = r.get("device") or {}
            rows.append({
                "detection_id":    r.get("composite_id") or r.get("id",""),
                "created_timestamp": r.get("created_timestamp",""),
                "status":          r.get("status",""),
                "severity":        r.get("severity_name") or str(r.get("severity","")),
                "user_name":       user_name or dev.get("agent_loaded_by",""),
                "device_id":       dev.get("device_id") or dev.get("agent_id",""),
                "hostname":        dev.get("hostname") or hostname,
                "platform_name":   dev.get("platform_name",""),
                "os_version":      dev.get("os_version",""),
                "local_ip":        dev.get("local_ip") or (r.get("local_address_ip4") or ""),
                "site_name":       dev.get("site_name",""),
                "ou":              dev.get("ou",""),
                "behavior_id":     "",
                "tactic":          r.get("tactic") or "",
                "technique":       r.get("technique") or r.get("display_name",""),
                "objective":       r.get("objective",""),
                "indicator":       (r.get("destination_ips") or r.get("source_ips") or [""])[0] if isinstance(r.get("destination_ips") or r.get("source_ips"), list) else "",
                "filename":        "",
                "sha256":          "",
                "md5":             "",
                "command_line":    "",
                # Campos XDR extras
                "alert_name":      r.get("display_name") or r.get("name",""),
                "source_product":  ", ".join(str(p) for p in source_prods),
                "source_vendor":   ", ".join(str(v) for v in source_vendors),
                "alert_type":      r.get("type",""),
            })

    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=empty_cols)
    if not df.empty:
        df["created_timestamp"] = pd.to_datetime(df["created_timestamp"], errors="coerce", utc=True)
        sev_map = {"INFORMATIONAL":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
        df["severity_num"] = df["severity"].map(lambda s: sev_map.get(str(s).upper(), pd.NA))
    return df


def check_api_scopes(cid, sec, base, mcid=None):
    """Prueba rápida de qué APIs son accesibles con el API key dado."""
    results = {}
    tests = {
        "hosts:read":       lambda: Hosts(client_id=cid, client_secret=sec, base_url=base, member_cid=mcid)
                                    .query_devices_by_filter_scroll(limit=1),
        "detections:read":  lambda: Detects(client_id=cid, client_secret=sec, base_url=base, member_cid=mcid)
                                    .query_detects(limit=1),
        "alerts:read":      lambda: Alerts(client_id=cid, client_secret=sec, base_url=base, member_cid=mcid)
                                    .query_alerts_v2(limit=1),
        "loggingapi:read":  lambda: FoundryLogScale(client_id=cid, client_secret=sec, base_url=base, member_cid=mcid)
                                    .list_repos(),
    }
    for scope, fn in tests.items():
        try:
            r = fn()
            sc = r.get("status_code") if isinstance(r, dict) else getattr(r, "status_code", None)
            results[scope] = "OK" if sc == 200 else f"HTTP {sc}"
        except Exception as e:
            results[scope] = f"ERROR: {e}"
    return results


# ---------------------------
# NG SIEM / LogScale
# ---------------------------
def _parse_ngsiem_connectors(raw: str) -> list[dict]:
    """Parsea CS_NGSIEM_CONNECTORS: 'Nombre:Estado:Ingest24h, ...' → lista de dicts."""
    if not raw:
        return []
    rows = []
    status_colors = {"active":"#28a745","error":"#dc3545","idle":"#ffc107",
                     "pending":"#6c757d","disconnected":"#dc3545","paused":"#adb5bd"}
    for item in raw.split(","):
        parts = [p.strip() for p in item.strip().split(":")]
        if len(parts) >= 1:
            name   = parts[0]
            status = parts[1] if len(parts) > 1 else ""
            ingest = parts[2] if len(parts) > 2 else "0 B"
            rows.append({
                "name":         name,
                "status":       status,
                "ingest_24h":   ingest,
                "status_color": status_colors.get(status.lower(), "#6c757d"),
            })
    return rows


def infer_ngsiem_from_alerts(df_dets: pd.DataFrame) -> dict:
    """
    Extrae info de NG SIEM inferida desde los campos XDR de Alerts:
    source_products, source_vendors, alert_type.
    Retorna un dict compatible con fetch_ngsiem_metrics().
    """
    if df_dets.empty:
        return {"repos": [], "views": [], "daily_stats": pd.DataFrame(),
                "connectors": [], "available": False,
                "error": "Sin datos de Alerts para inferir conectores",
                "inferred": True}

    connectors = set()
    products   = set()
    vendors    = set()

    for col in ["source_product", "source_vendor", "alert_type"]:
        if col not in df_dets.columns:
            continue
        for val in df_dets[col].dropna():
            for item in str(val).split(","):
                item = item.strip()
                if item and item.lower() not in ("", "nan", "none"):
                    if col == "source_product": products.add(item)
                    elif col == "source_vendor":  vendors.add(item)
                    connectors.add(item)

    # Daily event count inferred from Alerts timestamps
    daily_stats = pd.DataFrame()
    if "created_timestamp" in df_dets.columns:
        td = df_dets.dropna(subset=["created_timestamp"]).copy()
        td["date"] = td["created_timestamp"].dt.strftime("%Y-%m-%d")
        agg = td.groupby("date")["detection_id"].nunique().reset_index()
        agg.columns = ["date", "events"]
        agg["gb"]     = 0.0   # No podemos calcular GB sin acceso directo a NG SIEM
        agg["source"] = "all"
        daily_stats = agg.sort_values("date")

    # Repos/views con info resumida
    repos = [{"name": "(NG SIEM - XDR Insight)", "description": "Inferido desde Alerts API",
               "retention_days": "—", "compressed_gb": 0.0, "event_count": len(df_dets)}]

    # Conectores manuales (del .env) tienen prioridad sobre los inferidos
    manual_connectors = _parse_ngsiem_connectors(NGSIEM_CONNECTORS_RAW)

    return {
        "repos":              repos,
        "views":              [],
        "daily_stats":        daily_stats,
        "connectors":         sorted(connectors),
        "products":           sorted(products),
        "vendors":            sorted(vendors),
        "manual_connectors":  manual_connectors,
        "limit_gb":           NGSIEM_LIMIT_GB,
        "avg_gb_day":         NGSIEM_AVG_GB,
        "today_mb":           NGSIEM_TODAY_MB,
        "available":          True,
        "inferred":           True,
        "error":              "Acceso directo al API de NG SIEM requiere activación por CrowdStrike. "
                              "Datos del portal completados manualmente.",
    }


def fetch_ngsiem_metrics(cid, sec, base, mcid=None):
    """
    Retorna un dict con:
      repos        — lista de repositorios LogScale
      views        — lista de vistas
      daily_stats  — DataFrame con ingesta diaria (date, gb, events) últimos 7 días
      connectors   — lista de conectores/fuentes detectados via query
      available    — bool: si el tenant tiene NG SIEM activo
    """
    empty = {"repos": [], "views": [], "daily_stats": pd.DataFrame(),
             "connectors": [], "available": False, "error": None, "inferred": False}
    try:
        ls = FoundryLogScale(client_id=cid, client_secret=sec, base_url=base, member_cid=mcid)

        # ---- Repositorios
        r_repos = ls.list_repos()
        repos = []
        if r_repos.get("status_code") == 200:
            repos = r_repos.get("body", {}).get("resources", []) or []

        # ---- Vistas
        r_views = ls.list_views()
        views = []
        if r_views.get("status_code") == 200:
            views = r_views.get("body", {}).get("resources", []) or []

        if not repos and not views:
            return {**empty, "error": "Sin repositorios/vistas — NG SIEM no activo o sin permisos"}

        # ---- Ingesta diaria: ejecutamos una query LogScale asíncrona
        # La query agrupa eventos por día y fuente para los últimos 7 días
        INGEST_QUERY = (
            "groupby([@source, bucket(span=1d, field=@timestamp)], "
            "function=[count(as=events), sum(@rawstring_size, as=bytes)])"
        )
        daily_stats = pd.DataFrame()
        connectors  = []

        # Intentamos con el primer repo disponible (usualmente "falcon" o el principal)
        target_repo = repos[0].get("name", "falcon") if repos else "falcon"
        body = {
            "repo_or_view": target_repo,
            "parameters": {
                "query_string": INGEST_QUERY,
                "start": "7d",
                "end":   "now",
            }
        }
        r_exec = ls.create_saved_searches_dynamic_execute_alt_v1(body=body)
        job_id = None
        if r_exec.get("status_code") in (200, 201):
            job_id = (r_exec.get("body", {}) or {}).get("job_id") or \
                     ((r_exec.get("body", {}) or {}).get("resources") or [{}])[0].get("job_id")

        if job_id:
            import time
            # Polling hasta que el job termine (máx 30s)
            for _ in range(10):
                time.sleep(3)
                r_status = ls.get_saved_searches_job_results_redirect_v1(job_id=job_id)
                sc = r_status.get("status_code")
                if sc == 200:
                    resources = (r_status.get("body", {}) or {}).get("resources") or []
                    if resources:
                        rows = []
                        for ev in resources:
                            src   = ev.get("@source") or ev.get("source") or "unknown"
                            ts    = ev.get("_bucket") or ev.get("@timestamp", "")[:10]
                            evts  = int(ev.get("events", 0) or 0)
                            bytes_= int(ev.get("bytes", 0) or 0)
                            gb    = round(bytes_ / 1e9, 4)
                            rows.append({"date": ts, "source": src, "events": evts, "gb": gb})
                        if rows:
                            daily_stats = pd.DataFrame(rows)
                            # Conectores únicos
                            connectors = sorted(daily_stats["source"].dropna().unique().tolist())
                    break
                elif sc == 202:
                    continue   # todavía procesando
                else:
                    break

        # Si la query no devolvió datos, intentamos una query más simple de conteo global
        if daily_stats.empty:
            body2 = {
                "repo_or_view": target_repo,
                "parameters": {
                    "query_string": "groupby(bucket(span=1d, field=@timestamp), function=[count(as=events)])",
                    "start": "7d", "end": "now",
                }
            }
            r2 = ls.create_saved_searches_dynamic_execute_alt_v1(body=body2)
            job2 = None
            if r2.get("status_code") in (200, 201):
                job2 = ((r2.get("body", {}) or {}).get("resources") or [{}])[0].get("job_id")
            if job2:
                import time
                for _ in range(10):
                    time.sleep(3)
                    rs2 = ls.get_saved_searches_job_results_redirect_v1(job_id=job2)
                    if rs2.get("status_code") == 200:
                        res2 = (rs2.get("body", {}) or {}).get("resources") or []
                        if res2:
                            rows2 = [{"date": e.get("_bucket","")[:10],
                                      "source": "all",
                                      "events": int(e.get("events",0) or 0),
                                      "gb": 0.0} for e in res2]
                            daily_stats = pd.DataFrame(rows2)
                        break
                    elif rs2.get("status_code") == 202:
                        continue
                    else:
                        break

        return {
            "repos":       repos,
            "views":       views,
            "daily_stats": daily_stats,
            "connectors":  connectors,
            "available":   True,
            "error":       None,
        }

    except Exception as e:
        logging.warning("NG SIEM no accesible: %s", e)
        return {**empty, "error": str(e)}


# ---------------------------
# Health Score & Recommendations
# ---------------------------
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {"critical":"#7d1128","high":"#dc3545","medium":"#fd7e14","low":"#ffc107","info":"#0dcaf0"}
SEVERITY_BG = {"critical":"rgba(125,17,40,.1)","high":"rgba(220,53,69,.08)","medium":"rgba(253,126,20,.08)","low":"rgba(255,193,7,.06)","info":"rgba(13,202,240,.06)"}

def compute_health_score(df_hosts, df_prev, df_dets, df_sensor_age_counts, ngsiem):
    """Calcula un score 0-100 basado en múltiples factores."""
    scores = {}  # category -> (score 0-100, weight)
    total_sensors = len(df_hosts) if not df_hosts.empty else 0

    # 1. Sensor freshness (25 pts) — % sensores en N o N-1
    if not df_sensor_age_counts.empty and total_sensors > 0:
        combined = df_sensor_age_counts[df_sensor_age_counts["platform"]=="Combined"]
        if not combined.empty:
            r = combined.iloc[0]
            fresh = int(r.get("N",0)) + int(r.get("N-1",0))
            pct_fresh = fresh / total_sensors * 100 if total_sensors else 0
            scores["sensor_freshness"] = (min(pct_fresh, 100), 25)
        else:
            scores["sensor_freshness"] = (50, 25)
    else:
        scores["sensor_freshness"] = (0, 25)

    # 2. Sensor activity (15 pts) — % sensores activos (no inactive 14d)
    if not df_hosts.empty and "is_inactive_14d" in df_hosts:
        active_pct = (1 - df_hosts["is_inactive_14d"].mean()) * 100
        scores["sensor_activity"] = (active_pct, 15)
    else:
        scores["sensor_activity"] = (100, 15)

    # 3. RFM (10 pts) — % sensores sin RFM
    if not df_hosts.empty:
        rfm = df_hosts["rfm_state"].apply(lambda x: str(x).lower() in ("true","yes","1") if pd.notna(x) else False)
        rfm_pct = (1 - rfm.mean()) * 100
        scores["rfm"] = (rfm_pct, 10)
    else:
        scores["rfm"] = (100, 10)

    # 4. Policy compliance (25 pts) — % prevention settings ON
    if not df_prev.empty and "value_norm" in df_prev:
        on_count = (df_prev["value_norm"].str.upper() == "ON").sum()
        total = len(df_prev[df_prev["value_norm"].notna()])
        pct = on_count / total * 100 if total else 0
        scores["policy_compliance"] = (pct, 25)
    else:
        scores["policy_compliance"] = (0, 25)

    # 5. Detection resolution (15 pts) — % detecciones cerradas
    if not df_dets.empty and "status" in df_dets:
        closed = df_dets["status"].str.lower().isin(["closed","resolved","true_positive","false_positive"])
        pct_closed = closed.mean() * 100
        scores["detection_resolution"] = (pct_closed, 15)
    else:
        scores["detection_resolution"] = (100, 15)

    # 6. NG SIEM usage (10 pts)
    ng = ngsiem or {}
    if ng.get("available"):
        ng_score = 50  # baseline for having it
        if ng.get("manual_connectors") or ng.get("connectors"):
            active_conns = sum(1 for c in (ng.get("manual_connectors") or []) if c.get("status","").lower() == "active")
            total_conns = len(ng.get("manual_connectors") or ng.get("connectors") or [])
            if total_conns:
                ng_score = 50 + (active_conns / total_conns * 50)
        scores["ngsiem"] = (ng_score, 10)
    else:
        scores["ngsiem"] = (0, 10)

    # Weighted average
    total_weight = sum(w for _, w in scores.values())
    weighted = sum(s * w for s, w in scores.values())
    overall = round(weighted / total_weight) if total_weight else 0

    return {
        "overall": overall,
        "breakdown": {k: round(v[0], 1) for k, v in scores.items()},
        "weights": {k: v[1] for k, v in scores.items()},
    }


def generate_recommendations(df_hosts, df_prev, df_dets, df_sensor_age_counts, ngsiem):
    """Genera recomendaciones priorizadas basadas en los datos recopilados."""
    recs = []
    total_sensors = len(df_hosts) if not df_hosts.empty else 0

    # --- Sensor Freshness ---
    if not df_sensor_age_counts.empty and total_sensors > 0:
        combined = df_sensor_age_counts[df_sensor_age_counts["platform"]=="Combined"]
        if not combined.empty:
            r = combined.iloc[0]
            old = int(r.get("N-3_plus",0))
            pct_old = old / total_sensors * 100 if total_sensors else 0
            if pct_old > 20:
                recs.append({"severity":"high","category":"Sensor Health","title":f"{old} sensores ({pct_old:.0f}%) en versiones N-3 o anteriores",
                    "detail":f"Hay {old} dispositivos con versiones de sensor muy desactualizadas. Esto implica falta de protección contra amenazas nuevas y posibles vulnerabilidades en el agente.",
                    "mitigation":"Revisar las Sensor Update Policies. Verificar que las políticas tengan habilitada la actualización automática. Para hosts offline, planificar actualización manual o via herramienta de deployment."})
            elif pct_old > 5:
                recs.append({"severity":"medium","category":"Sensor Health","title":f"{old} sensores ({pct_old:.0f}%) en versiones N-3 o anteriores",
                    "detail":"Un grupo de dispositivos tiene sensores desactualizados.",
                    "mitigation":"Verificar que las Sensor Update Policies estén configuradas con actualización automática y que los hosts tengan conectividad al cloud de CrowdStrike."})

    # --- Inactive sensors ---
    if not df_hosts.empty and "is_inactive_14d" in df_hosts:
        inactive = int(df_hosts["is_inactive_14d"].sum())
        pct_inactive = inactive / total_sensors * 100 if total_sensors else 0
        if pct_inactive > 15:
            recs.append({"severity":"high","category":"Sensor Health","title":f"{inactive} sensores ({pct_inactive:.0f}%) inactivos hace más de 14 días",
                "detail":"Estos hosts no reportan al cloud de CrowdStrike. Pueden estar apagados, desinstalados, o sin conexión.",
                "mitigation":"Identificar los hosts inactivos en la sección de Hosts. Cruzar con el inventario de IT para determinar si son hosts dados de baja. Para hosts válidos, verificar conectividad de red al cloud de CrowdStrike (*.crowdstrike.com)."})
        elif inactive > 0:
            recs.append({"severity":"medium","category":"Sensor Health","title":f"{inactive} sensores inactivos (>14 días sin reportar)",
                "detail":"Algunos hosts no reportan al cloud. Revisar si son hosts legítimos.",
                "mitigation":"Revisar el listado de hosts inactivos y determinar si corresponde dar de baja o reconectar los sensores."})

    # --- RFM ---
    if not df_hosts.empty:
        rfm = df_hosts["rfm_state"].apply(lambda x: str(x).lower() in ("true","yes","1") if pd.notna(x) else False)
        rfm_count = int(rfm.sum())
        if rfm_count > 0:
            recs.append({"severity":"critical","category":"Sensor Health","title":f"{rfm_count} sensores en Reduced Functionality Mode (RFM)",
                "detail":"Los sensores en RFM tienen capacidades limitadas de detección y prevención. Esto puede deberse a licencia vencida, incompatibilidad de kernel, o problemas de espacio en disco.",
                "mitigation":"Para cada host en RFM: verificar espacio en disco (mínimo 500MB libres), verificar compatibilidad del kernel con la versión de agente, y contactar soporte de CrowdStrike si persiste."})

    # --- Policy Compliance ---
    if not df_prev.empty and "value_norm" in df_prev:
        for plat in ["Windows","Mac","Linux"]:
            dp = df_prev[df_prev["platform_name"].str.upper()==plat.upper()]
            if dp.empty:
                continue
            off_settings = dp[dp["value_norm"].str.upper()=="OFF"]
            if not off_settings.empty:
                n_off = len(off_settings)
                n_total = len(dp[dp["value_norm"].notna()])
                pct_off = n_off / n_total * 100 if n_total else 0
                # Get unique setting names that are OFF
                off_names = off_settings["setting_name"].unique()[:5]
                sev = "high" if pct_off > 40 else "medium" if pct_off > 20 else "low"
                recs.append({"severity":sev,"category":f"Políticas ({plat})",
                    "title":f"{n_off} settings de prevención deshabilitados ({pct_off:.0f}%)",
                    "detail":f"Settings OFF incluyen: {', '.join(str(s) for s in off_names)}{'...' if len(off_names)>=5 else ''}",
                    "mitigation":f"Revisar la configuración de Prevention Policies para {plat}. Habilitar detección y prevención para: Machine Learning, Ransomware, Exploit Mitigation, Script-Based Execution Monitoring. Evaluar el impacto antes de cambiar a prevención en producción."})

        # Check if any policy is fully disabled
        if "policy_enabled" in df_prev:
            disabled_pols = df_prev[df_prev["policy_enabled"]==False]["policy_name"].unique()
            if len(disabled_pols) > 0:
                recs.append({"severity":"critical","category":"Políticas",
                    "title":f"{len(disabled_pols)} política(s) de prevención deshabilitada(s)",
                    "detail":f"Políticas deshabilitadas: {', '.join(str(p) for p in disabled_pols[:5])}. Los hosts asignados a estas políticas NO tienen protección de prevención activa.",
                    "mitigation":"Habilitar las políticas de prevención deshabilitadas o reasignar los hosts a políticas activas."})

    # --- Detections ---
    if not df_dets.empty and "status" in df_dets:
        total_dets = df_dets["detection_id"].nunique()
        new_dets = df_dets[df_dets["status"].str.lower()=="new"]["detection_id"].nunique()
        crit_new = df_dets[(df_dets["status"].str.lower()=="new") & (df_dets["severity"].str.upper().isin(["CRITICAL","HIGH"]))]["detection_id"].nunique()

        if crit_new > 0:
            recs.append({"severity":"critical","category":"Detecciones",
                "title":f"{crit_new} detecciones Critical/High sin resolver",
                "detail":"Hay alertas de alta severidad que no han sido triageadas. Estas podrían indicar compromiso activo.",
                "mitigation":"Revisar inmediatamente las detecciones Critical y High en el dashboard de CrowdStrike. Realizar triage, investigar IoCs, y tomar acciones de contención si corresponde."})

        if new_dets > 0 and total_dets > 0:
            pct_new = new_dets / total_dets * 100
            if pct_new > 50:
                recs.append({"severity":"high","category":"Detecciones",
                    "title":f"{pct_new:.0f}% de detecciones sin triage ({new_dets}/{total_dets})",
                    "detail":"La mayoría de las detecciones están en estado 'new'. Esto indica falta de proceso de respuesta a incidentes o falta de atención a las alertas.",
                    "mitigation":"Implementar un proceso de triage de alertas. Asignar responsables para revisión diaria. Considerar activar Falcon Complete para respuesta gestionada."})

        # MTTR
        if "created_timestamp" in df_dets:
            closed_dets = df_dets[df_dets["status"].str.lower().isin(["closed","resolved","true_positive","false_positive"])]
            # We can't calculate MTTR without close timestamps, but we can flag if many are open
            open_dets = total_dets - len(closed_dets["detection_id"].unique())
            if open_dets > 0 and total_dets > 10:
                recs.append({"severity":"medium","category":"Detecciones",
                    "title":f"{open_dets} detecciones abiertas de {total_dets} totales",
                    "detail":"Las detecciones abiertas acumuladas dificultan el triage de nuevas alertas y pueden enmascarar amenazas reales.",
                    "mitigation":"Realizar una revisión bulk de detecciones abiertas. Cerrar falsos positivos con justificación. Crear exclusiones para detecciones recurrentes legítimas."})

    # --- NG SIEM ---
    ng = ngsiem or {}
    if not ng.get("available"):
        recs.append({"severity":"medium","category":"NG SIEM",
            "title":"NG SIEM no configurado o no accesible",
            "detail":"No se pudo acceder a la funcionalidad de NG SIEM. Sin SIEM, no hay correlación de eventos ni visibilidad centralizada de logs.",
            "mitigation":"Verificar que el tenant tenga licencia de NG SIEM (incluida en Falcon Insight XDR). Configurar Data Connectors para ingestar logs de terceros (firewall, identity, email, etc.)."})
    else:
        manual_conns = ng.get("manual_connectors", [])
        error_conns = [c for c in manual_conns if c.get("status","").lower() in ("error","disconnected")]
        if error_conns:
            names = ", ".join(c["name"] for c in error_conns)
            recs.append({"severity":"high","category":"NG SIEM",
                "title":f"{len(error_conns)} conector(es) con error",
                "detail":f"Conectores con problemas: {names}. Estos conectores no están ingiriendo datos.",
                "mitigation":"Revisar la configuración de cada conector en Data Connectors. Verificar credenciales, endpoints, y permisos del conector."})
        idle_conns = [c for c in manual_conns if c.get("status","").lower() in ("idle","pending")]
        if idle_conns:
            names = ", ".join(c["name"] for c in idle_conns)
            recs.append({"severity":"low","category":"NG SIEM",
                "title":f"{len(idle_conns)} conector(es) idle/pending",
                "detail":f"Conectores sin actividad: {names}. Pueden no estar configurados correctamente.",
                "mitigation":"Verificar la configuración y activar los conectores pendientes."})
        # Ingest limit
        if ng.get("limit_gb") and ng.get("avg_gb_day"):
            pct = ng["avg_gb_day"] / ng["limit_gb"] * 100
            if pct < 10:
                recs.append({"severity":"info","category":"NG SIEM",
                    "title":f"Ingesta promedio muy baja ({pct:.0f}% del límite)",
                    "detail":f"Se están ingiriendo {ng['avg_gb_day']} GB/día de un límite de {ng['limit_gb']} GB/día.",
                    "mitigation":"Considerar agregar más fuentes de datos: logs de firewall, proxy, VPN, WAF, identity provider, cloud trail, email gateway."})

    recs.sort(key=lambda r: SEVERITY_ORDER.get(r.get("severity","info"), 99))
    return recs


def _recommendations_html(recs):
    """Genera HTML de la sección de recomendaciones."""
    if not recs:
        return '<div class="card"><div class="card-body text-center py-4"><span style="font-size:2rem">&#x2705;</span><div class="mt-2 text-muted">Sin hallazgos. La configuración cumple con las buenas prácticas.</div></div></div>'
    by_sev = {}
    for r in recs:
        s = r.get("severity","info")
        by_sev[s] = by_sev.get(s,0)+1
    sev_badges = ""
    for sev in ["critical","high","medium","low","info"]:
        if sev in by_sev:
            sev_badges += f'<span class="badge fs-6 me-2" style="background:{SEVERITY_COLORS[sev]}">{sev.upper()}: {by_sev[sev]}</span>'
    by_cat = {}
    for r in recs:
        c = r.get("category","Otro")
        by_cat[c] = by_cat.get(c,0)+1
    rows_html = ""
    for cat in sorted(by_cat.keys()):
        cat_recs = [r for r in recs if r.get("category")==cat]
        rows_html += f'<tr class="table-dark"><td colspan="4" style="font-size:.88rem;font-weight:700">{cat} ({len(cat_recs)})</td></tr>'
        for r in cat_recs:
            sev = r.get("severity","info")
            rows_html += (
                f'<tr style="background:{SEVERITY_BG.get(sev,"")}">'
                f'<td><span class="badge" style="background:{SEVERITY_COLORS.get(sev,"#6c757d")}">{sev.upper()}</span></td>'
                f'<td><strong>{r.get("title","")}</strong><br><small class="text-muted">{r.get("detail","")}</small></td>'
                f'<td style="font-size:.78rem"><strong>{r.get("mitigation","")}</strong></td></tr>')
    return f"""
    <div class="d-flex gap-2 flex-wrap mb-3 align-items-center">
      <span style="font-weight:700;font-size:.9rem">{len(recs)} hallazgos:</span> {sev_badges}
    </div>
    <div class="card"><div class="card-body p-0"><div class="table-responsive">
      <table class="table table-sm mb-0" style="font-size:.82rem">
        <thead class="table-dark sticky-top"><tr>
          <th style="width:80px">Severidad</th><th style="width:40%">Hallazgo / Detalle</th>
          <th>Mitigación</th></tr></thead>
        <tbody>{rows_html}</tbody></table>
    </div></div></div>"""


# ---------------------------
# Policy Settings Knowledge Base  (riesgo vs fricción)
# ---------------------------
# Cada entry: setting_id_pattern -> (desc, risk_if_off, friction_if_on, risk_level, friction_level)
# risk_level / friction_level: "critical","high","medium","low"
# El matching es case-insensitive substring sobre setting_name o setting_id.
POLICY_KB = [
    # --- NGAV / ML ---
    {"match": ["cloud anti-malware","cloudantimalware","cloud_anti_malware","cloud ml"],
     "name": "Cloud Anti-Malware (ML)",
     "desc": "Usa modelos de Machine Learning en la nube para detectar malware desconocido en tiempo real.",
     "risk_off": "Sin ML cloud, el sensor depende solo de firmas locales y pierde capacidad de detectar malware zero-day y variantes nuevas.",
     "friction_on": "Bajo. Puede generar falsos positivos en software custom o compiladores internos. Se recomienda empezar en DETECT y pasar a PREVENT.",
     "risk_level": "critical", "friction_level": "low"},

    {"match": ["sensor anti-malware","sensorantimalware","sensor_anti_malware","sensor ml","on-sensor ml"],
     "name": "Sensor Anti-Malware (ML local)",
     "desc": "Modelo de ML que corre localmente en el sensor para detección offline (sin conexión al cloud).",
     "risk_off": "Si el host pierde conectividad al cloud, no tendrá detección ML. Solo quedará protección por firmas.",
     "friction_on": "Bajo. Consume algo más de CPU/RAM en el endpoint. Mismo riesgo de FP que cloud ML.",
     "risk_level": "high", "friction_level": "low"},

    {"match": ["quarantine","cuarentena"],
     "name": "Quarantine (Cuarentena)",
     "desc": "Mueve automáticamente archivos maliciosos detectados a cuarentena, impidiendo su ejecución.",
     "risk_off": "Los archivos maliciosos detectados NO se bloquean — solo se genera la alerta. El usuario puede ejecutar malware conocido.",
     "friction_on": "Medio. Puede poner en cuarentena herramientas legítimas que disparan ML. Requiere un proceso de excepciones.",
     "risk_level": "critical", "friction_level": "medium"},

    # --- Script & Execution ---
    {"match": ["script-based execution","script based","scriptbased","script_based"],
     "name": "Script-Based Execution Monitoring",
     "desc": "Monitorea y puede bloquear ejecución de scripts (PowerShell, VBScript, JScript, macros).",
     "risk_off": "Los atacantes usan scripts como vector principal (fileless malware, PowerShell Empire, etc.). Sin esto, no hay visibilidad.",
     "friction_on": "Medio-Alto. Puede afectar scripts de administración, GPOs, herramientas de deployment. Requiere tuning de exclusiones.",
     "risk_level": "critical", "friction_level": "high"},

    {"match": ["intelligence-sourced","intelligence sourced","ioa","custom intelligence"],
     "name": "Intelligence-Sourced Threats (IoA)",
     "desc": "Detecta amenazas basadas en Indicators of Attack de la inteligencia de CrowdStrike.",
     "risk_off": "Se pierden detecciones de amenazas activas identificadas por el equipo de threat intelligence de CrowdStrike.",
     "friction_on": "Bajo. Son reglas curadas por CrowdStrike con muy baja tasa de falsos positivos.",
     "risk_level": "critical", "friction_level": "low"},

    # --- Exploit & Injection ---
    {"match": ["exploit mitigation","additional user mode","user mode data","aum"],
     "name": "Exploit Mitigation / User Mode Data",
     "desc": "Detecta y previene técnicas de explotación de vulnerabilidades en memoria (heap spray, ROP, stack pivot).",
     "risk_off": "Los exploits de día cero contra aplicaciones (browser, Office, Adobe) no serán detectados por behavioral analysis.",
     "friction_on": "Bajo-Medio. Raramente genera falsos positivos. Puede afectar software de debugging o herramientas de seguridad ofensiva.",
     "risk_level": "critical", "friction_level": "low"},

    {"match": ["code injection","process injection","injection"],
     "name": "Code/Process Injection Detection",
     "desc": "Detecta inyección de código en procesos legítimos (DLL injection, process hollowing, etc.).",
     "risk_off": "Técnica clave de evasión — los atacantes inyectan código en procesos confiables para evadir EDR.",
     "friction_on": "Medio. Algunas herramientas legítimas de accessibility, AV legacy, o DRM usan inyección. Requiere excepciones puntuales.",
     "risk_level": "high", "friction_level": "medium"},

    # --- Ransomware ---
    {"match": ["ransomware","ransom"],
     "name": "Ransomware Protection",
     "desc": "Detecta comportamiento de cifrado masivo de archivos y lo bloquea antes de completar.",
     "risk_off": "Sin protección de ransomware, un ataque exitoso puede cifrar todos los archivos del host y compartidos de red.",
     "friction_on": "Bajo. Muy pocas aplicaciones legítimas cifran archivos masivamente. Software de backup/encryption puede requerir excepción.",
     "risk_level": "critical", "friction_level": "low"},

    # --- Lateral Movement ---
    {"match": ["lateral movement","lateral"],
     "name": "Lateral Movement Detection",
     "desc": "Detecta técnicas de movimiento lateral: pass-the-hash, PsExec, WMI remoto, RDP brute force.",
     "risk_off": "Un atacante que compromete un host puede moverse libremente a otros sistemas sin ser detectado.",
     "friction_on": "Medio. Herramientas de administración remota (SCCM, Ansible, RMM) pueden generar alertas. Requiere baseline de comportamiento normal.",
     "risk_level": "high", "friction_level": "medium"},

    # --- Credential Theft ---
    {"match": ["credential","credguard","credential dumping","lsass"],
     "name": "Credential Theft Detection",
     "desc": "Detecta intentos de robo de credenciales: volcado de LSASS, mimikatz, kerberoasting.",
     "risk_off": "Los atacantes pueden extraer credenciales y escalar privilegios sin ser detectados.",
     "friction_on": "Bajo-Medio. Algunos productos de SSO o herramientas de IT que interactúan con LSASS pueden generar alertas.",
     "risk_level": "critical", "friction_level": "low"},

    # --- USB / Device Control ---
    {"match": ["usb","removable media","device control","usb device"],
     "name": "USB / Removable Media Control",
     "desc": "Controla qué dispositivos USB pueden conectarse y qué operaciones pueden realizar.",
     "risk_off": "Los usuarios pueden conectar USB con malware, o exfiltrar datos a dispositivos removibles.",
     "friction_on": "Alto. Puede bloquear periféricos legítimos (mouse, teclado, impresoras USB). Requiere política granular por tipo de dispositivo.",
     "risk_level": "medium", "friction_level": "high"},

    # --- Network & Firewall ---
    {"match": ["firewall","network contain","network isolation"],
     "name": "Host Firewall Management",
     "desc": "Gestiona reglas de firewall del host desde CrowdStrike.",
     "risk_off": "Sin firewall gestionado, no hay control centralizado del tráfico de red del endpoint.",
     "friction_on": "Alto. Reglas mal configuradas pueden bloquear tráfico legítimo y causar caída de servicios. Requiere planificación cuidadosa.",
     "risk_level": "medium", "friction_level": "high"},

    # --- Visibility ---
    {"match": ["visibility","enhanced visibility","telemetry"],
     "name": "Enhanced Visibility / Telemetry",
     "desc": "Incrementa la telemetría enviada al cloud para mejor detección y threat hunting.",
     "risk_off": "Menor visibilidad para threat hunting y respuesta a incidentes. Las investigaciones serán más limitadas.",
     "friction_on": "Bajo. Incrementa levemente el consumo de ancho de banda y almacenamiento en el cloud.",
     "risk_level": "medium", "friction_level": "low"},

    # --- On Write ---
    {"match": ["on write","on-write","onwrite","prevent suspicious"],
     "name": "On-Write Detection",
     "desc": "Analiza archivos al momento de escribirse en disco, antes de su ejecución.",
     "risk_off": "El malware puede residir en disco sin ser detectado hasta que el usuario lo ejecute.",
     "friction_on": "Bajo. Puede agregar un mínimo de latencia en operaciones de escritura de archivos.",
     "risk_level": "high", "friction_level": "low"},

    # --- Process Blocking ---
    {"match": ["process blocking","suspicious process","block","hash blocking"],
     "name": "Suspicious Process Blocking",
     "desc": "Bloquea la ejecución de procesos catalogados como sospechosos o maliciosos.",
     "risk_off": "Los procesos maliciosos detectados se alertan pero NO se bloquean — el malware continúa ejecutándose.",
     "friction_on": "Medio. En modo prevención puede bloquear herramientas de pentest, scripts internos, o software no firmado.",
     "risk_level": "critical", "friction_level": "medium"},

    # --- Sensor Tampering ---
    {"match": ["sensor tamper","tamper protection","uninstall","anti-tamper"],
     "name": "Sensor Tamper Protection",
     "desc": "Previene que el sensor sea desinstalado o deshabilitado sin autorización.",
     "risk_off": "Un atacante con acceso admin puede desinstalar el sensor y operar sin ninguna detección.",
     "friction_on": "Bajo. Solo afecta si IT necesita desinstalar el sensor — requiere token de mantenimiento.",
     "risk_level": "critical", "friction_level": "low"},

    # --- Interpreter-Only ---
    {"match": ["interpreter only","interpreter-only","fileless"],
     "name": "Interpreter-Only (Fileless) Detection",
     "desc": "Detecta malware fileless que vive solo en memoria sin tocar disco.",
     "risk_off": "Los ataques fileless (living-off-the-land) son el método más común de evasión actual y no serán detectados.",
     "friction_on": "Medio. Puede generar alertas en scripts de automatización legítimos.",
     "risk_level": "high", "friction_level": "medium"},

    # --- Adware/PUP ---
    {"match": ["adware","pup","potentially unwanted"],
     "name": "Adware / PUP Detection",
     "desc": "Detecta programas potencialmente no deseados (adware, toolbars, bundleware).",
     "risk_off": "Los PUPs pueden degradar rendimiento, exfiltrar datos, o servir como vector de entrada.",
     "friction_on": "Medio. Puede marcar software legítimo gratuito que incluye bundleware.",
     "risk_level": "low", "friction_level": "medium"},

    # --- Chopper Webshell ---
    {"match": ["chopper","webshell","web shell"],
     "name": "Chopper Webshell Detection",
     "desc": "Detecta webshells conocidos usados para persistencia en servidores web.",
     "risk_off": "Los atacantes pueden mantener acceso persistente a servidores web sin detección.",
     "friction_on": "Bajo. Solo aplica a servidores web. Falsos positivos muy raros.",
     "risk_level": "high", "friction_level": "low"},

    # --- Drift Detection (Linux) ---
    {"match": ["drift","container drift","image drift"],
     "name": "Container Drift Detection",
     "desc": "Detecta cambios no autorizados en contenedores respecto a su imagen base.",
     "risk_off": "Un atacante puede modificar un contenedor en runtime sin ser detectado.",
     "friction_on": "Medio. Puede alertar sobre actualizaciones legítimas de contenedores o procesos de CI/CD.",
     "risk_level": "medium", "friction_level": "medium"},

    # --- MalQuery / YARA ---
    {"match": ["custom blocking","ioc","custom ioc","ioc management"],
     "name": "Custom IOC Blocking",
     "desc": "Permite bloquear hashes, IPs, dominios custom definidos por el equipo de seguridad.",
     "risk_off": "No se pueden bloquear IoCs específicos identificados en investigaciones internas.",
     "friction_on": "Bajo. Solo bloquea lo que el equipo agrega manualmente. Requiere gestión activa de la lista de IoCs.",
     "risk_level": "medium", "friction_level": "low"},
]

def _match_setting_to_kb(setting_name: str, setting_id: str = "") -> dict | None:
    """Busca en el KB el setting que mejor matchea por nombre o ID."""
    sn = (setting_name or "").lower()
    si = (setting_id or "").lower()
    for entry in POLICY_KB:
        for pattern in entry["match"]:
            if pattern in sn or pattern in si:
                return entry
    return None

def _build_risk_matrix_html(df_prev: pd.DataFrame) -> str:
    """Genera la tabla HTML de riesgo vs fricción cruzando con el estado actual de las políticas."""
    if df_prev.empty or "value_norm" not in df_prev:
        return '<p class="text-muted">Sin datos de políticas de prevención.</p>'

    # Get unique settings across all platforms/policies
    settings_seen = {}  # setting_name -> {kb_entry, platforms: {plat: {pol: value}}}
    for _, row in df_prev.iterrows():
        sname = str(row.get("setting_name",""))
        sid   = str(row.get("setting_id",""))
        if not sname:
            continue
        kb = _match_setting_to_kb(sname, sid)
        if sname not in settings_seen:
            settings_seen[sname] = {"kb": kb, "sid": sid, "platforms": {}}
        plat = str(row.get("platform_name",""))
        pol  = str(row.get("policy_name",""))
        val  = str(row.get("value_norm",""))
        if plat not in settings_seen[sname]["platforms"]:
            settings_seen[sname]["platforms"][plat] = {}
        settings_seen[sname]["platforms"][plat][pol] = val

    # Build rows — only settings with KB entries, sorted by risk level
    risk_order = {"critical":0,"high":1,"medium":2,"low":3}
    rows = []
    for sname, info in settings_seen.items():
        kb = info["kb"]
        if not kb:
            continue
        # Determine current state across all policies
        all_vals = []
        for plat_pols in info["platforms"].values():
            all_vals.extend(plat_pols.values())
        on_count  = sum(1 for v in all_vals if v.upper()=="ON")
        off_count = sum(1 for v in all_vals if v.upper()=="OFF")
        total = on_count + off_count
        # Status summary
        if total == 0:
            status_html = '<span class="text-muted">—</span>'
        elif off_count == 0:
            status_html = '<span class="badge bg-success">100% ON</span>'
        elif on_count == 0:
            status_html = '<span class="badge bg-danger">100% OFF</span>'
        else:
            pct = round(on_count/total*100)
            status_html = f'<span class="badge bg-warning text-dark">{pct}% ON</span>'
        # Per-platform mini status
        plat_badges = ""
        for plat in ["Windows","Mac","Linux"]:
            pols = info["platforms"].get(plat, {})
            if not pols:
                continue
            p_on  = sum(1 for v in pols.values() if v.upper()=="ON")
            p_off = sum(1 for v in pols.values() if v.upper()=="OFF")
            p_t   = p_on + p_off
            if p_t == 0: continue
            if p_off == 0:
                plat_badges += f'<span class="badge bg-success me-1" style="font-size:.65rem">{plat[:3]}: ON</span>'
            elif p_on == 0:
                plat_badges += f'<span class="badge bg-danger me-1" style="font-size:.65rem">{plat[:3]}: OFF</span>'
            else:
                plat_badges += f'<span class="badge bg-warning text-dark me-1" style="font-size:.65rem">{plat[:3]}: {p_on}/{p_t}</span>'

        rl = kb["risk_level"]
        fl = kb["friction_level"]
        risk_badge_color = {"critical":"#7d1128","high":"#dc3545","medium":"#fd7e14","low":"#28a745"}
        friction_badge_color = {"high":"#dc3545","medium":"#fd7e14","low":"#28a745"}
        rows.append({
            "sort_key": risk_order.get(rl, 99),
            "html": (
                f'<tr>'
                f'<td><span class="badge" style="background:{risk_badge_color.get(rl,"#6c757d")}">{rl.upper()}</span></td>'
                f'<td><strong>{kb["name"]}</strong><br><small class="text-muted">{kb["desc"]}</small></td>'
                f'<td>{status_html}<br>{plat_badges}</td>'
                f'<td style="font-size:.78rem">{kb["risk_off"]}</td>'
                f'<td><span class="badge" style="background:{friction_badge_color.get(fl,"#6c757d")}">{fl.upper()}</span><br>'
                f'<small class="text-muted">{kb["friction_on"]}</small></td>'
                f'</tr>')
        })

    # Settings OFF without KB (generic row)
    unknown_off = []
    for sname, info in settings_seen.items():
        if info["kb"]:
            continue
        all_vals = []
        for plat_pols in info["platforms"].values():
            all_vals.extend(plat_pols.values())
        if any(v.upper()=="OFF" for v in all_vals):
            unknown_off.append(sname)
    if unknown_off:
        rows.append({
            "sort_key": 5,
            "html": (
                f'<tr class="table-light">'
                f'<td><span class="badge bg-secondary">INFO</span></td>'
                f'<td><strong>{len(unknown_off)} settings adicionales con valor OFF</strong><br>'
                f'<small class="text-muted">{", ".join(unknown_off[:8])}{"..." if len(unknown_off)>8 else ""}</small></td>'
                f'<td colspan="3" style="font-size:.78rem">Estos settings no tienen evaluación de riesgo predefinida. '
                f'Revisar la documentación de CrowdStrike para cada uno.</td></tr>')
        })

    rows.sort(key=lambda x: x["sort_key"])

    return f"""
    <div class="card">
      <div class="card-body p-0">
        <div class="table-responsive" style="max-height:600px;overflow-y:auto">
          <table class="table table-sm table-hover mb-0" style="font-size:.82rem">
            <thead class="table-dark sticky-top">
              <tr>
                <th style="width:80px">Riesgo<br><small style="font-weight:400">(si OFF)</small></th>
                <th style="width:25%">Setting</th>
                <th style="width:12%">Estado actual</th>
                <th style="width:30%">Impacto de tenerlo desactivado</th>
                <th style="width:20%">Friccion<br><small style="font-weight:400">(si se activa)</small></th>
              </tr>
            </thead>
            <tbody>{"".join(r["html"] for r in rows)}</tbody>
          </table>
        </div>
      </div>
    </div>"""


# ---------------------------
# HTML Report
# ---------------------------
def _safe_json(obj) -> str:
    """Serialize DataFrame or dict to a JSON string safe for embedding in HTML."""
    if isinstance(obj, pd.DataFrame):
        if obj.empty:
            return "[]"
        df2 = obj.copy()
        for col in df2.columns:
            if pd.api.types.is_datetime64_any_dtype(df2[col]):
                df2[col] = df2[col].dt.strftime("%Y-%m-%d %H:%M UTC").fillna("")
        df2 = df2.where(pd.notnull(df2), None)
        return json.dumps(df2.to_dict(orient="records"), default=str)
    return json.dumps(obj, default=str)

def _policy_pivot(df_settings: pd.DataFrame, platform: str) -> tuple[list, list, list[list]]:
    """Return (settings, policies_with_host_counts, matrix) for a platform."""
    d = df_settings[df_settings["platform_name"].str.upper() == platform.upper()].copy()
    d = d[d["setting_name"].notna() & (d["setting_name"] != "")]
    if d.empty:
        return [], [], []
    piv = d.pivot_table(index="setting_name", columns="policy_name",
                        values="value_norm", aggfunc="first")
    settings  = list(piv.index)
    policies  = list(piv.columns)
    matrix    = [[str(piv.iloc[r, c]) if pd.notna(piv.iloc[r, c]) else "—"
                  for c in range(len(policies))]
                 for r in range(len(settings))]
    return settings, policies, matrix

def generate_html_report(
    client_name: str, cid: str,
    df_summary, df_hosts, df_sensor_age_counts, df_uninstall,
    df_count_prev, df_count_supd, df_count_fw, df_count_dctl,
    df_prev, df_supd, df_fw, df_dctl,
    df_agent_versions, df_os_versions,
    df_detects_summary, df_dets,
    df_dets_status, df_dets_sev, df_dets_plat, df_dets_tactic,
    pivot_tactic, pivot_host,
    ngsiem: dict = None,
) -> str:

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M")
    title       = f"CrowdStrike Falcon Health Check — {client_name or cid}"

    # ---- Health Score ----
    health = compute_health_score(df_hosts, df_prev, df_dets, df_sensor_age_counts, ngsiem)
    health_score = health["overall"]
    health_breakdown = health["breakdown"]
    score_color = "#28a745" if health_score >= 75 else "#ffc107" if health_score >= 50 else "#fd7e14" if health_score >= 30 else "#dc3545"

    # ---- Recommendations ----
    recs = generate_recommendations(df_hosts, df_prev, df_dets, df_sensor_age_counts, ngsiem)
    recs_html = _recommendations_html(recs)
    recs_critical = sum(1 for r in recs if r["severity"]=="critical")
    recs_high = sum(1 for r in recs if r["severity"]=="high")

    # ---- KPIs ----
    s = df_summary.iloc[0] if not df_summary.empty else {}
    total_sensors   = int(s.get("Total Sensors", 0))
    win_sensors     = int(s.get("Windows Sensors", 0))
    mac_sensors     = int(s.get("Mac Sensors", 0))
    lin_sensors     = int(s.get("Linux Sensors", 0))
    inactive_14d    = int(s.get("Inactive (>14d)", 0))
    rfm_count       = int(df_hosts["rfm_state"].apply(lambda x: str(x).lower() in ("true","yes","1") if pd.notna(x) else False).sum()) if not df_hosts.empty else 0

    if not df_detects_summary.empty:
        detects_90d = int(df_detects_summary.iloc[0].get("detects_90d", 0))
        pct_new_90d = float(df_detects_summary.iloc[0].get("pct_new_90d", 0))
    else:
        detects_90d, pct_new_90d = 0, 0.0

    # ---- Policy Compliance ----
    def _policy_compliance(df, plat):
        d = df[df["platform_name"].str.upper()==plat.upper()]
        if d.empty or "value_norm" not in d:
            return 0, 0, 0
        on = int((d["value_norm"].str.upper()=="ON").sum())
        total = len(d[d["value_norm"].notna()])
        return on, total, round(on/total*100) if total else 0
    win_on, win_total, win_pct = _policy_compliance(df_prev, "Windows")
    mac_on, mac_total, mac_pct = _policy_compliance(df_prev, "Mac")
    lin_on, lin_total, lin_pct = _policy_compliance(df_prev, "Linux")

    # ---- Sensor freshness % ----
    sensor_fresh_pct = 0
    if not df_sensor_age_counts.empty and total_sensors > 0:
        comb = df_sensor_age_counts[df_sensor_age_counts["platform"]=="Combined"]
        if not comb.empty:
            fresh = int(comb.iloc[0].get("N",0)) + int(comb.iloc[0].get("N-1",0))
            sensor_fresh_pct = round(fresh / total_sensors * 100)

    # ---- Detection response metrics ----
    dets_open = dets_closed = dets_new_crit = 0
    if not df_dets.empty and "status" in df_dets:
        unique_dets = df_dets.drop_duplicates("detection_id")
        dets_open = int(unique_dets["status"].str.lower().isin(["new","in_progress","reopened"]).sum())
        dets_closed = int(unique_dets["status"].str.lower().isin(["closed","resolved","true_positive","false_positive"]).sum())
        dets_new_crit = int(unique_dets[(unique_dets["status"].str.lower()=="new") & (unique_dets["severity"].str.upper().isin(["CRITICAL","HIGH"]))].shape[0])

    # ---- Sensor Age chart data ----
    age_platforms = ["Windows", "Mac", "Linux", "Combined"]
    age_labels    = ["N (latest)", "N-1", "N-2", "N-3+", "Unsupported"]
    age_colors    = ["#28a745", "#6fbf73", "#ffc107", "#fd7e14", "#dc3545"]
    age_data = {row["platform"]: [row.get("N",0), row.get("N-1",0),
                                   row.get("N-2",0), row.get("N-3_plus",0), row.get("Unsupported",0)]
                for _, row in df_sensor_age_counts.iterrows()}

    # ---- Policy pivot matrices ----
    win_settings, win_policies, win_matrix = _policy_pivot(df_prev, "Windows")
    mac_settings, mac_policies, mac_matrix = _policy_pivot(df_prev, "Mac")
    lin_settings, lin_policies, lin_matrix = _policy_pivot(df_prev, "Linux")

    # Host count per prevention policy (for column headers)
    hc_prev = {}
    if not df_count_prev.empty:
        for _, r in df_count_prev.iterrows():
            hc_prev[str(r.get("policy_prevention_name",""))] = int(r.get("host_count",0))

    # ---- Detection chart data ----
    def series_from(df, label_col, count_col="count"):
        if df.empty: return [], []
        return list(df[label_col].astype(str)), list(df[count_col].astype(int))

    det_status_labels, det_status_vals = series_from(df_dets_status, "status")
    det_sev_labels,    det_sev_vals    = series_from(df_dets_sev,    "severity")
    det_plat_labels,   det_plat_vals   = series_from(df_dets_plat,   "platform_name")
    det_tactic_labels, det_tactic_vals = series_from(df_dets_tactic, "tactic")

    sev_color_map = {
        "CRITICAL": "#7d1128", "HIGH": "#dc3545",
        "MEDIUM": "#fd7e14",   "LOW":  "#ffc107",
        "INFORMATIONAL": "#6c757d", "UNKNOWN": "#adb5bd"
    }
    status_color_map = {
        "new": "#dc3545", "in_progress": "#ffc107",
        "closed": "#28a745", "reopened": "#fd7e14"
    }
    det_sev_colors    = [sev_color_map.get(l.upper(), "#adb5bd") for l in det_sev_labels]
    det_status_colors = [status_color_map.get(l.lower(), "#6c757d") for l in det_status_labels]

    # Detection trend (daily)
    trend_labels, trend_vals = [], []
    if not df_dets.empty and "created_timestamp" in df_dets:
        td = df_dets.dropna(subset=["created_timestamp"]).copy()
        td["date"] = td["created_timestamp"].dt.strftime("%Y-%m-%d")
        daily = td.groupby("date")["detection_id"].nunique().reset_index()
        daily.columns = ["date","count"]
        daily = daily.sort_values("date")
        trend_labels = list(daily["date"])
        trend_vals   = list(daily["count"].astype(int))

    # Top 10 hosts by detections
    top_hosts_json = _safe_json(
        pivot_host.nlargest(10, "detections") if not pivot_host.empty else pivot_host
    )

    # ---- NG SIEM data
    ng = ngsiem or {}
    ng_available   = ng.get("available", False)
    ng_repos       = ng.get("repos", [])
    ng_views       = ng.get("views", [])
    ng_connectors  = ng.get("connectors", [])
    ng_error       = ng.get("error") or ""
    ng_daily       = ng.get("daily_stats", pd.DataFrame())

    ng_repos_count  = len(ng_repos)
    ng_views_count  = len(ng_views)

    # Daily ingest summary per day (sum across sources)
    ng_trend_labels, ng_trend_events, ng_trend_gb = [], [], []
    ng_daily_avg_gb = 0.0
    ng_total_events_7d = 0
    if not ng_daily.empty and "date" in ng_daily.columns:
        daily_agg = (ng_daily.groupby("date")
                              .agg(events=("events","sum"), gb=("gb","sum"))
                              .reset_index().sort_values("date"))
        ng_trend_labels  = list(daily_agg["date"])
        ng_trend_events  = [int(x) for x in daily_agg["events"]]
        ng_trend_gb      = [round(float(x), 3) for x in daily_agg["gb"]]
        ng_daily_avg_gb  = round(float(daily_agg["gb"].mean()), 3)
        ng_total_events_7d = int(daily_agg["events"].sum())

    # Ingest by source (connectors)
    ng_src_labels, ng_src_events = [], []
    if not ng_daily.empty and "source" in ng_daily.columns:
        src_agg = (ng_daily.groupby("source")
                            .agg(events=("events","sum"), gb=("gb","sum"))
                            .reset_index().sort_values("events", ascending=False))
        ng_src_labels = list(src_agg["source"])
        ng_src_events = [int(x) for x in src_agg["events"]]
        if not ng_connectors:
            ng_connectors = ng_src_labels

    # Repos table rows for HTML
    ng_repos_rows = []
    for r in ng_repos:
        ng_repos_rows.append({
            "name":          r.get("name",""),
            "description":   r.get("description",""),
            "retention_days":r.get("retention_days") or r.get("retentionDays","—"),
            "compressed_gb": round(float(r.get("compressedBytes",0) or 0) / 1e9, 2),
            "event_count":   r.get("eventCount") or r.get("event_count","—"),
        })
    ng_views_rows = []
    for v in ng_views:
        ng_views_rows.append({
            "name":        v.get("name",""),
            "description": v.get("description",""),
            "connections": ", ".join(c.get("repositoryName","") for c in (v.get("connections") or [])),
        })

    ng_inferred           = ng.get("inferred", False)
    ng_products           = ng.get("products", [])
    ng_vendors            = ng.get("vendors", [])
    ng_manual_connectors  = ng.get("manual_connectors", [])
    ng_limit_gb           = ng.get("limit_gb", NGSIEM_LIMIT_GB)
    ng_avg_gb_day         = ng.get("avg_gb_day", NGSIEM_AVG_GB)
    ng_today_mb           = ng.get("today_mb", NGSIEM_TODAY_MB)
    ng_pct_used           = round(ng_avg_gb_day / ng_limit_gb * 100, 1) if ng_limit_gb else 0

    if ng_available and not ng_inferred:
        ng_status_badge = '<span class="badge bg-success fs-6">Activo (API directa)</span>'
    elif ng_available and ng_inferred:
        ng_status_badge = '<span class="badge bg-warning text-dark fs-6">Activo (inferido)</span>'
    else:
        ng_status_badge = '<span class="badge bg-secondary fs-6">No disponible</span>'

    ng_error_html = (
        f'<div class="alert alert-info mt-2 py-2" style="font-size:.82rem">'
        f'ℹ️ <strong>NG SIEM:</strong> {ng_error} '
        f'<br><small>Para acceso directo al API de búsqueda de NG SIEM, contactá a tu TAM de CrowdStrike '
        f'para habilitar el proxy de autenticación Humio en tu tenant.</small></div>'
        if ng_error and ng_available else
        f'<div class="alert alert-warning mt-2 py-1" style="font-size:.82rem">⚠ {ng_error}</div>'
        if ng_error else ""
    )

    # Agent versions (top 15)
    df_agent_top = df_agent_versions.head(15) if not df_agent_versions.empty else df_agent_versions

    # Sensor update policy table
    supd_rows_json = _safe_json(df_count_supd)
    supd_settings_json = _safe_json(df_supd)

    # Hosts table (limited columns for performance)
    host_display_cols = ["hostname","platform_name","os_version","agent_version",
                         "last_seen","rfm_state","local_ip","site_name","ou",
                         "policy_prevention_name","policy_sensor_update_name"]
    host_display_cols = [c for c in host_display_cols if c in df_hosts.columns]
    hosts_json = _safe_json(df_hosts[host_display_cols]) if not df_hosts.empty else "[]"

    # Detections detail table (max 5000 rows for display)
    det_detail_cols = ["detection_id","created_timestamp","status","severity",
                       "hostname","platform_name","tactic","technique","objective",
                       "filename","command_line","user_name"]
    det_detail_cols = [c for c in det_detail_cols if c in df_dets.columns]
    det_json = _safe_json(df_dets[det_detail_cols].head(5000)) if not df_dets.empty else "[]"

    # Uninstall protection
    uninst_json = _safe_json(df_uninstall)
    agent_ver_json = _safe_json(df_agent_top)
    os_ver_json    = _safe_json(df_os_versions.head(30) if not df_os_versions.empty else df_os_versions)

    def policy_table_html(settings, policies, matrix, hc_map=None):
        """Build an HTML table for a policy comparison matrix."""
        if not settings or not policies:
            return "<p class='text-muted'>No hay datos de políticas.</p>"
        col_headers = []
        for p in policies:
            hc = hc_map.get(p, "") if hc_map else ""
            hc_str = f"<br><small class='text-muted'>{hc} hosts</small>" if hc else ""
            col_headers.append(f"<th class='policy-col'>{p}{hc_str}</th>")
        rows_html = []
        for i, setting in enumerate(settings):
            cells = []
            for val in matrix[i]:
                vup = val.upper()
                if vup == "ON":
                    cls = "badge bg-success"
                elif vup == "OFF":
                    cls = "badge bg-danger"
                elif vup in ("AGGRESSIVE","EXTRA_AGGRESSIVE","MODERATE"):
                    cls = "badge bg-warning text-dark"
                elif vup == "DISABLED":
                    cls = "badge bg-secondary"
                else:
                    cls = "badge bg-light text-dark"
                cells.append(f"<td class='text-center'><span class='{cls}'>{val}</span></td>")
            rows_html.append(f"<tr><td class='setting-name'>{setting}</td>{''.join(cells)}</tr>")
        return f"""
        <div class="table-responsive policy-table-wrap">
          <table class="table table-sm table-bordered table-hover policy-matrix">
            <thead class="table-dark sticky-header">
              <tr>
                <th style="min-width:220px">Setting</th>
                {''.join(col_headers)}
              </tr>
            </thead>
            <tbody>{''.join(rows_html)}</tbody>
          </table>
        </div>"""

    win_pol_html = policy_table_html(win_settings, win_policies, win_matrix, hc_prev)
    mac_pol_html = policy_table_html(mac_settings, mac_policies, mac_matrix, hc_prev)
    lin_pol_html = policy_table_html(lin_settings, lin_policies, lin_matrix, hc_prev)

    # ---- Inline alert badges ----
    def kpi_badge(value, warn_fn=None, danger_fn=None):
        cls = "bg-success"
        if danger_fn and danger_fn(value): cls = "bg-danger"
        elif warn_fn and warn_fn(value): cls = "bg-warning text-dark"
        return cls

    inactive_pct = round(inactive_14d / total_sensors * 100, 1) if total_sensors else 0

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --cs-red: #E1001A;
      --cs-dark: #1c1c1e;
    }}
    body {{ background:#f5f5f7; font-family:'Segoe UI',system-ui,sans-serif; color:#1c1c1e; }}
    .navbar {{ background:var(--cs-dark) !important; border-bottom:3px solid var(--cs-red); }}
    .navbar-brand {{ color:#fff !important; font-weight:700; font-size:1.1rem; letter-spacing:.3px; }}
    /* — Navbar links — */
    .navbar .nav-link {{ color:rgba(255,255,255,.75) !important; font-size:.85rem;
                         transition:color .15s; }}
    .navbar .nav-link:hover {{ color:#fff !important; }}

    /* — Policy tabs (Windows / Mac / Linux) — */
    .nav-tabs {{
      background: linear-gradient(to bottom, #f5f5f7, #eaeaed);
      border-bottom: 2px solid #d0d0d5;
      padding: .4rem 0 0 .5rem;
    }}
    .nav-tabs .nav-link {{
      color: #495057 !important;
      font-size: .85rem;
      font-weight: 500;
      border: none !important;
      border-radius: 8px 8px 0 0 !important;
      padding: .55rem 1.3rem;
      margin-bottom: -2px;
      transition: all .15s;
    }}
    .nav-tabs .nav-link:hover {{
      color: var(--cs-red) !important;
      background: rgba(225,0,26,.06);
    }}
    .nav-tabs .nav-link.active {{
      color: var(--cs-red) !important;
      font-weight: 700;
      background: #fff !important;
      border: 2px solid #d0d0d5 !important;
      border-bottom-color: #fff !important;
      box-shadow: 0 -2px 6px rgba(0,0,0,.04);
    }}

    /* — Tab content area — */
    .tab-content {{
      background: #fff;
      border-left: 1px solid #d0d0d5;
      border-right: 1px solid #d0d0d5;
      border-bottom: 1px solid #d0d0d5;
      border-radius: 0 0 10px 10px;
      padding: 1rem;
    }}

    /* — Section titles — */
    .section-title {{
      font-size:1.05rem; font-weight:700; text-transform:uppercase;
      letter-spacing:.5px; color:var(--cs-red); border-left:4px solid var(--cs-red);
      padding-left:.6rem; margin-bottom:1rem;
    }}

    /* — KPI cards — */
    .kpi-card {{ border:none; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
    .kpi-card .card-body {{ padding:1rem 1.2rem; }}
    .kpi-number {{ font-size:2rem; font-weight:700; line-height:1; }}
    .kpi-label {{ font-size:.78rem; text-transform:uppercase; letter-spacing:.4px;
                  color:#6c757d; margin-top:.2rem; }}

    /* — Cards — */
    .card {{ border:none; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.07); background:#fff; }}
    .card-header {{ background:#fafafa; border-bottom:1px solid #e9ecef;
                    font-weight:600; font-size:.9rem; padding:.75rem 1rem; }}

    /* — Policy matrix — */
    .policy-table-wrap {{ max-height:480px; overflow-y:auto; }}
    .policy-matrix td, .policy-matrix th {{ font-size:.78rem; padding:.3rem .5rem; white-space:nowrap; }}
    .setting-name {{ min-width:200px; max-width:280px; white-space:normal; font-size:.79rem; }}
    .policy-col {{ min-width:120px; text-align:center; font-size:.79rem; }}
    .sticky-header th {{ position:sticky; top:0; z-index:2; }}

    /* — Sortable tables — */
    table.filterable-table th {{ cursor:pointer; user-select:none; }}
    table.filterable-table th:hover {{ background:#f0f0f0; }}
    .search-box {{ max-width:320px; }}
    .badge {{ font-size:.72rem; font-weight:600; }}

    /* — Severity colors — */
    .sev-CRITICAL {{ color:#7d1128; font-weight:700; }}
    .sev-HIGH     {{ color:#dc3545; font-weight:700; }}
    .sev-MEDIUM   {{ color:#fd7e14; font-weight:600; }}
    .sev-LOW      {{ color:#856404; }}
    .sev-INFORMATIONAL {{ color:#6c757d; }}

    /* — Status colors — */
    .status-NEW       {{ color:#dc3545; font-weight:700; }}
    .status-IN_PROGRESS {{ color:#fd7e14; font-weight:600; }}
    .status-CLOSED    {{ color:#28a745; }}
    .rfm-yes {{ color:#dc3545; font-weight:700; }}
    .inactive-yes {{ color:#dc3545; }}

    /* — Scrollbar — */
    .policy-table-wrap::-webkit-scrollbar {{ width:6px; }}
    .policy-table-wrap::-webkit-scrollbar-thumb {{ background:#ccc; border-radius:3px; }}

    /* — Health Score Donut — */
    .score-ring {{ position:relative; width:140px; height:140px; }}
    .score-ring canvas {{ width:140px !important; height:140px !important; }}
    .score-ring-label {{ position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); text-align:center; }}
    .score-ring-number {{ font-size:2.4rem; font-weight:800; line-height:1; }}
    .score-ring-text {{ font-size:.65rem; text-transform:uppercase; letter-spacing:.5px; color:#6c757d; }}

    /* — Compliance bars — */
    .compliance-bar {{ height:8px; border-radius:4px; background:#e9ecef; overflow:hidden; }}
    .compliance-fill {{ height:100%; border-radius:4px; transition:width .6s; }}

    /* — Cover page — */
    .cover-page {{
      background: linear-gradient(135deg, #1c1c1e 0%, #2c2c2e 40%, #E1001A 100%);
      color:#fff; padding:4rem 3rem 3rem; position:relative; overflow:hidden;
    }}
    .cover-page::before {{
      content:''; position:absolute; top:-50%; right:-20%;
      width:500px; height:500px; border-radius:50%;
      background:rgba(225,0,26,.15); filter:blur(80px);
    }}

    .chart-container {{ position:relative; height:260px; }}
    .chart-container-lg {{ position:relative; height:340px; }}

    footer {{ background:var(--cs-dark); color:rgba(255,255,255,.5);
              font-size:.78rem; padding:1rem 2rem; margin-top:3rem; }}

    @media print {{
      .no-print {{ display:none !important; }}
      .card {{ break-inside:avoid; }}
      .policy-table-wrap {{ max-height:none !important; overflow:visible !important; }}
      .cover-page {{ break-after:page; }}
      body {{ background:#fff; }}
    }}
  </style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover-page no-print">
  <div style="position:relative;z-index:1">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:2rem">
      <svg width="36" height="24" viewBox="0 0 120 80" fill="#E1001A">
        <ellipse cx="60" cy="40" rx="58" ry="30"/><ellipse cx="60" cy="40" rx="42" ry="20" fill="#1c1c1e"/>
        <ellipse cx="60" cy="40" rx="26" ry="12"/>
      </svg>
      <span style="font-size:.9rem;font-weight:300;letter-spacing:2px;text-transform:uppercase;color:rgba(255,255,255,.5)">CrowdStrike Falcon</span>
    </div>
    <div style="font-size:2.6rem;font-weight:800;line-height:1.1;margin-bottom:.4rem">Health Check Report</div>
    <div style="font-size:1.2rem;font-weight:300;color:rgba(255,255,255,.65);margin-bottom:2rem">{client_name or cid}</div>
    <div style="display:flex;gap:3rem;flex-wrap:wrap;margin-bottom:2rem">
      <div><div style="font-size:.65rem;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.35);margin-bottom:.2rem">Fecha</div><div>{report_date}</div></div>
      <div><div style="font-size:.65rem;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.35);margin-bottom:.2rem">Sensores</div><div>{total_sensors:,}</div></div>
      <div><div style="font-size:.65rem;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.35);margin-bottom:.2rem">Detecciones 90d</div><div>{detects_90d:,}</div></div>
      <div><div style="font-size:.65rem;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.35);margin-bottom:.2rem">Health Score</div><div style="font-size:1.8rem;font-weight:800;color:{score_color}">{health_score}/100</div></div>
    </div>
    <div style="font-size:.7rem;color:rgba(255,255,255,.25);border-top:1px solid rgba(255,255,255,.1);padding-top:.8rem">
      CONFIDENCIAL — Este documento contiene informacion privilegiada del tenant de seguridad.
    </div>
  </div>
</div>

<!-- NAVBAR -->
<nav class="navbar navbar-dark sticky-top no-print">
  <div class="container-fluid">
    <span class="navbar-brand">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="var(--cs-red)" style="margin-right:6px;vertical-align:-2px">
        <path d="M12 2L2 7v10l10 5 10-5V7L12 2z"/>
      </svg>
      CrowdStrike Health Check
    </span>
    <div class="d-flex gap-3 align-items-center">
      <a class="nav-link" href="#summary">Resumen</a>
      <a class="nav-link" href="#sensor-health">Sensores</a>
      <a class="nav-link" href="#policies">Politicas</a>
      <a class="nav-link" href="#risk-matrix">Riesgo</a>
      <a class="nav-link" href="#ngsiem">NG SIEM</a>
      <a class="nav-link" href="#detections">Detecciones</a>
      <a class="nav-link" href="#hosts">Hosts</a>
      <button class="btn btn-sm btn-outline-light ms-2" onclick="window.print()">&#x23F6; PDF</button>
    </div>
  </div>
</nav>

<!-- HEADER -->
<div style="background:var(--cs-dark);color:#fff;padding:1rem 2rem .8rem;">
  <div class="d-flex justify-content-between align-items-center flex-wrap gap-2">
    <div>
      <div style="font-size:1.2rem;font-weight:700">{client_name or 'Health Check Report'}</div>
      <div style="color:rgba(255,255,255,.4);font-size:.78rem">Generado: {report_date} | Datos: 90 dias (detecciones) / snapshot actual</div>
    </div>
  </div>
</div>

<div class="container-fluid px-4 py-4">

<!-- ============================= SECTION 1: EXECUTIVE SUMMARY ============================= -->
<section id="summary" class="mb-5">
  <div class="section-title">Resumen Ejecutivo</div>
  <div class="row g-3 mb-4">
    <!-- Health Score Donut -->
    <div class="col-6 col-md-3">
      <div class="card h-100">
        <div class="card-body d-flex flex-column align-items-center justify-content-center py-3">
          <div class="score-ring"><canvas id="chartHealthScore"></canvas>
            <div class="score-ring-label">
              <div class="score-ring-number" style="color:{score_color}">{health_score}</div>
              <div class="score-ring-text">Health Score</div>
            </div>
          </div>
          <div class="mt-2 text-center" style="font-size:.72rem">
            {f'<span class="badge" style="background:#7d1128">{recs_critical} Critical</span> ' if recs_critical else ''}
            {f'<span class="badge bg-danger">{recs_high} High</span>' if recs_high else ''}
            {f'<span class="badge bg-success">OK</span>' if not recs_critical and not recs_high else ''}
          </div>
        </div>
      </div>
    </div>
    <!-- Score Breakdown -->
    <div class="col-6 col-md-3">
      <div class="card h-100">
        <div class="card-header" style="font-size:.82rem">Score por categoria</div>
        <div class="card-body py-2" style="font-size:.78rem">
          <div class="mb-2"><div class="d-flex justify-content-between"><span>Sensor Freshness</span><span class="fw-bold">{health_breakdown.get('sensor_freshness',0):.0f}%</span></div>
            <div class="compliance-bar"><div class="compliance-fill" style="width:{health_breakdown.get('sensor_freshness',0)}%;background:{'#28a745' if health_breakdown.get('sensor_freshness',0)>=70 else '#ffc107' if health_breakdown.get('sensor_freshness',0)>=40 else '#dc3545'}"></div></div></div>
          <div class="mb-2"><div class="d-flex justify-content-between"><span>Sensor Activity</span><span class="fw-bold">{health_breakdown.get('sensor_activity',0):.0f}%</span></div>
            <div class="compliance-bar"><div class="compliance-fill" style="width:{health_breakdown.get('sensor_activity',0)}%;background:{'#28a745' if health_breakdown.get('sensor_activity',0)>=70 else '#ffc107' if health_breakdown.get('sensor_activity',0)>=40 else '#dc3545'}"></div></div></div>
          <div class="mb-2"><div class="d-flex justify-content-between"><span>RFM Free</span><span class="fw-bold">{health_breakdown.get('rfm',0):.0f}%</span></div>
            <div class="compliance-bar"><div class="compliance-fill" style="width:{health_breakdown.get('rfm',0)}%;background:{'#28a745' if health_breakdown.get('rfm',0)>=90 else '#ffc107' if health_breakdown.get('rfm',0)>=70 else '#dc3545'}"></div></div></div>
          <div class="mb-2"><div class="d-flex justify-content-between"><span>Policy Compliance</span><span class="fw-bold">{health_breakdown.get('policy_compliance',0):.0f}%</span></div>
            <div class="compliance-bar"><div class="compliance-fill" style="width:{health_breakdown.get('policy_compliance',0)}%;background:{'#28a745' if health_breakdown.get('policy_compliance',0)>=70 else '#ffc107' if health_breakdown.get('policy_compliance',0)>=40 else '#dc3545'}"></div></div></div>
          <div class="mb-2"><div class="d-flex justify-content-between"><span>Detection Resolution</span><span class="fw-bold">{health_breakdown.get('detection_resolution',0):.0f}%</span></div>
            <div class="compliance-bar"><div class="compliance-fill" style="width:{health_breakdown.get('detection_resolution',0)}%;background:{'#28a745' if health_breakdown.get('detection_resolution',0)>=70 else '#ffc107' if health_breakdown.get('detection_resolution',0)>=40 else '#dc3545'}"></div></div></div>
          <div class="mb-1"><div class="d-flex justify-content-between"><span>NG SIEM Usage</span><span class="fw-bold">{health_breakdown.get('ngsiem',0):.0f}%</span></div>
            <div class="compliance-bar"><div class="compliance-fill" style="width:{health_breakdown.get('ngsiem',0)}%;background:{'#28a745' if health_breakdown.get('ngsiem',0)>=70 else '#ffc107' if health_breakdown.get('ngsiem',0)>=40 else '#dc3545'}"></div></div></div>
        </div>
      </div>
    </div>
    <!-- KPI grid -->
    <div class="col-12 col-md-6">
      <div class="row g-3">
        <div class="col-4"><div class="card kpi-card h-100" style="border-top:4px solid var(--cs-red)"><div class="card-body"><div class="kpi-number">{total_sensors:,}</div><div class="kpi-label">Sensores</div></div></div></div>
        <div class="col-4"><div class="card kpi-card h-100" style="border-top:4px solid {'#dc3545' if inactive_14d > total_sensors*0.1 else '#ffc107' if inactive_14d > 0 else '#28a745'}"><div class="card-body"><div class="kpi-number" style="color:{'#dc3545' if inactive_14d > total_sensors*0.1 else '#6c757d'}">{inactive_14d}</div><div class="kpi-label">Inactivos 14d+</div></div></div></div>
        <div class="col-4"><div class="card kpi-card h-100" style="border-top:4px solid {'#dc3545' if rfm_count>0 else '#28a745'}"><div class="card-body"><div class="kpi-number" style="color:{'#dc3545' if rfm_count>0 else '#28a745'}">{rfm_count}</div><div class="kpi-label">RFM</div></div></div></div>
        <div class="col-4"><div class="card kpi-card h-100" style="border-top:4px solid #fd7e14"><div class="card-body"><div class="kpi-number">{detects_90d:,}</div><div class="kpi-label">Detecciones 90d</div></div></div></div>
        <div class="col-4"><div class="card kpi-card h-100" style="border-top:4px solid {'#dc3545' if dets_new_crit>0 else '#28a745'}"><div class="card-body"><div class="kpi-number" style="color:{'#dc3545' if dets_new_crit>0 else '#28a745'}">{dets_new_crit}</div><div class="kpi-label">Crit/High Open</div></div></div></div>
        <div class="col-4"><div class="card kpi-card h-100" style="border-top:4px solid #28a745"><div class="card-body"><div class="kpi-number">{sensor_fresh_pct}%</div><div class="kpi-label">Sensor Fresh</div></div></div></div>
      </div>
    </div>
  </div>

  <!-- NG SIEM ingest bar -->
  {'<div class="row g-3 mb-3"><div class="col-12"><div class="card" style="border-left:4px solid var(--cs-red)"><div class="card-body py-2"><div class="d-flex justify-content-between align-items-center flex-wrap gap-2"><div><strong>NG SIEM Ingesta</strong> <span class="text-muted" style="font-size:.85rem">Prom: <strong>' + str(ng_avg_gb_day) + ' GB</strong> / <strong>' + str(ng_limit_gb) + ' GB</strong> limite | Hoy: <strong>' + str(ng_today_mb) + ' MB</strong></span></div><div style="font-size:.82rem;color:#6c757d">' + str(ng_pct_used) + '%</div></div><div class="progress mt-2" style="height:8px"><div class="progress-bar" style="width:' + str(min(ng_pct_used,100)) + '%;background:var(--cs-red)"></div></div></div></div></div></div>' if ng_avg_gb_day else ''}

  <!-- Charts row -->
  <div class="row g-3">
    <div class="col-md-3">
      <div class="card h-100"><div class="card-header">Plataformas</div>
        <div class="card-body d-flex align-items-center justify-content-center">
          <div style="height:200px;width:200px;position:relative"><canvas id="chartPlatform"></canvas></div></div></div>
    </div>
    <div class="col-md-3">
      <div class="card h-100"><div class="card-header">Severidad detecciones</div>
        <div class="card-body d-flex align-items-center justify-content-center">
          <div style="height:200px;width:200px;position:relative"><canvas id="chartDetSev"></canvas></div></div></div>
    </div>
    <div class="col-md-3">
      <div class="card h-100"><div class="card-header">Estado detecciones</div>
        <div class="card-body"><div style="height:200px"><canvas id="chartDetStatus"></canvas></div></div></div>
    </div>
    <div class="col-md-3">
      <div class="card h-100"><div class="card-header">Policy Compliance</div>
        <div class="card-body py-2" style="font-size:.82rem">
          <div class="mb-3"><div class="d-flex justify-content-between"><span>Windows ({win_on}/{win_total})</span><strong>{win_pct}%</strong></div>
            <div class="compliance-bar mt-1"><div class="compliance-fill" style="width:{win_pct}%;background:{'#28a745' if win_pct>=70 else '#ffc107' if win_pct>=40 else '#dc3545'}"></div></div></div>
          <div class="mb-3"><div class="d-flex justify-content-between"><span>Mac ({mac_on}/{mac_total})</span><strong>{mac_pct}%</strong></div>
            <div class="compliance-bar mt-1"><div class="compliance-fill" style="width:{mac_pct}%;background:{'#28a745' if mac_pct>=70 else '#ffc107' if mac_pct>=40 else '#dc3545'}"></div></div></div>
          <div><div class="d-flex justify-content-between"><span>Linux ({lin_on}/{lin_total})</span><strong>{lin_pct}%</strong></div>
            <div class="compliance-bar mt-1"><div class="compliance-fill" style="width:{lin_pct}%;background:{'#28a745' if lin_pct>=70 else '#ffc107' if lin_pct>=40 else '#dc3545'}"></div></div></div>
        </div></div>
    </div>
  </div>
</section>


<!-- ============================= SECTION 2: SENSOR HEALTH ============================= -->
<section id="sensor-health" class="mb-5">
  <div class="section-title">Salud del Sensor</div>
  <div class="row g-3 mb-4">
    <div class="col-md-7">
      <div class="card h-100">
        <div class="card-header">Sensor Age por plataforma (versión relativa al N más reciente)</div>
        <div class="card-body">
          <div class="chart-container-lg">
            <canvas id="chartSensorAge"></canvas>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-5">
      <div class="card h-100">
        <div class="card-header">Versiones de agente (Top 15)</div>
        <div class="card-body p-0">
          <div class="table-responsive" style="max-height:340px;overflow-y:auto">
            <table class="table table-sm table-hover mb-0" id="tblAgentVer">
              <thead class="table-dark sticky-top"><tr>
                <th>Plataforma</th><th>Versión</th><th>Devices</th>
              </tr></thead>
              <tbody id="tbodyAgentVer"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div class="row g-3">
    <div class="col-md-5">
      <div class="card h-100">
        <div class="card-header">Versiones de SO</div>
        <div class="card-body p-0">
          <div class="table-responsive" style="max-height:340px;overflow-y:auto">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-dark sticky-top"><tr>
                <th>OS Version</th><th>Devices</th>
              </tr></thead>
              <tbody id="tbodyOsVer"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-7">
      <div class="card h-100">
        <div class="card-header">Sensor Update Policies</div>
        <div class="card-body p-0">
          <div class="table-responsive" style="max-height:340px;overflow-y:auto">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-dark sticky-top"><tr>
                <th>Política</th><th>Hosts</th>
              </tr></thead>
              <tbody id="tbodySupd"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============================= SECTION 3: POLICIES ============================= -->
<section id="policies" class="mb-5">
  <div class="section-title">Configuración de Políticas</div>
  <ul class="nav nav-tabs mb-3" id="polTabs">
    <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#polWin">Windows</button></li>
    <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#polMac">Mac</button></li>
    <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#polLin">Linux</button></li>
  </ul>
  <div class="tab-content">
    <div class="tab-pane fade show active" id="polWin">
      <div class="fw-semibold mb-2" style="font-size:.9rem">Prevention Policy Settings — Windows</div>
      <div class="policy-table-wrap">{win_pol_html}</div>
    </div>
    <div class="tab-pane fade" id="polMac">
      <div class="fw-semibold mb-2" style="font-size:.9rem">Prevention Policy Settings — Mac</div>
      <div class="policy-table-wrap">{mac_pol_html}</div>
    </div>
    <div class="tab-pane fade" id="polLin">
      <div class="fw-semibold mb-2" style="font-size:.9rem">Prevention Policy Settings — Linux</div>
      <div class="policy-table-wrap">{lin_pol_html}</div>
    </div>
  </div>
</section>

<!-- ============================= SECTION 3a: RISK vs FRICTION ============================= -->
<section id="risk-matrix" class="mb-5">
  <div class="section-title">Matriz de Riesgo vs Friccion — Prevention Settings</div>
  <div class="alert alert-light py-2 mb-3" style="font-size:.82rem;border-left:4px solid var(--cs-red)">
    <strong>Riesgo:</strong> impacto de tener el setting desactivado (OFF). &nbsp;
    <strong>Friccion:</strong> impacto operativo de activarlo (ON) — posibles falsos positivos o afectacion a usuarios.
    <br><small class="text-muted">Recomendacion: activar primero los settings de riesgo CRITICAL + friccion LOW. Para friccion HIGH, empezar en modo DETECT antes de pasar a PREVENT.</small>
  </div>
  {_build_risk_matrix_html(df_prev)}
</section>

<!-- ============================= SECTION 3b: NG SIEM ============================= -->
<section id="ngsiem" class="mb-5">
  <div class="section-title">NG SIEM (LogScale)</div>
  {ng_error_html}
  <!-- KPI cards -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-2">
      <div class="card kpi-card h-100" style="border-top:4px solid {'#28a745' if ng_available else '#6c757d'}">
        <div class="card-body">
          <div style="font-size:1.1rem;font-weight:700;margin-bottom:.3rem">{ng_status_badge}</div>
          <div class="kpi-label">Estado NG SIEM</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card kpi-card h-100" style="border-top:4px solid #0d6efd">
        <div class="card-body">
          <div class="kpi-number">{ng_repos_count}</div>
          <div class="kpi-label">Repositorios</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card kpi-card h-100" style="border-top:4px solid #6c757d">
        <div class="card-body">
          <div class="kpi-number">{ng_views_count}</div>
          <div class="kpi-label">Vistas (Views)</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card kpi-card h-100" style="border-top:4px solid #fd7e14">
        <div class="card-body">
          <div class="kpi-number">{len(ng_connectors)}</div>
          <div class="kpi-label">Fuentes / Conectores</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card kpi-card h-100" style="border-top:4px solid var(--cs-red)">
        <div class="card-body">
          <div class="kpi-number">{ng_daily_avg_gb}</div>
          <div class="kpi-label">GB/día promedio (7d)</div>
        </div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card kpi-card h-100" style="border-top:4px solid #198754">
        <div class="card-body">
          <div class="kpi-number">{ng_total_events_7d:,}</div>
          <div class="kpi-label">Eventos totales (7d)</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="row g-3 mb-4">
    <div class="col-md-7">
      <div class="card h-100">
        <div class="card-header">Ingesta diaria (últimos 7 días)</div>
        <div class="card-body">
          <div class="chart-container">
            <canvas id="chartNgTrend"></canvas>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-5">
      <div class="card h-100">
        <div class="card-header">Eventos por fuente / conector</div>
        <div class="card-body">
          <div class="chart-container">
            <canvas id="chartNgSources"></canvas>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Data Connections table -->
  <div class="row g-3">
    <div class="col-md-8">
      <div class="card h-100">
        <div class="card-header">Data Connections ({len(ng_manual_connectors) or len(ng_connectors)} conexiones)</div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-sm table-hover mb-0" id="tblNgConn">
              <thead class="table-dark">
                <tr><th>Estado</th><th>Nombre</th><th>Ingest 24h</th></tr>
              </thead>
              <tbody id="tbodyNgConn"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card h-100">
        <div class="card-header">Fuentes detectadas (desde Alerts XDR)</div>
        <div class="card-body p-0">
          <div class="table-responsive" style="max-height:160px;overflow-y:auto">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-dark sticky-top"><tr><th>Producto</th></tr></thead>
              <tbody id="tbodyNgProducts"></tbody>
            </table>
          </div>
          <div class="table-responsive" style="max-height:120px;overflow-y:auto">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-dark sticky-top"><tr><th>Vendor</th></tr></thead>
              <tbody id="tbodyNgVendors"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ============================= SECTION 4: DETECTIONS ============================= -->
<section id="detections" class="mb-5">
  <div class="section-title">Detecciones (últimos 90 días)</div>
  <div class="row g-3 mb-3">
    <div class="col-md-4">
      <div class="card h-100">
        <div class="card-header">Por Táctica (MITRE ATT&CK)</div>
        <div class="card-body">
          <div class="chart-container-lg">
            <canvas id="chartDetTactic"></canvas>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card h-100">
        <div class="card-header">Por Plataforma</div>
        <div class="card-body d-flex align-items-center justify-content-center">
          <div style="height:260px;width:260px;position:relative">
            <canvas id="chartDetPlat"></canvas>
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card h-100">
        <div class="card-header">Top 10 Hosts con más detecciones</div>
        <div class="card-body p-0">
          <div class="table-responsive" style="max-height:280px;overflow-y:auto">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-dark sticky-top"><tr>
                <th>Hostname</th><th>Platform</th><th>Detecciones</th>
              </tr></thead>
              <tbody id="tbodyTopHosts"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
  <!-- Trend -->
  <div class="row g-3 mb-3">
    <div class="col-12">
      <div class="card">
        <div class="card-header">Tendencia diaria de detecciones</div>
        <div class="card-body">
          <div class="chart-container-trend">
            <canvas id="chartDetTrend"></canvas>
          </div>
        </div>
      </div>
    </div>
  </div>
  <!-- Detections table -->
  <div class="card">
    <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
      <span>Detecciones detalladas</span>
      <input type="text" class="form-control form-control-sm search-box no-print"
             id="searchDets" placeholder="Buscar en detecciones...">
    </div>
    <div class="card-body p-0">
      <div class="table-responsive" style="max-height:480px;overflow-y:auto">
        <table class="table table-sm table-hover mb-0 filterable-table" id="tblDets">
          <thead class="table-dark sticky-top">
            <tr id="tblDetsHead"></tr>
          </thead>
          <tbody id="tbodyDets"></tbody>
        </table>
      </div>
      <div class="p-2 text-muted" style="font-size:.78rem" id="detCount"></div>
    </div>
  </div>
</section>

<!-- ============================= SECTION 5: HOSTS ============================= -->
<section id="hosts" class="mb-5">
  <div class="section-title">Inventario de Hosts</div>
  <div class="card">
    <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
      <span>Todos los hosts ({total_sensors:,} total)</span>
      <input type="text" class="form-control form-control-sm search-box no-print"
             id="searchHosts" placeholder="Buscar hostname, IP, OS...">
    </div>
    <div class="card-body p-0">
      <div class="table-responsive" style="max-height:520px;overflow-y:auto">
        <table class="table table-sm table-hover mb-0 filterable-table" id="tblHosts">
          <thead class="table-dark sticky-top">
            <tr id="tblHostsHead"></tr>
          </thead>
          <tbody id="tbodyHosts"></tbody>
        </table>
      </div>
      <div class="p-2 text-muted" style="font-size:.78rem" id="hostCount"></div>
    </div>
  </div>
</section>

</div><!-- /container -->

<footer class="no-print">
  <div class="d-flex justify-content-between flex-wrap gap-2">
    <span>CrowdStrike Falcon Health Check &mdash; {client_name or cid}</span>
    <span>Generado: {report_date}</span>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ============================================================
// EMBEDDED DATA
// ============================================================
const D = {{
  agentVersions: {agent_ver_json},
  osVersions:    {os_ver_json},
  supdCounts:    {supd_rows_json},
  topHosts:      {top_hosts_json},
  dets:          {det_json},
  hosts:         {hosts_json},
  ageLabels:     {json.dumps(age_labels)},
  agePlatforms:  {json.dumps(age_platforms)},
  ageData:       {json.dumps(age_data)},
  detStatusLabels:{json.dumps(det_status_labels)},
  detStatusVals:  {json.dumps(det_status_vals)},
  detStatusColors:{json.dumps(det_status_colors)},
  detSevLabels:   {json.dumps(det_sev_labels)},
  detSevVals:     {json.dumps(det_sev_vals)},
  detSevColors:   {json.dumps(det_sev_colors)},
  detPlatLabels:  {json.dumps(det_plat_labels)},
  detPlatVals:    {json.dumps(det_plat_vals)},
  detTacticLabels:{json.dumps(det_tactic_labels)},
  detTacticVals:  {json.dumps(det_tactic_vals)},
  trendLabels:    {json.dumps(trend_labels)},
  trendVals:      {json.dumps(trend_vals)},
  winSensors:     {win_sensors},
  macSensors:     {mac_sensors},
  linSensors:     {lin_sensors},
  // NG SIEM
  ngTrendLabels:  {json.dumps(ng_trend_labels)},
  ngTrendGB:      {json.dumps(ng_trend_gb)},
  ngTrendEvents:  {json.dumps(ng_trend_events)},
  ngSrcLabels:    {json.dumps(ng_src_labels)},
  ngSrcEvents:    {json.dumps(ng_src_events)},
  ngRepos:        {json.dumps(ng_repos_rows)},
  ngViews:        {json.dumps(ng_views_rows)},
  ngConnectors:        {json.dumps(ng_connectors)},
  ngManualConnectors:  {json.dumps(ng_manual_connectors)},
  ngProducts:          {json.dumps(ng_products)},
  ngVendors:           {json.dumps(ng_vendors)},
  ngInferred:          {json.dumps(ng_inferred)},
}};

// ============================================================
// CHARTS
// ============================================================
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
Chart.defaults.plugins.legend.labels.boxWidth = 12;

// Health Score donut
new Chart(document.getElementById('chartHealthScore'), {{
  type:'doughnut',
  data:{{
    datasets:[{{
      data:[{health_score}, {100-health_score}],
      backgroundColor:['{score_color}', '#e9ecef'],
      borderWidth:0, cutout:'78%'
    }}]
  }},
  options:{{ responsive:false, maintainAspectRatio:false,
             plugins:{{ legend:{{ display:false }}, tooltip:{{ enabled:false }} }},
             animation:{{ animateRotate:true, duration:1200 }} }}
}});

// Platform donut
new Chart(document.getElementById('chartPlatform'), {{
  type:'doughnut',
  data:{{ labels:['Windows','Mac','Linux'],
          datasets:[{{ data:[D.winSensors, D.macSensors, D.linSensors],
                       backgroundColor:['#0d6efd','#6c757d','#fd7e14'],
                       borderWidth:2, borderColor:'#fff' }}] }},
  options:{{ responsive:true, maintainAspectRatio:false,
             plugins:{{ legend:{{ position:'bottom' }} }} }}
}});

// Detection status bar
new Chart(document.getElementById('chartDetStatus'), {{
  type:'bar',
  data:{{ labels: D.detStatusLabels,
          datasets:[{{ label:'Detecciones', data: D.detStatusVals,
                       backgroundColor: D.detStatusColors, borderRadius:4 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, indexAxis:'y',
             plugins:{{ legend:{{ display:false }} }},
             scales:{{ x:{{ grid:{{ display:false }} }} }} }}
}});

// Detection severity donut
new Chart(document.getElementById('chartDetSev'), {{
  type:'doughnut',
  data:{{ labels: D.detSevLabels,
          datasets:[{{ data: D.detSevVals,
                       backgroundColor: D.detSevColors,
                       borderWidth:2, borderColor:'#fff' }}] }},
  options:{{ responsive:true, maintainAspectRatio:false,
             plugins:{{ legend:{{ position:'right' }} }} }}
}});

// Sensor Age grouped bar
const ageColors = ['#28a745','#6fbf73','#ffc107','#fd7e14','#dc3545'];
const ageDatasets = D.ageLabels.map((lbl,i) => ({{
  label: lbl,
  data: D.agePlatforms.map(p => (D.ageData[p] || [])[i] || 0),
  backgroundColor: ageColors[i], borderRadius:3
}}));
new Chart(document.getElementById('chartSensorAge'), {{
  type:'bar',
  data:{{ labels: D.agePlatforms, datasets: ageDatasets }},
  options:{{ responsive:true, maintainAspectRatio:false,
             plugins:{{ legend:{{ position:'bottom' }} }},
             scales:{{ x:{{ stacked:false }}, y:{{ stacked:false, beginAtZero:true }} }} }}
}});

// Detection tactic horizontal bar
new Chart(document.getElementById('chartDetTactic'), {{
  type:'bar',
  data:{{ labels: D.detTacticLabels,
          datasets:[{{ label:'Detecciones', data: D.detTacticVals,
                       backgroundColor:'#E1001A', borderRadius:3 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, indexAxis:'y',
             plugins:{{ legend:{{ display:false }} }},
             scales:{{ x:{{ grid:{{ display:false }}, beginAtZero:true }} }} }}
}});

// Detection platform donut
new Chart(document.getElementById('chartDetPlat'), {{
  type:'doughnut',
  data:{{ labels: D.detPlatLabels,
          datasets:[{{ data: D.detPlatVals,
                       backgroundColor:['#0d6efd','#6c757d','#fd7e14','#28a745'],
                       borderWidth:2, borderColor:'#fff' }}] }},
  options:{{ responsive:true, maintainAspectRatio:false,
             plugins:{{ legend:{{ position:'bottom' }} }} }}
}});

// Detection trend line
if(D.trendLabels.length > 0) {{
  new Chart(document.getElementById('chartDetTrend'), {{
    type:'line',
    data:{{ labels: D.trendLabels,
            datasets:[{{ label:'Detecciones/día', data: D.trendVals,
                         borderColor:'#E1001A', backgroundColor:'rgba(225,0,26,.08)',
                         fill:true, tension:.3, pointRadius:2 }}] }},
    options:{{ responsive:true, maintainAspectRatio:false,
               plugins:{{ legend:{{ display:false }} }},
               scales:{{ x:{{ ticks:{{ maxTicksLimit:15 }}, grid:{{ display:false }} }},
                         y:{{ beginAtZero:true }} }} }}
  }});
}} else {{
  document.getElementById('chartDetTrend').parentElement.innerHTML =
    '<p class="text-muted text-center pt-4">Sin datos de tendencia</p>';
}}

// ============================================================
// TABLES
// ============================================================
function buildTable(tbodyId, data, cols, renderFn) {{
  const tbody = document.getElementById(tbodyId);
  if(!tbody) return;
  tbody.innerHTML = '';
  if(!data || !data.length) {{
    tbody.innerHTML = '<tr><td colspan="99" class="text-muted text-center">Sin datos</td></tr>';
    return;
  }}
  data.forEach(row => {{
    const tr = document.createElement('tr');
    tr.innerHTML = renderFn ? renderFn(row) : cols.map(c => `<td>${{row[c]??''}}</td>`).join('');
    tbody.appendChild(tr);
  }});
}}

function buildDynamicTable(headId, tbodyId, countId, data, searchId, sevCol, statusCol) {{
  if(!data || !data.length) return;
  const cols = Object.keys(data[0]);
  const head = document.getElementById(headId);
  head.innerHTML = cols.map(c => `<th>${{c}}</th>`).join('');

  let filtered = data;

  function render(rows) {{
    const tbody = document.getElementById(tbodyId);
    tbody.innerHTML = '';
    rows.forEach(row => {{
      const tr = document.createElement('tr');
      tr.innerHTML = cols.map(c => {{
        let val = row[c] ?? '';
        if(c === sevCol)   return `<td><span class="sev-${{String(val).toUpperCase()}}">${{val}}</span></td>`;
        if(c === statusCol) return `<td><span class="status-${{String(val).toUpperCase().replace(' ','_')}}">${{val}}</span></td>`;
        return `<td>${{val}}</td>`;
      }}).join('');
      tbody.appendChild(tr);
    }});
    const cnt = document.getElementById(countId);
    if(cnt) cnt.textContent = `Mostrando ${{rows.length}} de ${{data.length}} filas`;
  }}

  render(filtered);

  const searchBox = document.getElementById(searchId);
  if(searchBox) {{
    searchBox.addEventListener('input', () => {{
      const q = searchBox.value.toLowerCase();
      filtered = q ? data.filter(r => cols.some(c => String(r[c]??'').toLowerCase().includes(q))) : data;
      render(filtered);
    }});
  }}
}}

// Agent versions
buildTable('tbodyAgentVer', D.agentVersions, [], r =>
  `<td>${{r.platform_name||''}}</td><td><code>${{r.agent_version||''}}</code></td><td>${{r.device_count||0}}</td>`
);

// OS versions
buildTable('tbodyOsVer', D.osVersions, [], r =>
  `<td>${{r.os_version||r['Os Version']||''}}</td><td>${{r.device_count||r['Os Device Count']||0}}</td>`
);

// Sensor Update
buildTable('tbodySupd', D.supdCounts, [], r =>
  `<td>${{r.policy_sensor_update_name||r.policy_name||''}}</td><td>${{r.host_count||0}}</td>`
);

// Top Hosts
buildTable('tbodyTopHosts', D.topHosts, [], r =>
  `<td>${{r.hostname||''}}</td><td>${{r.platform_name||''}}</td><td><strong>${{r.detections||0}}</strong></td>`
);

// Detections dynamic table
buildDynamicTable('tblDetsHead','tbodyDets','detCount', D.dets, 'searchDets', 'severity', 'status');

// Hosts dynamic table
buildDynamicTable('tblHostsHead','tbodyHosts','hostCount', D.hosts, 'searchHosts', null, null);

// ============================================================
// NG SIEM charts & tables
// ============================================================
if(D.ngTrendLabels.length > 0) {{
  // Dual-axis: GB + Events per day
  new Chart(document.getElementById('chartNgTrend'), {{
    type:'bar',
    data:{{
      labels: D.ngTrendLabels,
      datasets:[
        {{ label:'GB ingeridos', data: D.ngTrendGB, backgroundColor:'rgba(225,0,26,.7)',
           yAxisID:'yGB', borderRadius:3 }},
        {{ label:'Eventos', data: D.ngTrendEvents, type:'line',
           borderColor:'#0d6efd', backgroundColor:'transparent',
           yAxisID:'yEv', tension:.3, pointRadius:3 }}
      ]
    }},
    options:{{
      responsive:true, maintainAspectRatio:false,
      plugins:{{ legend:{{ position:'bottom' }} }},
      scales:{{
        yGB:{{ type:'linear', position:'left',  title:{{ display:true, text:'GB' }}, beginAtZero:true }},
        yEv:{{ type:'linear', position:'right', title:{{ display:true, text:'Eventos' }}, beginAtZero:true,
               grid:{{ drawOnChartArea:false }} }},
        x:{{ grid:{{ display:false }} }}
      }}
    }}
  }});
}} else {{
  document.getElementById('chartNgTrend').parentElement.innerHTML =
    '<p class="text-muted text-center pt-5">Sin datos de ingesta disponibles.<br><small>Requiere permisos de LogScale en el API key.</small></p>';
}}

if(D.ngSrcLabels.length > 0) {{
  const palette = ['#E1001A','#0d6efd','#fd7e14','#28a745','#6c757d',
                   '#6610f2','#d63384','#0dcaf0','#ffc107','#20c997'];
  new Chart(document.getElementById('chartNgSources'), {{
    type:'doughnut',
    data:{{
      labels: D.ngSrcLabels,
      datasets:[{{ data: D.ngSrcEvents,
                   backgroundColor: D.ngSrcLabels.map((_,i)=>palette[i%palette.length]),
                   borderWidth:2, borderColor:'#fff' }}]
    }},
    options:{{ responsive:true, maintainAspectRatio:false,
               plugins:{{ legend:{{ position:'bottom', labels:{{ boxWidth:10, font:{{size:11}} }} }} }} }}
  }});
}} else {{
  document.getElementById('chartNgSources').parentElement.innerHTML =
    '<p class="text-muted text-center pt-5">Sin datos de fuentes disponibles.</p>';
}}

// NG Repos table
buildTable('tbodyNgRepos', D.ngRepos, [], r =>
  `<td><strong>${{r.name}}</strong></td>` +
  `<td>${{r.retention_days}} días</td>` +
  `<td>${{r.compressed_gb}} GB</td>`
);

// NG Views table
buildTable('tbodyNgViews', D.ngViews, [], r =>
  `<td><strong>${{r.name}}</strong></td><td><small class="text-muted">${{r.connections||'—'}}</small></td>`
);

// Data Connections table — manual connectors tienen prioridad
const connData = D.ngManualConnectors.length ? D.ngManualConnectors
               : D.ngConnectors.map(c => ({{name:c, status:'—', ingest_24h:'—', status_color:'#6c757d'}}));
buildTable('tbodyNgConn', connData, [], r => {{
  const dot = `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${{r.status_color}};margin-right:6px"></span>`;
  const statusBold = r.status ? `<strong>${{r.status}}</strong>` : '—';
  return `<td>${{dot}}${{statusBold}}</td><td>${{r.name}}</td><td><code>${{r.ingest_24h}}</code></td>`;
}});

// Products & Vendors from Alerts
buildTable('tbodyNgProducts',
  (D.ngProducts.length ? D.ngProducts : D.ngConnectors).map(c=>({{v:c}})), [], r =>
  `<td><code style="font-size:.78rem">${{r.v}}</code></td>`
);
buildTable('tbodyNgVendors', D.ngVendors.map(c=>({{v:c}})), [], r =>
  `<td><small>${{r.v}}</small></td>`
);
if(D.ngInferred) {{
  const note = document.createElement('div');
  note.className = 'text-muted px-2 pb-1';
  note.style.fontSize = '.75rem';
  note.textContent = '* Datos inferidos desde Alerts XDR. Para ingesta en GB contactá tu TAM.';
  document.getElementById('ngsiem')?.appendChild(note);
}}

</script>
</body>
</html>"""

    return html


# ---------------------------
# MAIN
# ---------------------------
def main():
    # -------- Diagnóstico de scopes
    logging.info("Verificando scopes del API key...")
    scopes = check_api_scopes(CID, SEC, BASE, MCID)
    for scope, status in scopes.items():
        icon = "✓" if status == "OK" else "✗"
        logging.info("  %s  %-25s %s", icon, scope, status)

    api        = APIHarnessV2(client_id=CID, client_secret=SEC, base_url=BASE, member_cid=MCID, pythonic=True)
    hosts_cli  = Hosts(client_id=CID,  client_secret=SEC, base_url=BASE, member_cid=MCID)
    detects_cli= Detects(client_id=CID, client_secret=SEC, base_url=BASE, member_cid=MCID)
    alerts_cli = Alerts(client_id=CID,  client_secret=SEC, base_url=BASE, member_cid=MCID)

    # -------- Hosts
    logging.info("Cargando hosts...")
    aids      = fetch_all_aids(hosts_cli)
    hosts_raw = fetch_host_details(hosts_cli, aids)
    hosts_rows = []
    for r in hosts_raw:
        dp   = r.get("device_policies") or {}
        prev = (dp.get("prevention") or {})
        supd = (dp.get("sensor_update") or {})
        fw   = (dp.get("firewall") or {})
        dctl = (dp.get("device_control") or {})
        hosts_rows.append({
            "aid":               r.get("device_id") or r.get("aid"),
            "hostname":          r.get("hostname"),
            "platform_name":     r.get("platform_name"),
            "os_version":        r.get("os_version"),
            "agent_version":     r.get("agent_version"),
            "local_ip":          r.get("local_ip"),
            "site_name":         r.get("site_name"),
            "ou":                r.get("ou"),
            "last_seen":         r.get("last_seen"),
            "rfm_state":         r.get("reduced_functionality_mode") or r.get("rfm_state"),
            "policy_prevention_id":    prev.get("policy_id"),
            "policy_sensor_update_id": supd.get("policy_id"),
            "policy_firewall_id":      fw.get("policy_id"),
            "policy_device_control_id":dctl.get("policy_id"),
        })
    df_hosts = pd.DataFrame(hosts_rows)

    # -------- Totales
    last_seen_cut = datetime.now(timezone.utc) - timedelta(days=14)
    def inactive(ts):
        try: return pd.to_datetime(ts, utc=True) < last_seen_cut
        except: return False
    if not df_hosts.empty:
        df_hosts["is_inactive_14d"] = df_hosts["last_seen"].apply(inactive)

    totals = {
        "Total Sensors":   len(df_hosts),
        "Windows Sensors": int((df_hosts["platform_name"].str.lower()=="windows").sum()) if not df_hosts.empty else 0,
        "Mac Sensors":     int((df_hosts["platform_name"].str.lower()=="mac").sum())     if not df_hosts.empty else 0,
        "Linux Sensors":   int((df_hosts["platform_name"].str.lower()=="linux").sum())   if not df_hosts.empty else 0,
        "Inactive (>14d)": int(df_hosts["is_inactive_14d"].sum()) if not df_hosts.empty and "is_inactive_14d" in df_hosts else 0,
    }
    df_summary = pd.DataFrame([totals])

    # -------- Sensor Age
    counts_win = sensor_age_counts_exact(df_hosts, "Windows")
    counts_mac = sensor_age_counts_exact(df_hosts, "Mac")
    counts_lin = sensor_age_counts_exact(df_hosts, "Linux")
    df_sensor_age_counts = pd.DataFrame([
        {"platform":"Windows", **counts_win},
        {"platform":"Mac",     **counts_mac},
        {"platform":"Linux",   **counts_lin},
        {"platform":"Combined",
         "N":        counts_win["N"]+counts_mac["N"]+counts_lin["N"],
         "N-1":      counts_win["N-1"]+counts_mac["N-1"]+counts_lin["N-1"],
         "N-2":      counts_win["N-2"]+counts_mac["N-2"]+counts_lin["N-2"],
         "N-3_plus": counts_win["N-3_plus"]+counts_mac["N-3_plus"]+counts_lin["N-3_plus"],
         "Unsupported": 0}
    ])

    # -------- Policies
    logging.info("Cargando políticas...")
    def collect_policies_safe(combined_op, query_op, get_op):
        out = []
        for plat in ("Windows","Mac","Linux"):
            flt = f"platform_name:'{plat}'"
            try:    out += query_combined(api, combined_op, flt)
            except: out += get_policies_via_ids(api, query_op, get_op, flt)
        return out

    pol_prev = collect_policies_safe("queryCombinedPreventionPolicies","queryPreventionPolicies","getPreventionPolicies")
    pol_supd = collect_policies_safe("queryCombinedSensorUpdatePolicies","querySensorUpdatePolicies","getSensorUpdatePolicies")
    try:    pol_fw   = collect_policies_safe("queryCombinedFirewallPolicies","queryFirewallPolicies","getFirewallPolicies")
    except: pol_fw   = []
    try:    pol_dctl = collect_policies_safe("queryCombinedDeviceControlPolicies","queryDeviceControlPolicies","getDeviceControlPolicies")
    except: pol_dctl = []

    rows_prev = list(itertools.chain.from_iterable(flatten_policy_settings(p) for p in pol_prev))
    rows_supd = list(itertools.chain.from_iterable(flatten_policy_settings(p) for p in pol_supd))
    rows_fw   = list(itertools.chain.from_iterable(flatten_policy_settings(p) for p in pol_fw))
    rows_dctl = list(itertools.chain.from_iterable(flatten_policy_settings(p) for p in pol_dctl))

    df_prev = pd.DataFrame(rows_prev)
    df_supd = pd.DataFrame(rows_supd)
    df_fw   = pd.DataFrame(rows_fw)
    df_dctl = pd.DataFrame(rows_dctl)

    def id2name(dfpol):
        return dict(dfpol[["policy_id","policy_name"]].drop_duplicates().values) if not dfpol.empty else {}

    map_prev = id2name(df_prev); map_supd = id2name(df_supd)
    map_fw   = id2name(df_fw);   map_dctl = id2name(df_dctl)

    if not df_hosts.empty:
        df_hosts["policy_prevention_name"]    = df_hosts["policy_prevention_id"].map(map_prev).fillna("(desconocida)")
        df_hosts["policy_sensor_update_name"] = df_hosts["policy_sensor_update_id"].map(map_supd).fillna("(desconocida)")
        df_hosts["policy_firewall_name"]      = df_hosts["policy_firewall_id"].map(map_fw).fillna("(desconocida)")
        df_hosts["policy_device_control_name"]= df_hosts["policy_device_control_id"].map(map_dctl).fillna("(desconocida)")

    # Uninstall protection
    def uninstall_flag(df_settings):
        if df_settings.empty: return pd.DataFrame(columns=["platform_name","pct_uninstall_protection_disabled"])
        mask = df_settings["setting_name"].str.contains("uninstall|tamper", case=False, na=False) | \
               df_settings["setting_id"].str.contains("uninstall|tamper", case=False, na=False)
        sub = df_settings[mask].copy()
        if sub.empty: return pd.DataFrame(columns=["platform_name","pct_uninstall_protection_disabled"])
        sub["is_disabled"] = sub["value_norm"].map(lambda x: str(x).upper()=="OFF")
        out = sub.groupby("platform_name")["is_disabled"].mean().mul(100).round(2).reset_index()
        out.rename(columns={"is_disabled":"pct_uninstall_protection_disabled"}, inplace=True)
        return out
    df_uninstall = uninstall_flag(df_supd)

    # Host counts per policy
    def count_by(df, id_col, name_col):
        if df.empty or id_col not in df:
            return pd.DataFrame(columns=[id_col, name_col, "host_count"])
        return (df.groupby([id_col, name_col], dropna=False)
                   .size().reset_index(name="host_count")
                   .sort_values(["host_count", name_col], ascending=[False, True]))

    df_count_prev = count_by(df_hosts, "policy_prevention_id",     "policy_prevention_name")
    df_count_supd = count_by(df_hosts, "policy_sensor_update_id",  "policy_sensor_update_name")
    df_count_fw   = count_by(df_hosts, "policy_firewall_id",       "policy_firewall_name")
    df_count_dctl = count_by(df_hosts, "policy_device_control_id", "policy_device_control_name")

    # Agent / OS versions
    if not df_hosts.empty:
        df_agent_versions = (df_hosts.dropna(subset=["agent_version"])
                                      .groupby(["platform_name","agent_version"])
                                      .size().reset_index(name="device_count")
                                      .sort_values(["platform_name","device_count"], ascending=[True,False]))
        df_os_versions = (df_hosts.dropna(subset=["os_version"])
                                   .groupby(["os_version"]).size().reset_index(name="device_count")
                                   .sort_values("device_count", ascending=False))
    else:
        df_agent_versions = pd.DataFrame(columns=["platform_name","agent_version","device_count"])
        df_os_versions    = pd.DataFrame(columns=["os_version","device_count"])

    # -------- Detections (prueba Detects API; si vacío, intenta Alerts)
    logging.info("Cargando detecciones (90d)...")
    try:
        df_dets = export_detections(detects_cli, time_filter="created_timestamp:>='-90d'", max_ids=20000)
        if df_dets.empty and scopes.get("alerts:read") == "OK":
            logging.info("Detects API sin resultados — intentando Alerts API...")
            df_dets = export_alerts(alerts_cli, days_back=90, max_ids=20000)
            if not df_dets.empty:
                logging.info("Alerts API: %d registros", len(df_dets))
        if df_dets.empty:
            df_dets_status = df_dets_sev = df_dets_plat = df_dets_tactic = pd.DataFrame(columns=["status","count"])
            df_detects_summary = pd.DataFrame([{"detects_90d":0,"pct_new_90d":0.0}])
        else:
            det_total = df_dets["detection_id"].nunique()
            pct_new   = df_dets.groupby("detection_id")["status"].first().str.upper().eq("NEW").mean()*100
            df_dets_status = df_dets.groupby("status").size().reset_index(name="count").sort_values("count", ascending=False)
            df_dets_sev    = df_dets.groupby("severity").size().reset_index(name="count").sort_values("count", ascending=False)
            df_dets_plat   = df_dets.groupby("platform_name").size().reset_index(name="count").sort_values("count", ascending=False)
            df_dets_tactic = df_dets.groupby("tactic").size().reset_index(name="count").sort_values("count", ascending=False)
            df_detects_summary = pd.DataFrame([{"detects_90d": int(det_total), "pct_new_90d": round(float(pct_new),2)}])
    except Exception as e:
        logging.warning("Detections no accesibles: %s", e)
        df_dets = pd.DataFrame()
        df_dets_status = df_dets_sev = df_dets_plat = df_dets_tactic = pd.DataFrame()
        df_detects_summary = pd.DataFrame([{"detects_90d":0,"pct_new_90d":0.0}])

    if not df_dets.empty:
        pivot_tactic = (df_dets.pivot_table(index="tactic", values="detection_id", aggfunc="nunique")
                         .reset_index().rename(columns={"detection_id":"detections"}))
        pivot_host   = (df_dets.pivot_table(index=["hostname","platform_name"], values="detection_id", aggfunc="nunique")
                         .reset_index().rename(columns={"detection_id":"detections"}))
    else:
        pivot_tactic = pd.DataFrame(columns=["tactic","detections"])
        pivot_host   = pd.DataFrame(columns=["hostname","platform_name","detections"])

    # -------- NG SIEM
    logging.info("Cargando NG SIEM / LogScale...")
    ng = fetch_ngsiem_metrics(CID, SEC, BASE, MCID)
    # Si el API directo de NG SIEM no está disponible, inferir desde Alerts XDR
    if not ng["available"] and not df_dets.empty:
        logging.info("API directa de NG SIEM no accesible — infiriendo desde Alerts XDR...")
        ng = infer_ngsiem_from_alerts(df_dets)
    if ng["available"]:
        mode = "inferido desde Alerts" if ng.get("inferred") else "directo"
        logging.info("NG SIEM (%s): %d conectores detectados", mode, len(ng["connectors"]))
    else:
        logging.info("NG SIEM: %s", ng.get("error","no disponible"))

    # -------- Export Excel
    logging.info("Generando Excel...")
    with pd.ExcelWriter(OUT_XLSX, engine="openpyxl") as w:
        df_summary.to_excel(w,         index=False, sheet_name="Client_Summary")
        df_hosts.to_excel(w,           index=False, sheet_name="Hosts")
        df_sensor_age_counts.to_excel(w, index=False, sheet_name="Sensor_Age")
        df_uninstall.to_excel(w,       index=False, sheet_name="Uninstall_Protection")
        df_count_prev.to_excel(w,      index=False, sheet_name="Count_Policy_Prevention")
        df_count_supd.to_excel(w,      index=False, sheet_name="Count_Policy_SensorUpd")
        df_count_fw.to_excel(w,        index=False, sheet_name="Count_Policy_Firewall")
        df_count_dctl.to_excel(w,      index=False, sheet_name="Count_Policy_DevCtrl")
        df_prev.to_excel(w,            index=False, sheet_name="Policy_Prevention_Settings")
        df_supd.to_excel(w,            index=False, sheet_name="Policy_SensorUpd_Settings")
        df_fw.to_excel(w,              index=False, sheet_name="Policy_Firewall_Settings")
        df_dctl.to_excel(w,            index=False, sheet_name="Policy_DeviceCtrl_Settings")
        df_agent_versions.to_excel(w,  index=False, sheet_name="Agent_Versions")
        df_os_versions.to_excel(w,     index=False, sheet_name="OS_Versions")
        df_detects_summary.to_excel(w, index=False, sheet_name="Detections_Summary")
        df_dets_status.to_excel(w,     index=False, sheet_name="Detections_Status")
        df_dets_sev.to_excel(w,        index=False, sheet_name="Detections_Severity")
        df_dets_plat.to_excel(w,       index=False, sheet_name="Detections_Platform")
        df_dets_tactic.to_excel(w,     index=False, sheet_name="Detections_Tactic")
        # Excel no soporta datetimes con timezone — strip tzinfo antes de exportar
        df_dets_xls = df_dets.copy()
        for col in df_dets_xls.select_dtypes(include=["datetimetz"]).columns:
            df_dets_xls[col] = df_dets_xls[col].dt.tz_localize(None)
        df_dets_xls.to_excel(w,        index=False, sheet_name="Detections_Detailed")
        pivot_tactic.to_excel(w,       index=False, sheet_name="Detections_By_Tactic")
        pivot_host.to_excel(w,         index=False, sheet_name="Detections_By_Host")
        # Health Score
        health_export = compute_health_score(df_hosts, df_prev, df_dets, df_sensor_age_counts, ng)
        pd.DataFrame([{
            "overall_score": health_export["overall"],
            **{f"score_{k}": v for k,v in health_export["breakdown"].items()},
            **{f"weight_{k}": v for k,v in health_export["weights"].items()},
        }]).to_excel(w, index=False, sheet_name="Health_Score")
        # NG SIEM sheets
        if ng["available"]:
            pd.DataFrame(ng["repos"]).to_excel(w, index=False, sheet_name="NGSIEM_Repos")
            pd.DataFrame(ng["views"]).to_excel(w, index=False, sheet_name="NGSIEM_Views")
            if not ng["daily_stats"].empty:
                ng["daily_stats"].to_excel(w, index=False, sheet_name="NGSIEM_DailyIngest")
            pd.DataFrame({"connector": ng["connectors"]}).to_excel(w, index=False, sheet_name="NGSIEM_Connectors")
    logging.info("Excel -> %s", OUT_XLSX)

    # -------- Export HTML
    logging.info("Generando HTML...")
    html = generate_html_report(
        client_name   = CLIENT_NAME or CID,
        cid           = CID,
        df_summary    = df_summary,
        df_hosts      = df_hosts,
        df_sensor_age_counts = df_sensor_age_counts,
        df_uninstall  = df_uninstall,
        df_count_prev = df_count_prev,
        df_count_supd = df_count_supd,
        df_count_fw   = df_count_fw,
        df_count_dctl = df_count_dctl,
        df_prev       = df_prev,
        df_supd       = df_supd,
        df_fw         = df_fw,
        df_dctl       = df_dctl,
        df_agent_versions  = df_agent_versions,
        df_os_versions     = df_os_versions,
        df_detects_summary = df_detects_summary,
        df_dets       = df_dets,
        df_dets_status = df_dets_status,
        df_dets_sev    = df_dets_sev,
        df_dets_plat   = df_dets_plat,
        df_dets_tactic = df_dets_tactic,
        pivot_tactic   = pivot_tactic,
        pivot_host     = pivot_host,
        ngsiem         = ng,
    )
    with open(OUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info("HTML  -> %s", OUT_HTML)

if __name__ == "__main__":
    main()
