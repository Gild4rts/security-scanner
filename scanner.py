import os
import re
import json
import requests
from datetime import datetime

# ---------------------------------------------------------
# 1. EXPRESIONES REGULARES PARA DETECTAR SECRETOS
# ---------------------------------------------------------
PATRONES_SECRETOS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "OpenAI API Key": r"sk-[a-zA-Z0-9]{32,48}",
    "Google API Key": r"AIzaSy[a-zA-Z0-9_-]{35}",
    "Private Key (SSH/RSA)": r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----",
    "Generic Secret / Token": r"(?i)(api_key|secret|password|token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{8,})['\"]"
}

# Carpetas y archivos que ignoraremos para evitar falsos positivos
IGNORAR = {".git", "__pycache__", "venv", ".venv", "node_modules", ".vscode", "reporte_seguridad.html"}

def escanear_secretos(directorio="."):
    """Recorre las carpetas y busca patrones de claves/secretos en archivos de texto."""
    hallazgos = []
    print("\n🔍 Buscando secretos expuestos en los archivos...")

    for root, dirs, files in os.walk(directorio):
        # Filtrar carpetas ignoradas
        dirs[:] = [d for d in dirs if d not in IGNORAR]

        for file in files:
            if file in IGNORAR:
                continue
            ruta_archivo = os.path.join(root, file)
            try:
                with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
                    for num_linea, linea in enumerate(f, 1):
                        for nombre_secret, patron in PATRONES_SECRETOS.items():
                            if re.search(patron, linea):
                                hallazgos.append({
                                    "archivo": ruta_archivo,
                                    "linea": num_linea,
                                    "tipo": nombre_secret
                                })
            except Exception:
                pass  # Ignorar archivos binarios que no se puedan leer

    return hallazgos

# ---------------------------------------------------------
# 2. AUDITORÍA DE DEPENDENCIAS (API OSV - Google)
# ---------------------------------------------------------
def auditar_dependencias(archivo_req="requirements.txt"):
    """Lee el requirements.txt y consulta la API de OSV para ver vulnerabilidades conocidas."""
    vulnerabilidades = []
    
    if not os.path.exists(archivo_req):
        print(f"\n⚠️  No se encontró el archivo '{archivo_req}'. Se omitirá el escaneo de dependencias.")
        return vulnerabilidades

    print(f"\n📦 Auditando dependencias en '{archivo_req}'...")

    with open(archivo_req, "r") as f:
        lineas = f.readlines()

    for linea in lineas:
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue

        if "==" in linea:
            paquete, version = linea.split("==")[:2]
            
            payload = {
                "version": version.strip(),
                "package": {
                    "name": paquete.strip(),
                    "ecosystem": "PyPI"
                }
            }
            
            try:
                response = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if "vulns" in data:
                        num_vulns = len(data["vulns"])
                        vulnerabilidades.append({
                            "paquete": paquete,
                            "version": version,
                            "total_cves": num_vulns,
                            "detalles": [v["id"] for v in data["vulns"][:3]]
                        })
            except Exception as e:
                print(f"⚠️ Error al consultar OSV para {paquete}: {e}")

    return vulnerabilidades

# ---------------------------------------------------------
# 3. GENERADOR DE REPORTE VISUAL HTML
# ---------------------------------------------------------
def generar_reporte_html(secretos, vulnerabilidades, output_file="reporte_seguridad.html"):
    """Genera un reporte visual profesional e interactivo en formato HTML."""
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_secretos = len(secretos)
    total_vulns = len(vulnerabilidades)
    
    # Determinar estado de seguridad
    if total_secretos == 0 and total_vulns == 0:
        status_badge = '<span class="status-badge status-success">✅ SEGURO</span>'
        status_desc = "No se detectaron secretos ni vulnerabilidades conocidas en el proyecto."
    else:
        status_badge = '<span class="status-badge status-danger">⚠️ RIESGO DETECTADO</span>'
        status_desc = "Se han identificado hallazgos de seguridad que requieren atención inmediata."

    # Renderizar filas de secretos
    if secretos:
        rows_secretos = "".join([
            f"""<tr>
                <td><span class="badge badge-warning">{s['tipo']}</span></td>
                <td><code>{s['archivo']}</code></td>
                <td><strong>Línea {s['linea']}</strong></td>
            </tr>""" for s in secretos
        ])
    else:
        rows_secretos = '<tr><td colspan="3" class="empty-state">✅ No se detectaron secretos ni claves de API expuestas.</td></tr>'

    # Renderizar filas de vulnerabilidades
    if vulnerabilidades:
        rows_vulns = "".join([
            f"""<tr>
                <td><strong>{v['paquete']}</strong></td>
                <td><code>{v['version']}</code></td>
                <td><span class="badge badge-danger">{v['total_cves']} CVEs</span></td>
                <td>{" ".join([f'<span class="cve-pill">{cve}</span>' for cve in v['detalles']])}</td>
            </tr>""" for v in vulnerabilidades
        ])
    else:
        rows_vulns = '<tr><td colspan="4" class="empty-state">✅ Todas las dependencias analizadas están libres de vulnerabilidades conocidas.</td></tr>'

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Auditoría de Seguridad</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.15);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.15);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.15);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }}
        body {{ background-color: var(--bg-color); color: var(--text-main); padding: 40px 20px; line-height: 1.6; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}

        header {{
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 2px solid var(--border-color); padding-bottom: 20px; margin-bottom: 30px;
        }}
        .title-group h1 {{ font-size: 1.8rem; display: flex; align-items: center; gap: 10px; }}
        .title-group p {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 5px; }}

        .status-badge {{ padding: 8px 16px; border-radius: 20px; font-weight: bold; font-size: 0.85rem; }}
        .status-danger {{ background-color: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }}
        .status-success {{ background-color: var(--success-bg); color: var(--success); border: 1px solid var(--success); }}

        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 35px; }}
        .metric-card {{ background: var(--card-bg); border: 1px solid var(--border-color); padding: 20px; border-radius: 12px; }}
        .metric-card h3 {{ font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; }}
        .metric-value {{ font-size: 2.2rem; font-weight: bold; }}
        .metric-value.danger {{ color: var(--danger); }}
        .metric-value.warning {{ color: var(--warning); }}
        .metric-value.success {{ color: var(--success); }}

        .section-card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; margin-bottom: 30px; }}
        .section-header {{ margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; }}
        .section-header h2 {{ font-size: 1.25rem; font-weight: 600; }}

        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border-color); font-size: 0.95rem; }}
        th {{ background-color: rgba(255, 255, 255, 0.03); color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }}
        
        code {{ background-color: rgba(255, 255, 255, 0.08); padding: 3px 8px; border-radius: 4px; font-family: monospace; color: var(--accent-blue); }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; inline-block; }}
        .badge-warning {{ background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning); }}
        .badge-danger {{ background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }}
        .cve-pill {{ background-color: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-color); color: var(--text-muted); padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin-right: 4px; }}
        .empty-state {{ text-align: center; color: var(--success); padding: 20px !important; font-weight: 500; }}
        footer {{ text-align: center; margin-top: 40px; color: var(--text-muted); font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="title-group">
                <h1>🛡️ Security Scanner Report</h1>
                <p>Fecha de escaneo: {fecha} | Proyecto: <code>{os.path.basename(os.getcwd())}</code></p>
            </div>
            <div>{status_badge}</div>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Secretos Expuestos</h3>
                <div class="metric-value {'danger' if total_secretos > 0 else 'success'}">{total_secretos}</div>
            </div>
            <div class="metric-card">
                <h3>Dependencias Vulnerables</h3>
                <div class="metric-value {'warning' if total_vulns > 0 else 'success'}">{total_vulns}</div>
            </div>
            <div class="metric-card">
                <h3>Diagnóstico</h3>
                <p style="margin-top: 10px; font-size: 0.88rem; color: var(--text-muted);">{status_desc}</p>
            </div>
        </div>

        <div class="section-card">
            <div class="section-header"><h2>🔑 Secretos y Claves Detectadas</h2></div>
            <table>
                <thead>
                    <tr><th>Tipo de Secreto</th><th>Archivo</th><th>Ubicación</th></tr>
                </thead>
                <tbody>{rows_secretos}</tbody>
            </table>
        </div>

        <div class="section-card">
            <div class="section-header"><h2>📦 Auditoría de Dependencias (PyPI / OSV)</h2></div>
            <table>
                <thead>
                    <tr><th>Paquete</th><th>Versión Usada</th><th>Total CVEs</th><th>IDs Principales</th></tr>
                </thead>
                <tbody>{rows_vulns}</tbody>
            </table>
        </div>

        <footer>Generado con <strong>Python Security Scanner CLI</strong></footer>
    </div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n✨ ¡Reporte HTML generado exitosamente en: {os.path.abspath(output_file)}")

# ---------------------------------------------------------
# 4. REPORTE EN CONSOLA Y EJECUCIÓN
# ---------------------------------------------------------
def generar_reporte(secretos, vulnerabilidades):
    """Muestra el reporte estructurado en consola."""
    print("\n" + "="*50)
    print("         📋 REPORTE DE SEGURIDAD DEL PROYECTO       ")
    print("="*50)

    print(f"\n🔑 SECRETOS ENCONTRADOS: {len(secretos)}")
    if secretos:
        for s in secretos:
            print(f"  ❌ [{s['tipo']}] en {s['archivo']} (Línea {s['linea']})")
    else:
        print("  ✅ No se encontraron secretos expuestos.")

    print(f"\n🛡️ DEPENDENCIAS VULNERABLES: {len(vulnerabilidades)}")
    if vulnerabilidades:
        for v in vulnerabilidades:
            cves = ", ".join(v['detalles'])
            print(f"  ⚠️  {v['paquete']} v{v['version']} -> {v['total_cves']} vulnerabilidades detectadas ({cves})")
    else:
        print("  ✅ Todas las dependencias escaneadas están libres de vulnerabilidades conocidas.")

    print("\n" + "="*50)

if __name__ == "__main__":
    secretos_hallados = escanear_secretos(".")
    vulns_halladas = auditar_dependencias("requirements.txt")
    
    # Reporte en consola
    generar_reporte(secretos_hallados, vulns_halladas)
    
    # Generar el archivo HTML automáticamente
    generar_reporte_html(secretos_hallados, vulns_halladas, "reporte_seguridad.html")