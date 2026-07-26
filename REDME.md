# 🛡️ Python Security Scanner

Una herramienta ligera de CLI para escanear repositorios en busca de **secretos expuestos** (API Keys, Token AWS, SSH) y **vulnerabilidades en dependencias** conectada a la API de OSV (Google).

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## 🚀 Características

* 🔑 **Detección de Secretos:** Escanea de forma recursiva patrones de claves de AWS, OpenAI, Google API, RSA y Tokens genéricos.
* 📦 **Auditoría de Dependencias:** Consulta la base de datos de [OSV.dev](https://osv.dev/) para identificar CVEs asociadas a paquetes en `requirements.txt`.
* 📊 **Reporte HTML Visual:** Genera un dashboard automático en **Dark Mode** listo para ser exportado.

## ⚙️ Instalación y Uso

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/TU_USUARIO/security-scanner.git](https://github.com/TU_USUARIO/security-scanner.git)
   cd security-scanner