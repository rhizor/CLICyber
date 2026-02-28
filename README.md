# cybercli 🛡️

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Tests-17%2F17-success-green.svg" alt="Tests">
</p>

> CLI de seguridad inspirada en CyberAgent para escaneos de red, threat intelligence, compliance ISO 27001 y más.

## 📖 Descripción

`cybercli` es una interfaz de línea de comandos interactiva diseñada para operaciones de seguridad. Permite a usuarios de diferentes niveles realizar escaneos de red, consultar fuentes de inteligencia de amenazas, generar reportes, verificar cumplimiento con ISO 27001, crear laboratorios CTF y aprovechar modelos de IA para resumir hallazgos y proponer pasos de remediación.

## ⚠️ Características de Seguridad

Este proyecto incluye código fortalecido para seguridad:
- **Bloqueo de Comandos Peligrosos**: Comandos como `rm -rf`, fork bombs, etc. son bloqueados en remediaciones
- **Verificación SSL/TLS**: Todas las peticiones HTTP verifican certificados SSL por defecto
- **Protección de Timeout**: Comandos se ejecutan con timeout de 30 segundos para evitar bloqueos
- **Log de Auditoría**: Todos los intentos de remediación son registrados

## 🚀 Instalación

### Requisitos Previos

- Python 3.8+
- pip
- Git

### Instalación con Entorno Virtual (Recomendado)

```bash
# Clonar repositorio
git clone https://github.com/rhizor/CLICyber.git
cd CLICyber

# Crear entorno virtual (recomendado)
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate  # Linux/macOS
# En Windows:
# venv\Scripts\activate

# Instalar en modo editable
pip install -e .

# O instalar solo dependencias
pip install -r requirements.txt
```

### Instalación Global

```bash
git clone https://github.com/rhizor/CLICyber.git
cd CLICyber
pip install -e .
```

> ⚠️ **Nota**: Se recomienda usar un entorno virtual (`venv`) para evitar conflictos con otras dependencias del sistema.

### Verificar Instalación

```bash
# Verificar que está instalado
cybercli --help

# O usar como módulo
python3 -m cybercli --help
```

## 📦 Características

### Escaneo y Redes
- **Escaneo de red**: Escaneos asíncronos de puertos sobre rangos IPv4 usando socket library de Python
- **Perfiles de escaneo**: Guardar y reusing perfiles de puertos personalizados
- **Programación**: Programar escaneos recurrentes usando expresiones cron

### Análisis de Seguridad
- **Escaneo de malware**: Calcular hashes SHA256 y comparar contra base de datos de hashes maliciosos
- **Hardening del sistema**: Verificar configuraciones de seguridad (SSH, passwords, firewall)
- **Análisis Blue Team**: Evaluar vulnerabilidades basadas en puertos abiertos y análisis de logs
- **Análisis de autenticación**: Detectar logins fuera de horario normal

### Threat Intelligence
- **CVE Monitoring**: Consultar bases de datos NVD y CIRCL
- **Threat Intel**: Consultar Shodan, AbuseIPDB, VirusTotal (requiere API keys)
- **Caza de amenazas**: Detectar anomalías en datos históricos de escaneos

### Compliance y Reportes
- **ISO 27001**: Verificar implementación de controles de ISO 27001:2022
- **Reportes**: Generar reportes técnicos, ejecutivos o de compliance en PDF, HTML o JSON
- **Export**: Exportar historial a JSON para integración con SIEM

### Contenedores e Integridad
- **Seguridad de Contenedores**: Escanear Docker y Kubernetes
- **File Integrity Monitoring (FIM)**: Monitorear cambios en archivos

### SIEM y API
- **Integración SIEM**: Enviar eventos a Splunk, ELK, Syslog
- **REST API**: Servidor FastAPI para acceso programático

### Labs y Educación
- **Laboratorios CTF**: Crear entornos de práctica CTF
- **Red Team**: Simular explotación segura de labs
- **Self-Learning**: Análisis de historial para identificar patrones

## 💻 Uso

### Comandos Básicos

```bash
# Ayuda general
python3 -m cybercli --help

# Escaneo de red
python3 -m cybercli scan network 10.0.0.0/24 --top-ports 50

# Perfiles de escaneo
python3 -m cybercli scan save-profile web --ports 80,443 --description "Web services"
python3 -m cybercli scan run-profile web 10.0.0.0/24

# Programar escaneos
python3 -m cybercli schedule add weekly-scan 10.0.0.0/24 --cron "0 0 * * 0" --profile web
```

### Blue/Red Team

```bash
# Escaneo de hardening
python3 -m cybercli scan hardening

# Análisis de vulnerabilidades
python3 -m cybercli blue vuln-scan

# Análisis de logs
python3 -m cybercli blue log-analysis /var/log/auth.log

# Análisis de autenticación
python3 -m cybercli blue auth-analysis /var/log/auth.log --start-hour 0 --end-hour 6

# Explotar lab CTF
python3 -m cybercli red exploit-lab mylab
```

### Threat Intelligence

```bash
# Buscar CVE específico
python3 -m cybercli.cli cve search CVE-2024-1234 --detailed

# CVEs recientes
python3 -m cybercli.cli cve recent --days 7 --limit 10

# CVEs por producto
python3 -m cybercli.cli cve product nginx --vendor apache
```

### Contenedores

```bash
# Escanear Docker
python3 -m cybercli.cli container docker

# Escanear Kubernetes
python3 -m cybercli.cli container kubernetes
```

### File Integrity

```bash
# Crear baseline
python3 -m cybercli.cli fim create-baseline /etc --recursive

# Verificar integridad
python3 -m cybercli.cli fim check

# Monitoreo continuo
python3 -m cybercli.cli fim monitor /var/www --interval 30
```

### SIEM

```bash
# Enviar a Splunk
python3 -m cybercli.cli siem send splunk "Test alert" --host splunk.example.com

# Probar conexión ELK
python3 -m cybercli.cli siem test elk --host elk.example.com:9200
```

### API REST

```bash
# Iniciar servidor API
python3 -m cybercli.cli api --host 0.0.0.0 --port 8000
```

## ⚙️ Variables de Entorno

| Variable | Descripción |
|----------|-------------|
| `CYBERCLI_AI_API_KEY` | API key para funciones de IA (Gemini, OpenAI) |
| `SHODAN_API_KEY` | API de Shodan para threat intelligence |
| `ABUSEIPDB_API_KEY` | AbuseIPDB para reputación de IPs |
| `VIRUSTOTAL_API_KEY` | VirusTotal para escaneo de malware |
| `NVD_API_KEY` | API del National Vulnerability Database |
| `SPLUNK_HEC_TOKEN` | Token de Splunk HEC |
| `SPLUNK_USERNAME` | Usuario de Splunk |
| `SPLUNK_PASSWORD` | Password de Splunk |
| `ELASTIC_HOST` | Host de Elasticsearch (default: localhost:9200) |
| `ELASTIC_API_KEY` | API key de Elasticsearch |
| `SMTP_SERVER` | Servidor SMTP para emails |
| `SMTP_PORT` | Puerto SMTP (default: 587) |
| `SMTP_USER` | Usuario SMTP |
| `SMTP_PASSWORD` | Password SMTP |
| `SLACK_WEBHOOK_URL` | Webhook de Slack para alertas |
| `TELEGRAM_TOKEN` | Token del bot de Telegram |
| `TELEGRAM_CHAT_ID` | Chat ID de Telegram |

## 🧪 Testing

```bash
# Ejecutar todos los tests
pytest

# Ejecutar con coverage
pytest --cov=cybercli

# Ejecutar tests específicos
pytest tests/test_cli.py -v
```

## 📁 Estructura del Proyecto

```
CLICyber/
├── cybercli/
│   ├── __init__.py
│   ├── cli.py              # CLI principal
│   ├── api.py              # Servidor REST API
│   └── engines/            # Módulos de funcionalidad
│       ├── network_scanner.py
│       ├── malware_scanner.py
│       ├── hardening_checker.py
│       ├── threat_intel.py
│       ├── cve_monitor.py
│       ├── container_security.py
│       ├── file_integrity.py
│       ├── siem_integration.py
│       └── ...
├── tests/                  # Tests unitarios
├── docs/                   # Documentación
│   ├── INSTALL.md          # Guía de instalación
│   ├── USAGE.md           # Guía de uso
│   └── API.md             # Documentación REST API
├── pyproject.toml
└── README.md
```

## 📚 Documentación

Consulta la documentación detallada en la carpeta `docs/`:

- **[INSTALL.md](docs/INSTALL.md)** - Guía completa de instalación
- **[USAGE.md](docs/USAGE.md)** - Guía detallada de uso con ejemplos  
- **[API.md](docs/API.md)** - Documentación de la REST API

## 🤝 Contribuir

1. Fork el proyecto
2. Crear una rama (`git checkout -b feature/nueva-caracteristica`)
3. Commitear cambios (`git commit -am 'Agregar nueva característica'`)
4. Pushear (`git push origin feature/nueva-caracteristica`)
5. Crear Pull Request

## 📜 Licencia

MIT License - ver LICENSE para detalles.

---

<p align="center">
  <i>"La herramienta perfecta para el keamanan profesional"</i>
</p>
