# CyberCLI 🛡️

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

> CLI de seguridad simplificada para operaciones de escaneo y hardening.

## 📖 Descripción

**CyberCLI** es una herramienta de línea de comandos simplificada para operaciones de seguridad. Enfocada en funcionalidad real: escaneo de red, verificación de hardening y compliance ISO 27001.

## ⚡ Características

- **Escaneo de Red**: Escaneo asíncrono de puertos TCP
- **Hardening**: Verificación de configuración de seguridad del sistema
- **Compliance**: Evaluación interactiva de ISO 27001
- **API REST**: Servidor FastAPI para integración
- **Historial**: Guarda historial de escaneos

## 🚀 Instalación

```bash
# Clonar repositorio
git clone https://github.com/rhizor/CLICyber.git
cd CLICyber

# Instalar dependencias
pip install typer requests fastapi uvicorn

# Ejecutar
PYTHONPATH=/home/ubuntu/.openclaw/workspace/clicyber python3 -m cybercli.cli --help
```

## 📦 Uso

### Escaneo de Red

```bash
# Escanear por categoría
python3 -m cybercli.cli scan network 192.168.1.1 --category web      # Puertos web
python3 -m cybercli.cli scan network 192.168.1.1 --category db         # Bases de datos
python3 -m cybercli.cli scan network 192.168.1.1 --category mail        # Correo
python3 -m cybercli.cli scan network 192.168.1.1 --category remote     # Acceso remoto
python3 -m cybercli.cli scan network 192.168.1.1 --category file      # Archivos
python3 -m cybercli.cli scan network 192.168.1.1 --category dns        # DNS
python3 -m cybercli.cli scan network 192.168.1.1 --category all        # Todos

# Escanear puertos comunes (default)
python3 -m cybercli.cli scan network 192.168.1.1

# Escanear top N puertos
python3 -m cybercli.cli scan network 192.168.1.1 --top-ports 20
```

### Categorías disponibles

| Categoría | Puertos |
|-----------|---------|
| `web` | 80, 443, 8080, 8443, 3000, 5000, 8000, 9000... |
| `db` | 3306, 5432, 27017, 6379, 1433, 1521, 9200... |
| `mail` | 25, 110, 143, 465, 587, 993, 995... |
| `remote` | 22, 23, 3389, 5900, 2222, 22222... |
| `file` | 20, 21, 69, 115, 139, 445, 2049... |
| `dns` | 53, 853, 5353, 5060, 5061... |
| `all` | Todos los anteriores (~63 puertos) |

### Hardening

```bash
# Verificar hardening del sistema
python3 -m cybercliSimplified.cli hardening
```

### Compliance ISO 27001

```bash
# Modo interactivo
python3 -m cybercliSimplified.cli compliance
```

### Perfiles de Escaneo

```bash
# Guardar perfil
python3 -m cybercliSimplified.cli scan save-profile web --ports 80,443,8080

# Listar perfiles
python3 -m cybercliSimplified.cli scan list-profiles

# Ejecutar perfil
python3 -m cybercliSimplified.cli scan run-profile web 192.168.1.1
```

### API REST

```bash
# Iniciar servidor
python3 -m cybercliSimplified.cli api --port 8000

# Documentación en http://localhost:8000/docs
```

### Estadísticas

```bash
# Ver historial de escaneos
python3 -m cybercliSimplified.cli stats
```

## 📁 Estructura

```
CLICyber/
├── cybercli/
│   ├── engines/           # Módulos de escaneo
│   │   ├── network_scanner.py
│   │   ├── hardening_checker.py
│   │   └── ...
│   ├── api.py            # Servidor API
│   └── cli.py            # CLI principal
├── cybercliSimplified/   # Versión simplificada
│   └── cli.py           # CLI simplificada
└── README.md
```

## 🧪 Comandos Disponibles

| Comando | Descripción |
|---------|-------------|
| `scan network` | Escaneo de puertos |
| `scan save-profile` | Guardar perfil |
| `scan list-profiles` | Listar perfiles |
| `scan run-profile` | Ejecutar perfil |
| `hardening` | Verificar hardening |
| `compliance` | Evaluación ISO 27001 |
| `api` | Iniciar servidor REST |
| `stats` | Ver estadísticas |

## 🤝 Contribuir

1. Fork el proyecto
2. Crear rama (`git checkout -b feature/nueva-caracteristica`)
3. Commitear cambios
4. Pushear y crear Pull Request

## 📜 Licencia

MIT License
