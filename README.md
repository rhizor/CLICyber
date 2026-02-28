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
PYTHONPATH=/home/ubuntu/.openclaw/workspace/clicyber python3 -m cybercliSimplified.cli --help
```

## 📦 Uso

### Escaneo de Red

```bash
# Escanear puertos comunes
python3 -m cybercliSimplified.cli scan network 192.168.1.1

# Escanear top 20 puertos
python3 -m cybercliSimplified.cli scan network 192.168.1.1 --top-ports 20

# Escanear red completa
python3 -m cybercliSimplified.cli scan network 192.168.1.0/24 --top-ports 10
```

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
