# CLI Cyber - Guía de Instalación

## Requisitos del Sistema

### Requisitos Mínimos
- Python 3.8+
- pip
- Git

### Requisitos Recomendados
- Python 3.10+
- 4GB RAM
- Conexión a internet (para APIs de threat intel)

## Instalación

### Método 1: Entorno Virtual (Recomendado)

```bash
# Clonar repositorio
git clone https://github.com/rhizor/CLICyber.git
cd CLICyber

# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate

# Instalar en modo editable
pip install -e .

# Verificar instalación
python3 -m cybercli --help
```

### Método 2: Instalación Global

```bash
git clone https://github.com/rhizor/CLICyber.git
cd CLICyber
pip install -e .
```

## Verificación de Instalación

```bash
# Ver ayuda
python3 -m cybercli --help

# Ver versión
python3 -m cybercli --version

# Ejecutar test básico
python3 -m pytest tests/ -v
```

## Configuración Inicial

### 1. Configurar API Keys (Opcional)

```bash
# Exportar variables de entorno
export CYBERCLI_AI_API_KEY="tu-api-key"
export SHODAN_API_KEY="tu-shodan-key"
export ABUSEIPDB_API_KEY="tu-abuseipdb-key"

# O agregar al ~/.bashrc
echo 'export CYBERCLI_AI_API_KEY="tu-key"' >> ~/.bashrc
source ~/.bashrc
```

### 2. Verificar Configuración

```bash
# Ver configuración actual
python3 -m cybercli config status
```

## Estructura de Archivos

```
~/.cybercli/
├── profiles.json      # Perfiles de escaneo
├── schedules.json    # Escaneos programados
├── history.json     # Historial de escaneos
├── labs/            # Laboratorios CTF
└── fim_baseline.json  # Baseline de integridad
```

## Solución de Problemas

### Error: "No module named cybercli"

```bash
# Asegúrate de estar en el directorio correcto
cd CLICyber

# O instala globalmente
pip install -e .
```

### Error: Permisos denegados

```bash
# Usa --user si no tienes permisos de admin
pip install -e . --user
```

### Error: ModuleNotFoundError

```bash
# Activa el entorno virtual
source venv/bin/activate

# O agrega al PYTHONPATH
export PYTHONPATH="$(pwd):$PYTHONPATH"
```

## Actualización

```bash
# Pull latest changes
git pull origin main

# Reinstalar
pip install -e .
```

## Desinstalación

```bash
# Desactivar entorno virtual
deactivate

# Eliminar carpeta
rm -rf CLICyber

# O si fue instalado globalmente
pip uninstall cybercli
```
