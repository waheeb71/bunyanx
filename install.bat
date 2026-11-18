@echo off
echo =======================================================
echo 🛡️  Enterprise bunyanx NGFW Windows Setup Booster 🛡️
echo =======================================================

:: 1. Verify Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH! Please install Python 3.9+.
    exit /b 1
)

:: 2. Create Virtual Environment
if not exist venv (
    echo [+] Creating virtual environment...
    python -m venv venv
) else (
    echo [OK] Virtual environment already exists.
)

:: 3. Activate and Install dependencies
echo [+] Installing/Upgrading packages in virtual environment...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements-production.txt

:: 4. Generate Secure .env configuration
echo [+] Setting up environment secrets...
python -c "import os, secrets; env = '.env'; exists = os.path.exists(env); print('Generating secure .env...') if not exists else print('.env already exists.'); f = open(env, 'w') if not exists else None; sk = secrets.token_hex(64); ap = secrets.token_urlsafe(24); op = secrets.token_urlsafe(24); cp = secrets.token_urlsafe(24); hs = secrets.token_hex(32); f.write(f'BunyanX_SECRET_KEY={sk}\nBunyanX_ADMIN_PASSWORD={ap}\nBunyanX_OPERATOR_PASSWORD={op}\nCA_KEY_PASSPHRASE={cp}\nBunyanX_ENV=production\nBunyanX_DATA_DIR=data\nBunyanX_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:8000\nNGFW_SECRET_KEY={sk}\nNGFW_ADMIN_PASSWORD={ap}\nNGFW_OPERATOR_PASSWORD={op}\nNGFW_HA_SYNC_SECRET={hs}\nNGFW_CA_KEY_PASSWORD={cp}\nNGFW_ENV=production\nNGFW_DATA_DIR=data\n') if f else None; f.close() if f else None"

:: 5. Initialize CA Certs
echo [+] Initializing Cryptographic Certificates...
python main.py --init-ca

echo =======================================================
echo [SUCCESS] bunyanx NGFW successfully configured!
echo To run the NGFW server, execute:
echo   venv\Scripts\python main.py
echo =======================================================
