#!/usr/bin/env bash
set -e

echo -e "\033[0;36m=======================================================\033[0m"
echo -e "\033[1;36m🛡️  Enterprise bunyanx NGFW Linux Setup Booster 🛡️\033[0m"
echo -e "\033[0;36m=======================================================\033[0m"

# 1. Verify Python
if ! command -v python3 &> /dev/null; then
    echo -e "\033[0;31m[ERROR] Python3 is not installed! Please install Python 3.9+.\033[0m"
    exit 1
fi

# 2. Install native compilation libraries
echo -e "\033[1;33m[+] Installing system libraries (requires root/sudo)...\033[0m"
if command -v apt-get &> /dev/null; then
    sudo apt-get update -y || true
    sudo apt-get install -y build-essential python3-dev python3-pip python3-venv \
        libssl-dev libffi-dev libpcap-dev wireguard-tools nftables \
        bpfcc-tools libbpfcc libbpfcc-dev python3-bpfcc linux-headers-$(uname -r) \
        clang llvm libelf-dev iproute2 ethtool || true
elif command -v yum &> /dev/null; then

    sudo yum install -y gcc python3-devel libpcap-devel wireguard-tools || true
fi

# 3. Create Virtual Environment
if [ ! -d "venv" ]; then
    echo -e "\033[1;33m[+] Creating virtual environment...\033[0m"
    python3 -m venv venv
else
    echo -e "\033[0;32m[OK] Virtual environment already exists.\033[0m"
fi

# 4. Activate and Install dependencies
echo -e "\033[1;33m[+] Installing/Upgrading packages in virtual environment...\033[0m"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-production.txt

# 5. Generate Secure .env configuration
echo -e "\033[1;33m[+] Setting up environment secrets...\033[0m"
if [ ! -f ".env" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    ADMIN_PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    OP_PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    CA_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
    HA_SYNC=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    cat <<EOF > .env
bunyanx_SECRET_KEY=$SECRET_KEY
bunyanx_ADMIN_PASSWORD=$ADMIN_PW
bunyanx_OPERATOR_PASSWORD=$OP_PW
CA_KEY_PASSPHRASE=$CA_PASS
bunyanx_ENV=production
bunyanx_DATA_DIR=data
bunyanx_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:8000
NGFW_SECRET_KEY=$SECRET_KEY
NGFW_ADMIN_PASSWORD=$ADMIN_PW
NGFW_OPERATOR_PASSWORD=$OP_PW
NGFW_HA_SYNC_SECRET=$HA_SYNC
NGFW_CA_KEY_PASSWORD=$CA_PASS
NGFW_ENV=production
NGFW_DATA_DIR=data
EOF
    echo -e "\033[0;32m[OK] Secure .env file generated.\033[0m"
else
    echo -e "\033[0;32m[OK] .env file already exists.\033[0m"
fi

echo "[+] Applying sysctl network optimizations..."
sudo cp system/config/sysctl-optimization.conf /etc/sysctl.d/99-bunyanx-optimization.conf || true
sudo sysctl --system || true 
# 6. Initialize CA Certs
echo -e "\033[1;33m[+] Initializing Cryptographic Certificates...\033[0m"
python3 main.py --init-ca

echo -e "\033[0;36m=======================================================\033[0m"
echo -e "\033[0;32m[SUCCESS] bunyanx NGFW successfully configured!\033[0m"
echo -e "To run the NGFW server, execute:"
echo -e "  \033[1;33msource venv/bin/activate && python3 main.py\033[0m"
echo -e "\033[0;36m=======================================================\033[0m"
