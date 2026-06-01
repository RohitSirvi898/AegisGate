#!/bin/bash

# ==============================================================================
# AegisGate VPS Infrastructure Provisioning Script
# Target OS: Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS
# Purpose: Installs Docker Engine, Docker Compose, maps firewalls, and prepares
#          the system to run the AegisGate production microservices stack.
# ==============================================================================

# Exit immediately if any command exits with a non-zero status
set -e

# Output Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}      AegisGate VPS Production Setup & Deployment      ${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e ""

# Step 1: Update standard Ubuntu apt packages
echo -e "${YELLOW}[1/4] Updating Ubuntu Package Index...${NC}"
sudo apt-get update -y
sudo apt-get upgrade -y
echo -e "${GREEN}✓ Package index updated successfully.${NC}\n"

# Step 2: Install Docker Engine and Docker Compose securely
echo -e "${YELLOW}[2/4] Installing Prerequisites & Docker Stack...${NC}"

# Install necessary helper packages
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key securely
sudo mkdir -p /etc/apt/keyrings
if [ -f /etc/apt/keyrings/docker.gpg ]; then
    sudo rm -f /etc/apt/keyrings/docker.gpg
fi
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Set up the stable repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update apt-get index and install Docker engine components
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Ensure docker service starts on boot and runs
sudo systemctl enable docker
sudo systemctl start docker

# Install standalone docker-compose binary compatibility if requested
# Many environments expect 'docker-compose' command format.
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}Installing docker-compose standalone compatibility binary...${NC}"
    sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

echo -e "${GREEN}✓ Docker Engine and Docker Compose installed and verified successfully.${NC}"
echo -e "   Docker Version: $(docker --version)"
echo -e "   Docker Compose Version: $(docker-compose --version || docker compose version)"
echo -e ""

# Step 3: Firewall & Port mapping documentation blocks
echo -e "${BLUE}======================================================${NC}"
echo -e "${YELLOW}[3/4] PORT MAPPING & FIREWALL RULES CONFIGURATION     ${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "To secure the multi-service network, make sure to apply the following firewall rules:"
echo -e ""
echo -e "  ${GREEN}┌────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${GREEN}│ REQUIRED OPEN PORTS (Public Access Allowed)            │${NC}"
echo -e "  ${GREEN}├────────────────────────────────────────────────────────┤${NC}"
echo -e "  ${GREEN}│ [TCP] Port 8080 -> Public Ingress Proxy (gateway_core) │${NC}"
echo -e "  ${GREEN}│   (Exposed for External Dashboards, Vercel & Clients)   │${NC}"
echo -e "  ${GREEN}└────────────────────────────────────────────────────────┘${NC}"
echo -e ""
echo -e "  ${RED}┌────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${RED}│ RESTRICTED INTERNAL-ONLY PORTS (Must Stay Closed)      │${NC}"
echo -e "  ${RED}├────────────────────────────────────────────────────────┤${NC}"
echo -e "  ${RED}│  • Port 8000 (FastAPI Engine)                          │${NC}"
echo -e "  ${RED}│  • Port 5672 (RabbitMQ Queue)                          │${NC}"
echo -e "  ${RED}│  • Port 6379 (Redis Cache)                             │${NC}"
echo -e "  ${RED}│                                                        │${NC}"
echo -e "  ${RED}│ Note: These ports are securely isolated and run        │${NC}"
echo -e "  ${RED}│ internally within the Docker bridge network mesh       │${NC}"
echo -e "  ${RED}│ (aegis_mesh) and MUST NOT be exposed to the internet.  │${NC}"
echo -e "  ${RED}└────────────────────────────────────────────────────────┘${NC}"
echo -e ""
echo -e "  To enforce this on Ubuntu using UFW (Uncomplicated Firewall):"
echo -e "    sudo ufw default deny incoming"
echo -e "    sudo ufw default allow outgoing"
echo -e "    sudo ufw allow 22/tcp comment 'SSH'"
echo -e "    sudo ufw allow 8080/tcp comment 'AegisGate Public Gateway Ingress'"
echo -e "    sudo ufw --force enable"
echo -e ""

# Step 4: Boot sequence documentation
echo -e "${BLUE}======================================================${NC}"
echo -e "${YELLOW}[4/4] REPOSITORY CLONING & STACK BOOT SEQUENCE        ${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "To pull your repository and spin up your high-performance containerized system, run:"
echo -e ""
echo -e "  ${GREEN}# 1. Clone your AegisGate repository (if not already done)${NC}"
echo -e "  git clone <YOUR_REPOSITORY_URL> aegis-gate"
echo -e "  cd aegis-gate"
echo -e ""
echo -e "  ${GREEN}# 2. Configure your production environment secrets${NC}"
echo -e "  # Edit/create your production .env file inside root context:"
echo -e "  # echo \"MONGO_URI=mongodb+srv://...\" > .env"
echo -e "  # echo \"LLM_API_KEY=your-api-key\" >> .env"
echo -e ""
echo -e "  ${GREEN}# 3. Boot the production stack in detached daemon mode${NC}"
echo -e "  ${GREEN}docker-compose -f docker-compose.prod.yml up -d --build${NC}"
echo -e ""
echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}AegisGate VPS provisioning automation configured successfully!${NC}"
echo -e "${BLUE}======================================================${NC}"
