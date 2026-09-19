# Aegis Enterprise - Complete Deployment Guide

This guide covers local development setup and production deployment on DigitalOcean.

---

## 📋 Prerequisites

- **Node.js** v20+ installed
- **Python** 3.10+ installed
- **Git** installed
- **PostgreSQL 15+**
- **Redis 7+**
- **PM2** (`npm install -g pm2`) for production process management

---

## 🚀 QUICK START - LOCAL DEVELOPMENT

```bash
# 1. Clone and navigate to project
git clone <your-repo-url> aegis
cd aegis

# 2. Copy environment file
cp .env.example .env

# 3. Edit .env file with your credentials:
#    DATABASE_URL=postgresql://aegis:password@localhost:5432/aegis_enterprise?schema=public
#    REDIS_URL=redis://localhost:6379
#    JWT_SECRET=your_jwt_secret_min_32_chars
#    GEMINI_API_KEY=your_google_gemini_api_key

# 4. Install dependencies
npm install
pip3 install -r requirements.txt

# 5. Run database migrations
npx prisma migrate deploy
npx prisma generate

# 6. Start development server
npm run dev
# Frontend + Backend API runs at: http://localhost:3000
```

### Option 2: Native Installation (Windows)

```bash
# 1. Install PostgreSQL 15
# Download from: https://www.postgresql.org/download/windows/
# During install, remember the password you set for 'postgres' user

# 2. Install Redis
# Download from: https://github.com/microsoftarchive/redis/releases
# Or use WSL: sudo apt install redis-server

# 3. Install Node.js dependencies
npm install

# 4. Copy and configure environment
copy .env.example .env
# Edit .env with your values

# 5. Create PostgreSQL database
psql -U postgres
CREATE DATABASE aegis_enterprise;
CREATE USER aegis WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE aegis_enterprise TO aegis;
\q

# 6. Run migrations
npx prisma migrate deploy
npx prisma generate

# 7. Start development server
npm run dev

# 8. Access application
# Frontend: http://localhost:5173
# Backend: http://localhost:3000
```

---

## ☁️ DEPLOYMENT ON RENDER (Zero Server Management — Recommended)

Aegis includes a `render.yaml` Blueprint for automated deployment on Render.

### Option A: One-Click Blueprint Setup

1. Push your latest code to your GitHub repository.
2. Go to [dashboard.render.com](https://dashboard.render.com) and click **New +** → **Blueprint**.
3. Connect your repository.
4. Render detects [`render.yaml`](file:///d:/Aegis/render.yaml) and automatically configures:
   - **aegis-web**: Unified Web Service (Express API + React Frontend).
   - **aegis-copilot**: Python AI Copilot microservice.
   - **aegis-postgres**: Managed PostgreSQL database.
5. Provide your `GEMINI_API_KEY` and `REDIS_URL` (free from [Upstash](https://upstash.com)) when prompted.
6. Click **Apply** to deploy!

### Option B: Manual Web Service Setup on Render

1. **Database**: Click **New +** → **PostgreSQL** (Name: `aegis-postgres`, Plan: Free).
2. **Web Service**: Click **New +** → **Web Service** and connect your repository:
   - **Runtime**: Node
   - **Build Command**: `npm install && npx prisma generate && npm run build`
   - **Start Command**: `npm start`
   - **Health Check Path**: `/api/public/health`
   - **Environment Variables**:
     - `NODE_ENV`: `production`
     - `MODE`: `organization`
     - `DATABASE_URL`: Connection string from your Render PostgreSQL database
     - `REDIS_URL`: Free Redis connection string (from [Upstash](https://upstash.com))
     - `JWT_SECRET`: Random 32+ character string
     - `ENCRYPTION_KEY`: Random 32-character string
     - `GEMINI_API_KEY`: Your Gemini API key
3. Click **Deploy Web Service**. Render provides free SSL/HTTPS and automatically redeploys whenever you push to `main`!

---

## 🌐 PRODUCTION DEPLOYMENT - DIGITALOCEAN / VPS

### Step 1: Create DigitalOcean Account

1. Go to [digitalocean.com](https://www.digitalocean.com)
2. Sign up (get $200 free credit for 60 days)
3. Verify your email

### Step 2: Create a Droplet

1. Click **Create** → **Droplets**
2. Choose configuration:
   - **OS**: Ubuntu 22.04 LTS x64
   - **Plan**: Basic ($12/month) or Premium ($24/month)
   - **Region**: Choose closest to your users (e.g., NYC, London, Singapore)
   - **Authentication**: SSH key (recommended) or Password
3. Click **Create Droplet**
4. Wait 1-2 minutes for provisioning
5. Note your server IP address (e.g., `123.45.67.89`)

### Step 3: Connect to Your Server

**Windows (PowerShell):**

```powershell
ssh root@123.45.67.89
# Enter password or use SSH key
```

**Mac/Linux:**

```bash
ssh root@123.45.67.89
```

### Step 4: Install Dependencies on Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install Python 3, Git, PostgreSQL, Redis, and build tools
sudo apt install -y git python3 python3-pip python3-venv postgresql postgresql-contrib redis-server nginx

# Install PM2 globally
sudo npm install -g pm2

# Enable and start PostgreSQL & Redis
sudo systemctl enable --now postgresql
sudo systemctl enable --now redis-server

# Configure PostgreSQL database and user
sudo -u postgres psql -c "CREATE DATABASE aegis_enterprise;"
sudo -u postgres psql -c "CREATE USER aegis WITH ENCRYPTED PASSWORD 'your_secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE aegis_enterprise TO aegis;"
```

### Step 5: Deploy Aegis with PM2

```bash
# Create application directory
sudo mkdir -p /opt/aegis
sudo chown -R $USER:$USER /opt/aegis
cd /opt/aegis

# Clone your repository
git clone <your-repo-url> .

# Copy environment file and configure
cp .env.example .env
nano .env

# Set minimum required values in .env:
# DATABASE_URL=postgresql://aegis:your_secure_password@localhost:5432/aegis_enterprise?schema=public
# REDIS_URL=redis://localhost:6379
# JWT_SECRET=<random-32-char-string>
# ENCRYPTION_KEY=<random-32-char-string>
# GEMINI_API_KEY=<your-gemini-key>
# NODE_ENV=production
# PORT=3000

# Install dependencies
npm ci
pip3 install -r requirements.txt

# Run migrations
npx prisma migrate deploy
npx prisma generate

# Build frontend and backend bundles
npm run build

# Start services via PM2
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup
```

### Step 6: Configure Domain & SSL

**A. Point Domain to Server**

1. Go to your domain registrar (Namecheap, Google Domains, etc.)
2. Add DNS records:
   - **Type**: A
   - **Name**: @
   - **Value**: `123.45.67.89` (your server IP)
   - **TTL**: Automatic
3. Add another for www:
   - **Type**: CNAME
   - **Name**: www
   - **Value**: `your-domain.com`

**B. Install SSL Certificate (Let's Encrypt)**

```bash
# Install Certbot
apt install -y certbot python3-certbot-nginx

# Get SSL certificate
certbot --nginx -d your-domain.com -d www.your-domain.com

# Test auto-renewal
certbot renew --dry-run

# Certbot automatically configures Nginx and sets up renewal
```

### Step 7: Configure Firewall

```bash
# Install UFW
apt install -y ufw

# Allow SSH
ufw allow 22/tcp

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Enable firewall
ufw enable

# Check status
ufw status
```

### Step 8: Setup Automated Backups

```bash
# Create backup script
nano /opt/aegis/backup.sh
```

```bash
#!/bin/bash
# Aegis Daily Backup Script

BACKUP_DIR="/opt/backups/aegis"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

mkdir -p $BACKUP_DIR

# Backup PostgreSQL
docker-compose exec -T postgres pg_dump -U aegis aegis_enterprise > $BACKUP_DIR/db_$DATE.sql

# Backup Redis
docker-compose exec -T redis redis-cli SAVE
cp /var/lib/docker/volumes/aegis_redis_data/_data/dump.rdb $BACKUP_DIR/redis_$DATE.rdb

# Backup uploads and knowledge base
tar -czf $BACKUP_DIR/files_$DATE.tar.gz ./storage ./knowledge_base

# Delete old backups
find $BACKUP_DIR -name "*.sql" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.rdb" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

```bash
# Make executable
chmod +x /opt/aegis/backup.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add line:
0 2 * * * /opt/aegis/backup.sh >> /var/log/aegis_backup.log 2>&1
```

### Step 9: Setup Monitoring

**A. Uptime Monitoring (External)**

1. Go to [UptimeRobot](https://uptimerobot.com)
2. Create free account
3. Add new monitor:
   - **Type**: HTTP(s)
   - **URL**: https://your-domain.com/api/health
   - **Check interval**: Every 5 minutes
   - **Alert contacts**: Your email

**B. Server Monitoring (Netdata)**

```bash
# Install Netdata
bash <(curl -Ss https://my-netdata.io/kickstart.sh)

# Access at: http://123.45.67.89:19999
# Configure Nginx to proxy Netdata (optional)
```

### Step 10: Security Hardening

```bash
# Install Fail2Ban
apt install -y fail2ban

# Start and enable
systemctl enable fail2ban
systemctl start fail2ban

# Configure automatic security updates
apt install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# Disable root SSH login (create sudo user first!)
# nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
# systemctl restart sshd
```

---

## 🔧 MAINTENANCE & OPERATIONS

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f postgres
docker-compose logs -f redis

# Last 100 lines
docker-compose logs --tail=100 backend
```

### Restart Services

```bash
# Restart all
docker-compose restart

# Restart specific
docker-compose restart backend

# Recreate (after code changes)
docker-compose up -d --force-recreate backend
```

### Update Application

```bash
cd /opt/aegis

# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose up -d --build

# Run new migrations
docker-compose exec backend npx prisma migrate deploy
docker-compose exec backend npx prisma generate

# Restart services
docker-compose restart
```

### Database Operations

```bash
# Backup now
docker-compose exec postgres pg_dump -U aegis aegis_enterprise > backup.sql

# Restore from backup
cat backup.sql | docker-compose exec -T postgres psql -U aegis aegis_enterprise

# View database size
docker-compose exec postgres psql -U aegis -d aegis_enterprise -c "SELECT pg_size_pretty(pg_database_size('aegis_enterprise'));"

# Run SQL query
docker-compose exec postgres psql -U aegis -d aegis_enterprise -c "SELECT COUNT(*) FROM anomalies;"
```

### Health Checks

```bash
# API health
curl http://localhost:3000/api/health

# Database connection
docker-compose exec postgres pg_isready -U aegis

# Redis connection
docker-compose exec redis redis-cli ping

# All services status
docker-compose ps
```

---

## 🆘 TROUBLESHOOTING

### Services Won't Start

```bash
# Check logs
docker-compose logs postgres
docker-compose logs redis
docker-compose logs backend

# Check disk space
df -h

# Check memory
free -h

# Check Docker status
systemctl status docker
```

### Database Connection Errors

```bash
# Verify PostgreSQL is running
docker-compose ps postgres

# Check database URL in .env
docker-compose exec backend env | grep DATABASE_URL

# Test connection
docker-compose exec backend npx prisma db pull
```

### Out of Memory

```bash
# Increase swap space
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# Make permanent
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

### SSL Certificate Issues

```bash
# Check certificate status
certbot certificates

# Renew manually
certbot renew --force-renewal

# Debug renewal
certbot renew --dry-run --verbose
```

### High CPU Usage

```bash
# Check top processes
top

# Check Docker resource usage
docker stats

# Limit Docker resources in docker-compose.yml
# Add deploy.resources.limits
```

---

## 📊 COST BREAKDOWN

| Item               | Monthly Cost | Annual Cost |
| ------------------ | ------------ | ----------- |
| Domain (.com)      | -            | $12-15      |
| DigitalOcean Basic | $12          | $144        |
| Backups (25GB)     | $2           | $24         |
| **Total**          | **$14**      | **$180**    |

---

## ✅ DEPLOYMENT CHECKLIST

### Pre-Deployment

- [ ] Domain purchased and DNS configured
- [ ] DigitalOcean account created
- [ ] Droplet provisioned (Ubuntu 22.04)
- [ ] SSH access working
- [ ] Docker and Docker Compose installed
- [ ] .env file created with all secrets
- [ ] Firewall configured (UFW)
- [ ] SSL certificate installed (Let's Encrypt)

### Post-Deployment

- [ ] All containers running (`docker-compose ps`)
- [ ] Database migrations applied
- [ ] API health endpoint responding
- [ ] Frontend accessible via HTTPS
- [ ] Uptime monitoring configured
- [ ] Automated backups configured
- [ ] Security updates enabled
- [ ] Fail2Ban installed and running

---

## 📞 SUPPORT

For issues:

1. Check logs: `docker-compose logs -f`
2. Check health: `curl http://localhost:3000/api/health`
3. Review this guide's troubleshooting section
4. Check Docker and system resources

---

**Last Updated**: June 2026
**Version**: 2.0.0
