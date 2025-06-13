# Environment Configuration Guide

## 🔒 Security First!

### What is .env?
- `.env` files store sensitive configuration like passwords and API keys
- They should **NEVER** be committed to version control
- Each developer/deployment should have their own `.env` file

### File Structure
```
wazuh-mcp-server/
├── .env              # ❌ NEVER COMMIT (your actual credentials)
├── .env.example      # ✅ SAFE TO COMMIT (template without secrets)
├── .gitignore        # ✅ Ensures .env is not tracked
└── src/
```

## 📝 Setup Instructions

### 1. Create Your .env File

**Windows (Command Prompt):**
```cmd
copy .env.example .env
```

**Windows (PowerShell):**
```powershell
Copy-Item .env.example .env
```

**Linux/Mac:**
```bash
cp .env.example .env
```

### 2. Edit Your .env File

**Required Changes:**
```env
# Change these from defaults!
WAZUH_HOST=your-actual-wazuh-server.com  # Not 'localhost'
WAZUH_USER=your-api-username             # Not 'admin'  
WAZUH_PASS=your-secure-password          # Not 'admin'
```

**Optional API Keys:**
```env
# Add if you have them
VIRUSTOTAL_API_KEY=your-virustotal-key-here
SHODAN_API_KEY=your-shodan-key-here
ABUSEIPDB_API_KEY=your-abuseipdb-key-here
```

### 3. Verify .gitignore

Check that `.env` is properly ignored:
```bash
git status
# Should NOT show .env in the output!
```

If you see `.env` in git status:
```bash
# Remove from tracking (if accidentally added)
git rm --cached .env
git commit -m "Remove .env from tracking"
```

### 4. Set File Permissions (Linux/Mac)

Protect your `.env` file:
```bash
chmod 600 .env  # Only owner can read/write
```

## 🐳 Docker Usage

### Option 1: Using .env File
```bash
# Docker Compose automatically reads .env
docker-compose up -d
```

### Option 2: Explicit Environment
```bash
# Override with different env file
docker-compose --env-file .env.production up -d
```

### Option 3: Inline Variables
```bash
# Pass directly (useful for CI/CD)
WAZUH_HOST=prod-server WAZUH_USER=api-user docker-compose up -d
```

## 🔍 Troubleshooting

### Test Your Configuration
```bash
# Verify connection
python scripts/test_connection.py

# Check loaded variables (be careful not to log passwords!)
python -c "import os; print('Host:', os.getenv('WAZUH_HOST', 'NOT SET'))"
```

### Common Issues

**Issue: "WAZUH_HOST environment variable not set"**
- Solution: Ensure .env file exists and is in the project root
- Check: File is named `.env` not `env` or `.env.txt`

**Issue: "Authentication failed"**
- Solution: Verify credentials in .env match your Wazuh setup
- Check: No extra spaces or quotes in .env values

**Issue: Changes to .env not taking effect**
- Solution: Restart your application/container
- Docker: `docker-compose restart`
- Python: Stop and restart the script

## 📋 Environment Variable Reference

### Priority Order
1. System environment variables (highest)
2. .env file variables
3. Default values in code (lowest)

### Required Variables
| Variable | Description | Example |
|----------|-------------|---------|
| `WAZUH_HOST` | Wazuh API server | `wazuh.company.com` |
| `WAZUH_USER` | API username | `api-reader` |
| `WAZUH_PASS` | API password | `SecurePass123!` |

### Security Best Practices

✅ **DO:**
- Use strong, unique passwords
- Create dedicated API users with minimal permissions
- Enable SSL verification in production (`VERIFY_SSL=true`)
- Rotate credentials regularly
- Use different credentials for dev/staging/prod

❌ **DON'T:**
- Commit .env files to Git
- Use default admin credentials
- Share .env files via email/chat
- Log or print credentials
- Use the same password everywhere

## 🚀 Production Deployment

### Using Environment Variables (Recommended)
```bash
# Set in your deployment platform (AWS, Azure, etc.)
export WAZUH_HOST=prod-wazuh.company.com
export WAZUH_USER=prod-api-user
export WAZUH_PASS=super-secret-password
```

### Using Secrets Management
```bash
# AWS Secrets Manager example
WAZUH_PASS=$(aws secretsmanager get-secret-value --secret-id wazuh-api-pass --query SecretString --output text)
```

### Kubernetes Secrets
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: wazuh-mcp-secrets
type: Opaque
data:
  wazuh-host: d2F6dWguY29tcGFueS5jb20=  # base64 encoded
  wazuh-user: YXBpLXVzZXI=              # base64 encoded
  wazuh-pass: c2VjcmV0LXBhc3N3b3Jk      # base64 encoded
```

## 📚 Additional Resources

- [12-Factor App Config](https://12factor.net/config)
- [Docker Environment Variables](https://docs.docker.com/compose/environment-variables/)
- [Python dotenv Documentation](https://pypi.org/project/python-dotenv/)