# Blockchain Event Anchoring Setup Guide

## Overview
This guide explains how to set up the complete blockchain event anchoring system for the Biometric Audit Log application. Events are automatically anchored to the Sepolia blockchain when users register or authenticate.

## Architecture

```
Frontend (Netlify)
    ↓ /api/* requests (proxied via netlify.toml)
Backend (Render - Flask)
    ↓ anchor_event_to_blockchain()
Blockchain Server (Render - Node.js)
    ↓ POST /api/anchor-event
Smart Contract (Sepolia)
    ↓ addLog() transaction
Blockchain ✓
```

## Event Flow

1. **User Registration**: Username → Backend → Blockchain API → Smart Contract
2. **Face Authentication Success/Failure**: Auth result → Backend → Blockchain API → Smart Contract
3. **Fingerprint Authentication Success/Failure**: Auth result → Backend → Blockchain API → Smart Contract

## Deployment Checklist

### 1. Frontend Configuration (Netlify)

**File**: `.env` or set in Netlify UI
```
VITE_BLOCKCHAIN_API=https://majorproject-cjno.onrender.com/api
```

**netlify.toml** - Already configured to proxy `/api/*` to backend:
```toml
[[redirects]]
  from = "/api/*"
  to = "https://majorproject-cjno.onrender.com/api/:splat"
  status = 200
  force = true
```

### 2. Backend Configuration (Render - Flask)

**Environment Variables** to set in Render:
- `BLOCKCHAIN_API_URL`: URL of blockchain Node.js server
  - Example: `https://majorproject-cjno.onrender.com` (same base URL as backend)
- `DATABASE_URL`: PostgreSQL connection string
- `FRONTEND_URL`: Your Netlify URL
- `SECRET_KEY`: Random string for security
- `JWT_SECRET`: Random string for JWT tokens

**Key Functions**:
- `anchor_event_to_blockchain()`: Calls blockchain API to record events
- Integrated in: Registration, Face Auth, Fingerprint Auth endpoints
- Uses ThreadPoolExecutor for non-blocking background anchoring

### 3. Blockchain Server Configuration (Render - Node.js)

**Environment Variables** to set in Render:
- `BLOCKCHAIN_RPC_URL`: Sepolia RPC endpoint
  - Recommended: Infura (free tier available)
  - Example: `https://sepolia.infura.io/v3/YOUR_INFURA_KEY`
- `BLOCKCHAIN_CONTRACT_ADDRESS`: Your deployed contract address
  - Get after deploying `BiometricAuditLog.sol` to Sepolia
  - Example: `0x1234567890123456789012345678901234567890`
- `BLOCKCHAIN_PRIVATE_KEY`: Private key for signing transactions
  - **CRITICAL**: Account must have ETH for gas fees on Sepolia
  - Get testnet ETH: https://sepoliafaucet.com/
  - Format: `0x...` (with 0x prefix)
- `FRONTEND_URL`: Frontend URL for CORS
  - Example: `https://majorpr.netlify.app`

### 4. Smart Contract Deployment (Sepolia)

**Steps**:
1. Deploy `BiometricAuditLog.sol` to Sepolia using Hardhat
2. Copy the contract address to `BLOCKCHAIN_CONTRACT_ADDRESS`
3. Update `blockchain/webapp/BiometricAuditLog_deploy.json` with the address

**Contract Functions**:
- `addLog(userIdHash, eventType, timestamp, metaHash)`: Records event
- `getLog(index)`: Retrieves event from blockchain
- `totalLogs()`: Gets total number of logged events

## Troubleshooting

### Issue: `net::ERR_NAME_NOT_RESOLVED`

**Cause**: Frontend can't reach backend URL (DNS resolution failure)

**Solution**:
1. Verify `VITE_BLOCKCHAIN_API` is set correctly in Netlify environment
2. Check that the Render backend URL is accessible:
   ```bash
   curl https://majorproject-cjno.onrender.com/api/health
   ```
3. Verify `netlify.toml` has correct redirects for `/api/*`

### Issue: Events not showing in frontend logs

**Cause**: Backend running but blockchain server not accessible

**Solution**:
1. Check backend logs for blockchain connection errors
2. Verify `BLOCKCHAIN_API_URL` is set in backend environment
3. Ensure blockchain Node.js server is running on Render
4. Test blockchain server health:
   ```bash
   curl https://majorproject-cjno.onrender.com/api/health
   ```

### Issue: Transactions not appearing on Sepolia

**Cause**: Private key account has no ETH or invalid configuration

**Solution**:
1. Verify account has ETH balance: https://sepolia.etherscan.io/
2. Get testnet ETH from: https://sepoliafaucet.com/
3. Verify private key is correct format (starts with 0x)
4. Check `BLOCKCHAIN_RPC_URL` is valid Infura/Alchemy endpoint
5. Verify `BLOCKCHAIN_CONTRACT_ADDRESS` is correct

### Issue: CORS errors

**Cause**: Frontend and backend have mismatched CORS settings

**Solution**:
1. Update backend `ALLOWED_ORIGINS` to include Netlify URL
2. Update blockchain server `FRONTEND_URL` to include all client URLs
3. In Netlify, ensure headers allow CORS

## Testing

### Local Development
1. Start blockchain server: `npm start` in `blockchain/`
2. Start Flask backend: `python Backend/app_enhanced.py`
3. Start frontend: `npm run dev` in project root

### Verify Endpoints
```bash
# Check blockchain server health
curl http://localhost:5000/api/health

# Check logs
curl http://localhost:5000/api/logs

# Check stats
curl http://localhost:5000/api/stats
```

### View Transactions
- Sepolia Explorer: https://sepolia.etherscan.io/
- Search by contract address or transaction hash
- Verify events in block explorer

## Files Modified

- `Frontend/.env`: Environment variables for frontend
- `Frontend/netlify.toml`: API proxy configuration
- `Frontend/src/LogViewer.jsx`: Fixed API URL construction
- `Frontend/vite.config.js`: Cleaned up env var handling
- `Backend/app_enhanced.py`: Added blockchain anchoring
- `Blockchain/server.js`: Added POST /api/anchor-event endpoint
- `.env.example`: Updated with all required variables

## Security Notes

1. **Never commit `.env` files** with real private keys
2. **Use environment variables** on Render/Netlify, not hardcoded values
3. **Create a dedicated account** for blockchain transactions
4. **Rotate keys regularly** in production
5. **Monitor transaction costs** on Sepolia (free testnet but good for testing)

## Next Steps

1. Deploy contract to Sepolia
2. Set all environment variables on Render and Netlify
3. Test registration and authentication
4. Verify transactions in Sepolia block explorer
5. Monitor logs for any errors

---

**Status**: ✅ System ready for deployment
**Last Updated**: December 2024
