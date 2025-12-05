require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Web3 } = require('web3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT || '5000', 10);

const parseCorsOrigin = () => {
  const frontendUrl = process.env.FRONTEND_URL;
  
  if (!frontendUrl || frontendUrl === '*') {
    return true;
  }
  
  if (frontendUrl.includes(',')) {
    return frontendUrl.split(',').map(url => url.trim());
  }
  
  return frontendUrl;
};

app.use(cors({
  origin: parseCorsOrigin(),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const RPC_URL = process.env.BLOCKCHAIN_RPC_URL || process.env.SEPOLIA_RPC_URL || 'http://127.0.0.1:8545';
const CONTRACT_ADDRESS = process.env.BLOCKCHAIN_CONTRACT_ADDRESS;
const CONTRACT_ABI_PATH = path.join(__dirname, 'webapp', 'BiometricAuditLog_deploy.json');
const CONTRACT_ABI_FALLBACK = path.join(__dirname, 'webapp', 'BiometricAuditLog_abi.json');

let web3;
let contract;

const initializeBlockchain = async () => {
  try {
    web3 = new Web3(RPC_URL);
    
    let contractAddress = CONTRACT_ADDRESS;
    let contractAbi = null;

    if (fs.existsSync(CONTRACT_ABI_PATH)) {
      const deployData = JSON.parse(fs.readFileSync(CONTRACT_ABI_PATH, 'utf8'));
      contractAddress = deployData.address;
      contractAbi = deployData.abi;
    } else if (fs.existsSync(CONTRACT_ABI_FALLBACK)) {
      contractAbi = JSON.parse(fs.readFileSync(CONTRACT_ABI_FALLBACK, 'utf8'));
    }

    if (!contractAddress || !contractAbi) {
      throw new Error('Contract address or ABI not found. Ensure BiometricAuditLog_deploy.json or BiometricAuditLog_abi.json exists in webapp/');
    }

    contract = new web3.eth.Contract(contractAbi, contractAddress);
    console.log('✓ Blockchain connection established');
    console.log(`  Contract: ${contractAddress}`);
    console.log(`  RPC: ${RPC_URL}`);
  } catch (error) {
    console.error('✗ Failed to initialize blockchain:', error.message);
    process.exit(1);
  }
};

const getEventTypeString = (eventTypeNum) => {
  const eventTypes = {
    0: 'ENROLL',
    1: 'AUTH_SUCCESS',
    2: 'AUTH_FAIL',
    3: 'ADMIN_ACTION'
  };
  return eventTypes[eventTypeNum] || 'UNKNOWN';
};

app.get('/api/logs', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.per_page) || 10;

    if (!contract) {
      return res.status(503).json({ error: 'Blockchain not initialized' });
    }

    const totalLogs = await contract.methods.totalLogs().call();
    const totalPages = Math.ceil(totalLogs / perPage);

    const startIndex = Math.max(0, totalLogs - page * perPage);
    const endIndex = Math.max(0, totalLogs - (page - 1) * perPage);

    const logs = [];
    for (let i = startIndex; i < endIndex; i++) {
      const entry = await contract.methods.getLog(i).call();
      logs.push({
        index: i,
        userIdHash: entry[0],
        eventType: getEventTypeString(entry[1]),
        timestamp: parseInt(entry[2]),
        metaHash: entry[3]
      });
    }

    logs.reverse();

    res.json({
      logs,
      page,
      per_page: perPage,
      total: totalLogs,
      pages: totalPages
    });
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/logs/:index/verify', async (req, res) => {
  try {
    const { index } = req.params;

    if (!contract) {
      return res.status(503).json({ error: 'Blockchain not initialized' });
    }

    const entry = await contract.methods.getLog(index).call();
    
    if (!entry) {
      return res.status(404).json({ success: false, error: 'Log entry not found' });
    }

    res.json({
      success: true,
      verified: true,
      data: {
        index,
        userIdHash: entry[0],
        eventType: getEventTypeString(entry[1]),
        timestamp: parseInt(entry[2]),
        metaHash: entry[3]
      },
      message: 'Log entry verified successfully on blockchain'
    });
  } catch (error) {
    console.error('Error verifying log:', error);
    res.status(500).json({
      success: false,
      verified: false,
      error: error.message
    });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    blockchain: contract ? 'connected' : 'disconnected',
    rpc: RPC_URL,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/stats', async (req, res) => {
  try {
    if (!contract) {
      return res.status(503).json({ error: 'Blockchain not initialized' });
    }

    const totalLogs = await contract.methods.totalLogs().call();
    
    res.json({
      totalLogs: parseInt(totalLogs),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const start = async () => {
  console.log('🚀 Starting Blockchain Audit Log API Server...');
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 RPC URL: ${RPC_URL}`);
  
  await initializeBlockchain();
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔═══════════════════════════════════════════════════╗
║     Blockchain Audit Log API Server Active        ║
╠═══════════════════════════════════════════════════╣
║  🟢 Server running on port ${PORT.toString().padEnd(30)}║
║  📊 Health: GET /api/health                       ║
║  📝 Logs: GET /api/logs                           ║
║  ✅ Verify: GET /api/logs/:index/verify           ║
║  📈 Stats: GET /api/stats                         ║
╚═══════════════════════════════════════════════════╝
    `);
  });
};

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

start().catch(error => {
  console.error('❌ Failed to start server:', error.message);
  console.error(error.stack);
  process.exit(1);
});
