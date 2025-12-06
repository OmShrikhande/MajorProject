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
    console.log('🔄 Initializing Web3...');
    web3 = new Web3(RPC_URL);
    
    let contractAddress = CONTRACT_ADDRESS;
    let contractAbi = null;

    console.log(`📁 Looking for contract ABI files...`);
    console.log(`  Path 1: ${CONTRACT_ABI_PATH}`);
    console.log(`  Path 2: ${CONTRACT_ABI_FALLBACK}`);

    if (fs.existsSync(CONTRACT_ABI_PATH)) {
      console.log(`✓ Found: ${CONTRACT_ABI_PATH}`);
      const deployData = JSON.parse(fs.readFileSync(CONTRACT_ABI_PATH, 'utf8'));
      contractAddress = deployData.address;
      contractAbi = deployData.abi;
      console.log(`✓ Contract address from deploy file: ${contractAddress}`);
    } else if (fs.existsSync(CONTRACT_ABI_FALLBACK)) {
      console.log(`✓ Found: ${CONTRACT_ABI_FALLBACK}`);
      contractAbi = JSON.parse(fs.readFileSync(CONTRACT_ABI_FALLBACK, 'utf8'));
    }

    if (!contractAddress) {
      throw new Error(`❌ Contract address missing. Set BLOCKCHAIN_CONTRACT_ADDRESS env var. Current: ${CONTRACT_ADDRESS}`);
    }

    if (!contractAbi) {
      throw new Error('❌ Contract ABI not found. Ensure BiometricAuditLog_deploy.json or BiometricAuditLog_abi.json exists in webapp/');
    }

    console.log(`✓ Creating contract instance with ABI (${contractAbi.length} methods)`);
    contract = new web3.eth.Contract(contractAbi, contractAddress);
    
    console.log('✅ Blockchain connection established');
    console.log(`  📍 Contract: ${contractAddress}`);
    console.log(`  🔗 RPC: ${RPC_URL.substring(0, 60)}...`);
  } catch (error) {
    console.error('❌ Failed to initialize blockchain:', error.message);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
};

const getEventTypeString = (eventTypeNum) => {
  const num = typeof eventTypeNum === 'bigint' ? Number(eventTypeNum) : parseInt(eventTypeNum);
  const eventTypes = {
    0: 'ENROLL',
    1: 'AUTH_SUCCESS',
    2: 'AUTH_FAIL',
    3: 'ADMIN_ACTION'
  };
  return eventTypes[num] || 'UNKNOWN';
};

const toBigInt = (val) => {
  if (typeof val === 'bigint') return val;
  if (typeof val === 'string') return BigInt(val);
  return BigInt(val.toString());
};

const toNumber = (val) => {
  if (typeof val === 'bigint') return Number(val);
  if (typeof val === 'string') return parseInt(val, 10);
  return Number(val);
};

const toHex = (val) => {
  if (typeof val === 'string' && val.startsWith('0x')) return val;
  if (typeof val === 'string') return '0x' + val;
  if (typeof val === 'object' && val.toString) return val.toString();
  return val;
};

app.get('/api/logs', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.per_page) || 10;

    if (!contract) {
      console.error('❌ Contract not initialized');
      return res.status(503).json({ 
        error: 'Blockchain not initialized',
        details: {
          contractAddress: CONTRACT_ADDRESS,
          rpcUrl: RPC_URL.substring(0, 50) + '...'
        }
      });
    }

    console.log(`📊 Fetching logs: page=${page}, perPage=${perPage}`);
    
    const totalLogsRaw = await contract.methods.totalLogs().call();
    const totalLogs = toNumber(totalLogsRaw);
    console.log(`✓ Total logs: ${totalLogs} (type: ${typeof totalLogsRaw})`);
    
    const totalPages = Math.ceil(totalLogs / perPage);

    const startIndex = Math.max(0, totalLogs - page * perPage);
    const endIndex = Math.max(0, totalLogs - (page - 1) * perPage);

    console.log(`🔄 Fetching entries from index ${startIndex} to ${endIndex}`);

    const logs = [];
    for (let i = startIndex; i < endIndex; i++) {
      try {
        const entry = await contract.methods.getLog(i).call();
        
        const log = {
          index: i,
          userIdHash: toHex(entry[0]),
          eventType: getEventTypeString(entry[1]),
          timestamp: toNumber(entry[2]),
          metaHash: toHex(entry[3]),
          raw: {
            eventTypeRaw: entry[1].toString(),
            timestampRaw: entry[2].toString()
          }
        };
        
        logs.push(log);
        console.log(`  ✓ Log ${i}: ${log.eventType} at ${new Date(log.timestamp * 1000).toISOString()}`);
      } catch (err) {
        console.error(`  ❌ Error fetching log ${i}:`, err.message);
        throw err;
      }
    }

    logs.reverse();

    console.log(`✅ Successfully fetched ${logs.length} logs`);

    res.json({
      logs,
      page,
      per_page: perPage,
      total: totalLogs,
      pages: totalPages
    });
  } catch (error) {
    console.error('❌ Error fetching logs:', error.message);
    console.error('Stack:', error.stack);
    res.status(500).json({ 
      error: error.message,
      type: error.constructor.name,
      details: error.stack
    });
  }
});

app.get('/api/logs/:index/verify', async (req, res) => {
  try {
    const { index } = req.params;

    if (!contract) {
      return res.status(503).json({ error: 'Blockchain not initialized' });
    }

    console.log(`🔍 Verifying log at index ${index}`);
    
    const entry = await contract.methods.getLog(index).call();
    
    if (!entry || !entry[0]) {
      return res.status(404).json({ success: false, error: 'Log entry not found' });
    }

    const verified = {
      success: true,
      verified: true,
      data: {
        index: toNumber(index),
        userIdHash: toHex(entry[0]),
        eventType: getEventTypeString(entry[1]),
        timestamp: toNumber(entry[2]),
        metaHash: toHex(entry[3]),
        formattedTime: new Date(toNumber(entry[2]) * 1000).toISOString()
      },
      message: 'Log entry verified successfully on blockchain'
    };
    
    console.log(`✅ Verification successful for log ${index}`);
    res.json(verified);
  } catch (error) {
    console.error('❌ Error verifying log:', error.message);
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
    rpc: RPC_URL.substring(0, 60) + '...',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/debug', (req, res) => {
  res.json({
    status: contract ? 'initialized' : 'not_initialized',
    environment: {
      NODE_ENV: process.env.NODE_ENV,
      PORT: PORT,
      CONTRACT_ADDRESS_ENV: process.env.BLOCKCHAIN_CONTRACT_ADDRESS,
      CONTRACT_ADDRESS_LOADED: CONTRACT_ADDRESS,
      RPC_URL_LOADED: RPC_URL.substring(0, 80) + '...',
      FRONTEND_URL: process.env.FRONTEND_URL,
      FILES: {
        deployJsonExists: fs.existsSync(CONTRACT_ABI_PATH),
        abiJsonExists: fs.existsSync(CONTRACT_ABI_FALLBACK),
        deployJsonPath: CONTRACT_ABI_PATH,
        abiJsonPath: CONTRACT_ABI_FALLBACK
      }
    },
    contract: contract ? {
      address: CONTRACT_ADDRESS,
      methodsCount: contract.methods ? Object.keys(contract.methods).length : 0
    } : null,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/stats', async (req, res) => {
  try {
    if (!contract) {
      return res.status(503).json({ error: 'Blockchain not initialized' });
    }

    const totalLogsRaw = await contract.methods.totalLogs().call();
    const totalLogs = toNumber(totalLogsRaw);
    
    console.log(`📈 Stats: ${totalLogs} total logs on blockchain`);
    
    res.json({
      totalLogs,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Error fetching stats:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/anchor-event', async (req, res) => {
  try {
    if (!contract) {
      return res.status(503).json({ error: 'Blockchain not initialized' });
    }

    const { userIdHash, eventType, timestamp, metaHash } = req.body;

    if (!userIdHash || eventType === undefined || !timestamp || !metaHash) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        required: ['userIdHash', 'eventType', 'timestamp', 'metaHash']
      });
    }

    console.log(`📝 Anchoring event: type=${eventType}, user=${userIdHash.substring(0, 10)}..., ts=${timestamp}`);

    const PRIVATE_KEY = process.env.BLOCKCHAIN_PRIVATE_KEY;
    if (!PRIVATE_KEY) {
      return res.status(503).json({ 
        error: 'Blockchain signer not configured',
        detail: 'BLOCKCHAIN_PRIVATE_KEY environment variable not set'
      });
    }

    const account = web3.eth.accounts.privateKeyToAccount(PRIVATE_KEY);
    web3.eth.accounts.wallet.add(account);

    const tx = contract.methods.addLog(userIdHash, eventType, timestamp, metaHash);
    const gas = await tx.estimateGas({ from: account.address });

    console.log(`⛽ Estimated gas: ${gas}`);

    const txData = tx.encodeABI();
    const nonce = await web3.eth.getTransactionCount(account.address);

    const rawTx = {
      from: account.address,
      to: CONTRACT_ADDRESS,
      data: txData,
      gas: Math.ceil(gas * 1.2),
      gasPrice: await web3.eth.getGasPrice(),
      nonce: nonce,
      chainId: 11155111
    };

    console.log(`🔐 Signing transaction from ${account.address}...`);
    const signedTx = await web3.eth.accounts.signTransaction(rawTx, PRIVATE_KEY);

    console.log(`📤 Sending transaction...`);
    const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);

    console.log(`✅ Event anchored! TxHash: ${receipt.transactionHash}`);

    res.json({
      success: true,
      transactionHash: receipt.transactionHash,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed,
      message: 'Event successfully anchored to blockchain'
    });

  } catch (error) {
    console.error('❌ Error anchoring event:', error.message);
    console.error('Stack:', error.stack);
    res.status(500).json({
      success: false,
      error: error.message,
      type: error.constructor.name
    });
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
║  ⛓️  Anchor: POST /api/anchor-event               ║
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
