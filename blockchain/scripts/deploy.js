/**
 * scripts/deploy.js
 *
 * Robust deployment script for BiometricAuditLog.sol
 * - Works with Hardhat (local) and remote networks (Sepolia via Infura/Alchemy)
 * - Uses BLOCKCHAIN_PRIVATE_KEY from .env when deploying to remote networks
 * - Performs a JSON-RPC health check before attempting deploy
 * - Writes webapp/BiometricAuditLog_deploy.json { address, abi }
 *
 * Usage:
 *   # local (requires `npx hardhat node` running or uses unlocked signers)
 *   npx hardhat run scripts/deploy.js --network localhost
 *
 *   # remote (requires .env with SEPOLIA_RPC_URL and BLOCKCHAIN_PRIVATE_KEY)
 *   npx hardhat run scripts/deploy.js --network sepolia
 */

require("dotenv").config();
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function rpcHealthCheck(provider) {
  try {
    // Minimal JSON-RPC call to ensure provider responds with JSON-RPC
    const block = await provider.send("eth_blockNumber", []);
    console.log("RPC health check OK. Latest block (hex):", block);
    return true;
  } catch (err) {
    console.error("RPC health check failed:", err && err.message ? err.message : err);
    return false;
  }
}

function extractJsonAbi(factoryOrInterface) {
  // Try a few ways to get a JSON ABI that works across ethers versions
  // Accepts either a ContractFactory (`factory`) or Interface object
  const iface = factoryOrInterface.interface ?? factoryOrInterface;
  // Attempt 1: interface.format("json")
  try {
    const jsonStr = iface.format ? iface.format("json") : null;
    if (jsonStr) {
      // Could be a JSON string of array or string that contains array - try parse safely
      try {
        return JSON.parse(jsonStr);
      } catch (e) {
        // Try to find the JSON array substring
        const first = jsonStr.indexOf("[");
        const last = jsonStr.lastIndexOf("]");
        if (first !== -1 && last !== -1 && last > first) {
          const slice = jsonStr.slice(first, last + 1);
          return JSON.parse(slice);
        }
        throw e;
      }
    }
  } catch (e) {
    // continue to next fallback
  }

  // Attempt 2: if fragments exist (ethers v6)
  try {
    if (Array.isArray(iface.fragments)) {
      // fragments might be objects or Fragment instances with format method
      const arr = iface.fragments.map((f) => {
        if (typeof f.format === "function") {
          // f.format("json") returns string of JSON for a fragment
          return JSON.parse(f.format("json"));
        } else if (typeof f === "object") {
          return f; // assume already JSON-like
        } else {
          return null;
        }
      }).filter(Boolean);
      if (arr.length > 0) return arr;
    }
  } catch (e) {
    // fallback below
  }

  // Attempt 3: some ethers versions expose .abi or .json
  if (iface.abi) return iface.abi;
  if (iface._abi) return iface._abi;

  throw new Error("Unable to derive JSON ABI from contract interface.");
}

async function main() {
  console.log("=== BiometricAuditLog deploy script ===");

  // Provider configured by Hardhat CLI's --network flag and hardhat.config.js
  const provider = hre.ethers.provider;
  let providerNetwork;
  try {
    providerNetwork = await provider.getNetwork();
    console.log("Hardhat provider network:", providerNetwork);
  } catch (e) {
    // provider might still be usable - continue after healthcheck
    console.warn("Could not auto-detect network from provider:", e.message || e);
  }

  // Health check RPC
  const ok = await rpcHealthCheck(provider);
  if (!ok) {
    console.error("\nERROR: RPC endpoint did not respond correctly.");
    console.error(" - Check your network flag (--network) and your .env variables (SEPOLIA_RPC_URL / BLOCKCHAIN_RPC_URL).");
    console.error(" - If you intended to deploy locally, ensure `npx hardhat node` is running and use --network localhost.");
    process.exit(1);
  }

  // Choose signer:
  // - Prefer BLOCKCHAIN_PRIVATE_KEY (for remote networks)
  // - Else fallback to unlocked local signer from hre.ethers.getSigners()
  const rawPk = process.env.BLOCKCHAIN_PRIVATE_KEY?.trim();
  let signer;
  if (rawPk) {
    // Validate simple format: 0x + 64 hex chars
    if (!/^0x[0-9a-fA-F]{64}$/.test(rawPk)) {
      console.error("BLOCKCHAIN_PRIVATE_KEY appears malformed. Ensure it is 0x + 64 hex chars (do not use mnemonic).");
      process.exit(1);
    }
    try {
      signer = new hre.ethers.Wallet(rawPk, provider);
      console.log("Using Wallet signer (from BLOCKCHAIN_PRIVATE_KEY):", signer.address);
    } catch (err) {
      console.error("Failed to create Wallet from BLOCKCHAIN_PRIVATE_KEY:", err.message || err);
      process.exit(1);
    }
  } else {
    // fallback to local signer (e.g., hardhat node unlocked accounts)
    const signers = await hre.ethers.getSigners();
    if (!signers || signers.length === 0) {
      console.error("No signer found. Provide BLOCKCHAIN_PRIVATE_KEY in .env (for remote) or run a local node.");
      process.exit(1);
    }
    signer = signers[0];
    try {
      const addr = (typeof signer.getAddress === "function") ? await signer.getAddress() : signer.address;
      console.log("Using local unlocked signer:", addr);
    } catch (e) {
      console.log("Using local unlocked signer (address unavailable to print).");
    }
  }

  // Prepare contract factory and attach signer
  console.log("Getting contract factory for BiometricAuditLog...");
  const factory = await hre.ethers.getContractFactory("BiometricAuditLog");
  const connectedFactory = factory.connect(signer);

  // Optional deploy parameter overrides (gas/gasLimit) - keep modest defaults
  const deployOverrides = {};
  // You can set gasLimit or maxFeePerGas here if needed, e.g.:
  // deployOverrides.gasLimit = 6_000_000;

  console.log("Deploying contract (this will broadcast a transaction)...");
  let contract;
  try {
    // Ethers v6: factory.deploy(...args, overrides)
    contract = await connectedFactory.deploy(deployOverrides);
  } catch (err) {
    // If the above fails because deploy() expects different args, try without overrides
    try {
      contract = await connectedFactory.deploy();
    } catch (err2) {
      console.error("Contract deploy() call failed:", err2 && err2.message ? err2.message : err2);
      process.exit(1);
    }
  }

  // Wait for deployment (support ethers v6 and v5)
  try {
    if (typeof contract.waitForDeployment === "function") {
      await contract.waitForDeployment();
    } else if (typeof contract.deployed === "function") {
      await contract.deployed();
    } else {
      // fallback: wait a few blocks or transaction confirmation if available
      if (contract.deployTransaction && contract.deployTransaction.wait) {
        await contract.deployTransaction.wait(1);
      }
    }
  } catch (err) {
    console.error("Error while waiting for deployment:", err && err.message ? err.message : err);
    process.exit(1);
  }

  // Obtain address in a version-agnostic way
  const contractAddress = contract.target ?? contract.address ?? (contract.deployTransaction && contract.deployTransaction.contractAddress);
  console.log("Contract deployed at:", contractAddress);

  // Extract ABI robustly
  let abi;
  try {
    abi = extractJsonAbi(factory);
  } catch (err) {
    console.error("Failed to extract ABI:", err.message || err);
    process.exit(1);
  }

  // Write JSON artifact for backend consumption (address + abi)
  const out = {
    address: contractAddress,
    abi,
  };

  const outPath = path.join(__dirname, "..", "webapp", "BiometricAuditLog_deploy.json");
  try {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(out, null, 2), { encoding: "utf8" });
    console.log("Wrote deployment artifact to:", outPath);
  } catch (err) {
    console.error("Failed to write deployment artifact:", err.message || err);
    process.exit(1);
  }

  // Friendly next-step guidance
  console.log("\n=== Next steps ===");
  console.log(`1) Add the contract address to your backend .env (or copy it from ${outPath}):`);
  console.log(`   BLOCKCHAIN_CONTRACT_ADDRESS=${contractAddress}`);
  console.log("2) Ensure your backend reads the ABI from webapp/BiometricAuditLog_deploy.json");
  console.log("3) If you deployed to Sepolia, ensure the deployer account has test ETH and BLOCKCHAIN_PRIVATE_KEY is kept secret.");
  console.log("\nDeployment completed successfully.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Unhandled error in deploy script:", err && err.stack ? err.stack : err);
    process.exit(1);
  });
