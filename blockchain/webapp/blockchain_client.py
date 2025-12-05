# webapp/blockchain_client.py
import os
import json
import time
import hashlib
from pathlib import Path
from web3 import Web3, HTTPProvider
from eth_account import Account
from dotenv import load_dotenv

load_dotenv()

RPC = os.getenv("SEPOLIA_RPC_URL") or os.getenv("BLOCKCHAIN_RPC_URL") or "http://127.0.0.1:8545"
w3 = Web3(HTTPProvider(RPC))

# Load ABI + address
deploy_path = Path(__file__).parent / "BiometricAuditLog_deploy.json"
if deploy_path.exists():
    data = json.loads(deploy_path.read_text())
    CONTRACT_ADDRESS = data["address"]
    CONTRACT_ABI = data["abi"]
else:
    CONTRACT_ADDRESS = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS")
    abi_path = Path(__file__).parent / "BiometricAuditLog_abi.json"
    CONTRACT_ABI = json.loads(abi_path.read_text()) if abi_path.exists() else None

contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI)

# Server wallet for signing write transactions
PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
if PRIVATE_KEY:
    acct = Account.from_key(PRIVATE_KEY)
    SENDER_ADDRESS = acct.address
else:
    acct = None
    SENDER_ADDRESS = None

def sha256_hex_of_json(obj: dict) -> str:
    import json
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def bytes32_from_hex(hexstr: str) -> bytes:
    h = hexstr[2:] if hexstr.startswith("0x") else hexstr
    return bytes.fromhex(h)

def log_biometric_event(user_internal_id: str, event_type: int, meta_obj: dict, gas_overrides: dict = None):
    if acct is None:
        raise RuntimeError("No blockchain private key configured for writes.")
    timestamp = int(time.time())
    user_hash = hashlib.sha256(user_internal_id.encode("utf-8")).hexdigest()
    meta_hash = sha256_hex_of_json(meta_obj)

    # convert to bytes32 hex strings
    user_hash_bytes32 = "0x" + user_hash
    meta_hash_bytes32 = "0x" + meta_hash

    nonce = w3.eth.get_transaction_count(SENDER_ADDRESS)

    txn = contract.functions.addLog(
        Web3.to_bytes(hexstr=user_hash_bytes32),
        event_type,
        timestamp,
        Web3.to_bytes(hexstr=meta_hash_bytes32)
    ).build_transaction({
        "from": SENDER_ADDRESS,
        "nonce": nonce,
        "gas": 300_000,
        **(gas_overrides or {})
    })

    signed = Account.sign_transaction(txn, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

def read_log(index: int):
    entry = contract.functions.getLog(index).call()
    # (userIdHash, eventType, timestamp, metaHash)
    return {
        "user_id_hash": entry[0].hex() if isinstance(entry[0], (bytes, bytearray)) else entry[0],
        "event_type": int(entry[1]),
        "timestamp": int(entry[2]),
        "meta_hash": entry[3].hex() if isinstance(entry[3], (bytes, bytearray)) else entry[3],
    }
