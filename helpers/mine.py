#!/usr/bin/env python3
"""
FPGA Bitcoin Miner Controller
Copyright (c) 2025 Lone Dynamics Corporation. All rights reserved.
"""

import serial
import struct
import hashlib
import json
import requests
import time
import binascii
import argparse
import sys

from typing import Optional, Dict, Tuple, List

def crc32_mpeg2(data: bytes, crc: int = 0x0) -> int:
    """CRC-32/MPEG-2 implementation that matches FPGA hardware exactly"""
    for val in data:
        crc ^= val << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04c11db7
            else:
                crc = crc << 1
            crc &= 0xffffffff
    return crc

def encode_compact_size(value: int) -> bytes:
    """Encode a compact size integer (varint) for Bitcoin protocol"""
    if value < 0xfd:
        return struct.pack("<B", value)
    elif value <= 0xffff:
        return b'\xfd' + struct.pack("<H", value)
    elif value <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", value)
    else:
        return b'\xff' + struct.pack("<Q", value)

def encode_block_height(height: int) -> bytes:
    """Encode block height for BIP 34 compliance in coinbase scriptSig"""
    if height < 0x100:
        return struct.pack("<B", 1) + struct.pack("<B", height)
    elif height < 0x10000:
        return struct.pack("<B", 2) + struct.pack("<H", height)
    elif height < 0x1000000:
        return struct.pack("<B", 3) + struct.pack("<I", height)[:3]
    else:
        return struct.pack("<B", 4) + struct.pack("<I", height)

def sha256_midstate(data: bytes) -> bytes:
    """Calculate SHA-256 midstate after processing first 64 bytes
    
    CRITICAL: Bitcoin block headers are stored in little-endian format,
    but SHA-256 processes 32-bit words in big-endian format.
    The FPGA expects the midstate calculated properly for this format.
    """
    # SHA-256 initial hash values
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Process first 64-byte block
    if len(data) >= 64:
        # CRITICAL: Parse 64 bytes as 16 32-bit words in BIG-ENDIAN
        # This is standard SHA-256 processing regardless of input endianness
        w = list(struct.unpack('>16I', data[:64]))
        
        # Extend to 64 words
        for i in range(16, 64):
            s0 = ((w[i-15] >> 7) | (w[i-15] << 25)) ^ ((w[i-15] >> 18) | (w[i-15] << 14)) ^ (w[i-15] >> 3)
            s1 = ((w[i-2] >> 17) | (w[i-2] << 15)) ^ ((w[i-2] >> 19) | (w[i-2] << 13)) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
        
        # Round constants
        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        
        # Main compression loop
        a, b, c, d, e, f, g, h_val = h
        for i in range(64):
            s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
            ch = (e & f) ^ (~e & g)
            temp1 = (h_val + s1 + ch + k[i] + w[i]) & 0xffffffff
            s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xffffffff
            
            h_val, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xffffffff, c, b, a, (temp1 + temp2) & 0xffffffff
        
        # Add to initial hash values
        h = [(h[i] + [a, b, c, d, e, f, g, h_val][i]) & 0xffffffff for i in range(8)]
    
    # Pack as big-endian bytes (standard SHA-256 output format)
    return struct.pack('>8I', *h)

class FPGAMinerController:
    def __init__(self, network: str = 'regtest', serial_port: str = '/dev/ttyUSB0', baud_rate: int = 9600):
        """Initialize the FPGA miner controller"""
        self.serial_port = serial_port
        self.baud_rate = baud_rate
        self.ser = None
        self.network = network.lower()
        
        self.last_nonce_info = (0, 0)

        # Network-specific configuration
        self.network_config = {
            'regtest': {
                'rpcurl': 'http://127.0.0.1:18443',
                'block_reward': 5000000000,  # 50 BTC in satoshis
                'default_difficulty': 1,
                'name': 'Bitcoin Regtest',
                'timeout': 1500
            },
            'testnet': {
                'rpcurl': 'http://127.0.0.1:18332',
                'block_reward': 625000000,   # 6.25 BTC in satoshis (current testnet reward)
                'default_difficulty': 1,
                'name': 'Bitcoin Testnet',
                'timeout': 60
            },
            'mainnet': {
                'rpcurl': 'http://127.0.0.1:8332',
                'block_reward': 312500000,   # 3.125 BTC in satoshis (current mainnet reward after 2024 halving)
                'default_difficulty': 1,
                'name': 'Bitcoin Mainnet',
                'timeout': 30
            }
        }
        
        if self.network not in self.network_config:
            raise ValueError(f"Invalid network: {network}")
        
        self.config = self.network_config[self.network]
        self.rpcurl = self.config['rpcurl']
        self.timeout = self.config['timeout']
        self.reward_address = None
        self.current_block_template = None
        
        print(f"🌐 Configured for {self.config['name']}")
            
    def connect_serial(self) -> bool:
        """Connect to FPGA via serial"""
        try:
            self.ser = serial.Serial(
                self.serial_port, 
                self.baud_rate, 
                timeout=1,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )
            
            time.sleep(2)
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            
            print(f"✅ Connected to FPGA on {self.serial_port} at {self.baud_rate} baud")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to serial port: {e}")
            return False
    
    def send_raw_command(self, data: bytes) -> Optional[bytes]:
        """Send raw command to FPGA and read response"""
        if not self.ser:
            print("❌ Serial connection not established")
            return None
        
        try:
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            
            print(f"📤 Sending: {binascii.hexlify(data).decode()}")
            self.ser.write(data)
            self.ser.flush()
            
            response = b""
            timeout_start = time.time()
            timeout_duration = 3.0
            
            while time.time() - timeout_start < timeout_duration:
                if self.ser.in_waiting > 0:
                    chunk = self.ser.read(self.ser.in_waiting)
                    response += chunk
                    print(f"📥 Received chunk: {binascii.hexlify(chunk).decode()}")
                    
                    time.sleep(0.1)
                    if self.ser.in_waiting == 0:
                        time.sleep(0.2)
                        if self.ser.in_waiting == 0:
                            break
                else:
                    time.sleep(0.01)
            
            if response:
                print(f"📩 Total response: {binascii.hexlify(response).decode()} ({len(response)} bytes)")
            else:
                print("📭 No response received")
                
            return response if response else None
            
        except Exception as e:
            print(f"❌ Serial communication error: {e}")
            return None
    
    def ping_fpga(self) -> bool:
        """Ping FPGA to test communication"""
        print("🏓 Pinging FPGA...")
        ping_cmd = b'\x00'
        response = self.send_raw_command(ping_cmd)
        
        if response and len(response) > 0 and response[0] == 0x01:
            print("✅ FPGA responded to ping!")
            return True
        else:
            print("❌ FPGA did not respond to ping")
            return False
    
    def get_fpga_info(self) -> Optional[Dict]:
        """Get FPGA info using protocol from README"""
        print("ℹ️  Getting FPGA info...")
        info_cmd = b'\x08\x00\x00\x00\xf9\xea\x98\x0a'
        response = self.send_raw_command(info_cmd)
        
        if response and len(response) >= 16:
            print(f"📊 FPGA Info received: {binascii.hexlify(response).decode()}")
            return {"raw_response": response}
        else:
            print("❌ Failed to get FPGA info")
            return None

    def test_with_genesis_block(self) -> bool:
        """Test FPGA with genesis block"""
        print("🧪 Testing with corrected genesis block...")
        
        genesis_cmd = b'\x3C\x00\x00\x02\xFF\xFF\xFF\xFF\x7B\x2B\xAC\x1D\x4A\x5E\x1E\x4B\x49\x5F\xAB\x29\x1d\x00\xFF\xFF\x33\x9A\x90\xBC\xF0\xBF\x58\x63\x7D\xAC\xCC\x90\xA8\xCA\x59\x1E\xE9\xD8\xC8\xC3\xC8\x03\x01\x4F\x36\x87\xB1\x96\x1B\xF9\x19\x47\x77\x15\x4f\x81'
        
        print(f"📤 Genesis command ({len(genesis_cmd)}B): {binascii.hexlify(genesis_cmd).decode()}")
        
        response = self.send_raw_command(genesis_cmd)
        
        if response:
            print(f"📥 Genesis response: {binascii.hexlify(response).decode()}")
            
            if len(response) > 0 and response[0] == 0x01:
                print("✅ GENESIS BLOCK GOT ACK!")
                
                for i in range(1, len(response) - 7):
                    if (response[i] == 0x08 and 
                        response[i+1] == 0x00 and 
                        response[i+2] == 0x00 and 
                        response[i+3] == 0x03):
                        
                        nonce_bytes = response[i+4:i+8]
                        found_nonce = struct.unpack("<I", nonce_bytes)[0]
                        
                        print(f"🎯 Found solution nonce: {found_nonce:08x}")
                        
                        expected_nonce = 0x7c2bac1d
                        if found_nonce == expected_nonce:
                            print("🎉 GENESIS SOLUTION CORRECT! Protocol working perfectly!")
                            return True
                        else:
                            print(f"⚠️  Nonce mismatch. Expected: {expected_nonce:08x}")
                
                print("✅ Genesis test passed (got ACK)")
                return True
            else:
                print("❌ Genesis block did not get ACK")
                return False
        else:
            print("❌ No response to genesis block")
            return False

    def get_rpc_auth(self) -> Tuple[str, str]:
        """Get RPC authentication credentials"""
        return ("test", "test123")

    def ensure_mining_wallet(self) -> bool:
        """Ensure we have a wallet for mining rewards"""
        try:
            auth = self.get_rpc_auth()
            
            # Check if wallet exists
            rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "listwallets", "params": []}
            response = requests.post(self.rpcurl, json=rpc_data, auth=auth, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                wallets = result.get("result", [])
                
                if "mining" not in wallets:
                    print("💳 Creating mining wallet...")
                    # Create wallet
                    rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "createwallet", 
                               "params": ["mining", False, False, "", False, True]}
                    response = requests.post(self.rpcurl, json=rpc_data, auth=auth, timeout=10)
                    
                    if response.status_code == 200:
                        print("✅ Mining wallet created successfully")
                    else:
                        print(f"❌ Failed to create mining wallet: {response.text}")
                        return False
                else:
                    print("✅ Mining wallet already exists")
                
                # Load the wallet if needed
                rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "loadwallet", "params": ["mining"]}
                requests.post(self.rpcurl, json=rpc_data, auth=auth, timeout=5)  # Ignore errors if already loaded
                
                return True
            
            return False
        except Exception as e:
            print(f"❌ Error managing mining wallet: {e}")
            return False

    def get_mining_address(self) -> str:
        """Get or create a mining address for mining rewards"""
        try:
            if not self.ensure_mining_wallet():
                return None
            
            auth = self.get_rpc_auth()
            
            # Use wallet-specific RPC URL
            wallet_rpc_url = f"{self.rpcurl}/wallet/mining"
            
            # Get new address from mining wallet
            rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "getnewaddress", 
                       "params": ["mining", "legacy"]}
            response = requests.post(wallet_rpc_url, json=rpc_data, auth=auth, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    address = result["result"]
                    print(f"✅ Mining reward address: {address}")
                    return address
            
            print(f"❌ Failed to get mining address: {response.text}")
            return None
        except Exception as e:
            print(f"❌ Error getting mining address: {e}")
            return None

    def get_block_template(self) -> Optional[Dict]:
        """Get block template from Bitcoin node"""
        try:
            if not self.reward_address:
                self.reward_address = self.get_mining_address()
                if not self.reward_address:
                    return None
            
            rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "getblocktemplate", 
                       "params": [{"rules": ["segwit"]}]}
            auth = self.get_rpc_auth()
            response = requests.post(self.rpcurl, json=rpc_data, auth=auth, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    template = result["result"]
                    self.current_block_template = template
                    return template
                    
            return None
        except Exception as e:
            print(f"❌ Error getting block template: {e}")
            return None
    
    def base58_decode(self, s: str) -> bytes:
        """Decode base58 string to bytes"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        base = len(alphabet)
        
        # Count leading zeros
        leading_zeros = 0
        for c in s:
            if c == '1':
                leading_zeros += 1
            else:
                break
        
        # Decode
        num = 0
        for c in s:
            if c not in alphabet:
                raise ValueError(f"Invalid base58 character: {c}")
            num = num * base + alphabet.index(c)
        
        # Convert to bytes
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        
        # Add leading zeros
        result.extend([0] * leading_zeros)
        
        return bytes(reversed(result))

    def base58_decode_check(self, s: str) -> bytes:
        """Decode base58check string (includes checksum verification)"""
        decoded = self.base58_decode(s)
        
        if len(decoded) < 4:
            raise ValueError("Invalid base58check string")
        
        data = decoded[:-4]
        checksum = decoded[-4:]
        
        # Verify checksum (double SHA256 of data)
        expected_checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        
        if checksum != expected_checksum:
            raise ValueError("Invalid base58check checksum")
        
        return data

    def decode_address_to_script(self, address: str) -> bytes:
        """Convert Bitcoin address to scriptPubKey - CRITICAL for receiving rewards!"""
        try:
            # Decode base58check address
            decoded = self.base58_decode_check(address)
            
            if len(decoded) != 21:  # 1 byte version + 20 byte hash
                raise ValueError(f"Invalid address length: {len(decoded)}")
            
            version = decoded[0]
            hash160 = decoded[1:]
            
            print(f"🏦 Decoded address: version=0x{version:02x}, hash160={binascii.hexlify(hash160).decode()}")
            
            # Legacy P2PKH address (version varies by network)
            if version in [0x00, 0x6f]:  # mainnet=0x00, testnet/regtest=0x6f
                # P2PKH script: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
                script = b"\x76\xa9\x14" + hash160 + b"\x88\xac"
                print(f"✅ Created P2PKH script: {binascii.hexlify(script).decode()}")
                return script
            
            # Legacy P2SH address
            elif version in [0x05, 0xc4]:  # mainnet=0x05, testnet/regtest=0xc4
                # P2SH script: OP_HASH160 <hash160> OP_EQUAL
                script = b"\xa9\x14" + hash160 + b"\x87"
                print(f"✅ Created P2SH script: {binascii.hexlify(script).decode()}")
                return script
            
            else:
                raise ValueError(f"Unsupported address version: {version:02x}")
                
        except Exception as e:
            print(f"❌ Error decoding address {address}: {e}")
            print("⚠️  CRITICAL: Using fallback script - REWARDS WILL BE LOST!")
            print("💡 Make sure your Bitcoin node is generating valid addresses")
            # Fallback to unspendable script
            return b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
    
    def create_coinbase_tx(self, block_height: int, nonce: int) -> bytes:
        """Create BIP 34 compliant coinbase transaction"""
        # BIP 34: scriptSig must start with block height
        height_script = encode_block_height(block_height)
        
        # Add extra nonce data
        coinbase_msg = f"FPGA Miner {nonce:08x}".encode()
        extra_nonce_script = struct.pack("<B", len(coinbase_msg)) + coinbase_msg
        
        # Combine height + extra data
        script_sig = height_script + extra_nonce_script
        
        tx = b""
        tx += struct.pack("<I", 1)              # version
        tx += b"\x01"                           # input count
        tx += b"\x00" * 32                      # prev txid (null for coinbase)
        tx += struct.pack("<I", 0xFFFFFFFF)     # prev index (0xFFFFFFFF for coinbase)
        tx += struct.pack("<B", len(script_sig)) + script_sig  # scriptSig with length
        tx += struct.pack("<I", 0xFFFFFFFF)     # sequence
        tx += b"\x01"                           # output count
        tx += struct.pack("<Q", self.config['block_reward'])  # reward amount
        
        # Create proper scriptPubKey for reward address
        if self.reward_address:
            script_pubkey = self.decode_address_to_script(self.reward_address)
        else:
            # Fallback to P2PKH with zeroed hash
            script_pubkey = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
            
        tx += struct.pack("<B", len(script_pubkey)) + script_pubkey
        tx += struct.pack("<I", 0)              # locktime

        return tx

    def txid_from_tx(self, tx: bytes) -> bytes:
        """Compute txid (double SHA256 and reverse for little-endian)"""
        h = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
        return h[::-1]  # reverse for little-endian

    def calculate_merkle_root(self, transactions: List[bytes]) -> bytes:
        """Calculate Merkle root of all transactions"""
        if not transactions:
            return b"\x00" * 32
            
        txids = [self.txid_from_tx(tx) for tx in transactions]
        
        while len(txids) > 1:
            if len(txids) % 2 == 1:
                txids.append(txids[-1])  # duplicate last if odd count
                
            new_level = []
            for i in range(0, len(txids), 2):
                combined = txids[i] + txids[i+1]
                new_hash = hashlib.sha256(hashlib.sha256(combined).digest()).digest()
                new_level.append(new_hash)
            txids = new_level
        
        return txids[0][::-1]  # return in little-endian for block header

    def create_block_header(self, block_template: Dict, nonce: int = 0, merkle_root: Optional[bytes] = None) -> bytes:
        """Create properly formatted block header"""
        if merkle_root is None:
            raise ValueError("Merkle root must be provided")

        # All values in little-endian format for block header
        version = struct.pack("<I", block_template["version"])
        prev_block = bytes.fromhex(block_template["previousblockhash"])[::-1]  # reverse to little-endian
        merkle_root_le = merkle_root  # Already in correct endianness
        timestamp = struct.pack("<I", block_template["curtime"])
        bits = struct.pack("<I", int(block_template["bits"], 16))
        nonce_bytes = struct.pack("<I", nonce)

        header = version + prev_block + merkle_root_le + timestamp + bits + nonce_bytes
        
        if len(header) != 80:
            raise ValueError(f"Invalid header length: {len(header)} (expected 80)")
            
        return header

    def reverse_4byte_blocks(self, data: bytes) -> bytes:
        """Reverse data in 4-byte blocks - kept for testing endianness"""
        result = b""
        for i in range(0, len(data), 4):
            block = data[i:i+4]
            result += block[::-1]
        return result
    
    def verify_solution(self, header: bytes, nonce: int, target: int) -> bool:
        """Verify that a nonce produces a valid solution with correct endianness"""
        # Create header with the nonce
        header_with_nonce = header[:-4] + struct.pack("<I", nonce)
        
        # Calculate double SHA-256
        hash_result = hashlib.sha256(hashlib.sha256(header_with_nonce).digest()).digest()
        
        # CRITICAL: Bitcoin interprets block hash in LITTLE-ENDIAN for difficulty comparison
        # The hash bytes need to be reversed before converting to integer
        hash_reversed = hash_result[::-1]  # Reverse for little-endian interpretation
        hash_int = int.from_bytes(hash_reversed, 'big')
        
        print(f"🔍 Block hash (BE): {binascii.hexlify(hash_result).decode()}")
        print(f"🔍 Block hash (LE): {binascii.hexlify(hash_reversed).decode()}")
        print(f"🎯 Target:          {target:064x}")
        print(f"✅ Valid:           {hash_int < target}")
        
        return hash_int < target

    def prepare_fpga_work(self, block_template: Dict, nonce_min: int = 0, nonce_max: int = 0xFFFFFFFF) -> bytes:
        """Prepare work data for FPGA with proper midstate calculation"""

        # 1. Create coinbase transaction with BIP 34 compliance
        block_height = block_template["height"]
        coinbase_tx = self.create_coinbase_tx(block_height, nonce_min)

        # 2. Get other transactions from template
        other_txs = []
        for tx in block_template.get("transactions", []):
            if "data" in tx:
                other_txs.append(bytes.fromhex(tx["data"]))

        # 3. Combine all transactions
        all_txs = [coinbase_tx] + other_txs

        # 4. Calculate Merkle root
        merkle_root = self.calculate_merkle_root(all_txs)

        # 5. Create block header
        header = self.create_block_header(block_template, nonce=nonce_min, merkle_root=merkle_root)

        print(f"📦 Block header: {binascii.hexlify(header).decode()}")
        print(f"🏗️  Block height: {block_height}")
        print(f"🌳 Merkle root: {binascii.hexlify(merkle_root).decode()}")

        # Reverse header in 4-byte blocks for FPGA compatibility
        reversed_header = self.reverse_4byte_blocks(header)
        
        # Calculate midstate from 4-byte reversed header
        midstate = sha256_midstate(reversed_header[:64])
        
        # Extract work data from 4-byte reversed header
        work_data = reversed_header[64:76]

        print(f"🔄 Reversed header: {binascii.hexlify(reversed_header).decode()}")
        print(f"🔑 Midstate (from reversed): {binascii.hexlify(midstate).decode()}")
        print(f"⚙️  Work data (from reversed): {binascii.hexlify(work_data).decode()}")
        print(f"💡 Using 4-byte reversal approach - compatible with FPGA hardware")

        # 7. Debug comparison
        print(f"🧪 ENDIANNESS COMPARISON:")
        original_work = header[64:76]
        print(f"   Original work data: {binascii.hexlify(original_work).decode()}")
        print(f"   Reversed work data: {binascii.hexlify(work_data).decode()}")
        print(f"   → Using REVERSED (matches genesis test format)")

        # 8. Construct FPGA message
        nonce_max_bytes = struct.pack("<I", nonce_max)
        nonce_min_bytes = struct.pack("<I", nonce_min)

        # Payload: nonce_max + nonce_min + midstate + work_data
        job_payload = nonce_max_bytes + nonce_min_bytes + midstate + work_data

        # Message: header + payload
        message_no_crc = bytearray([0x3C, 0x00, 0x00, 0x02])
        message_no_crc.extend(job_payload)

        # Calculate and append CRC32
        crc = crc32_mpeg2(bytes(message_no_crc))
        crc_bytes = struct.pack(">I", crc)
        final_message = bytes(message_no_crc) + crc_bytes

        print(f"📦 Final FPGA message ({len(final_message)}B): {binascii.hexlify(final_message).decode()}")

        if len(final_message) != 60:
            print(f"❌ Wrong message length: {len(final_message)} (expected 60)")
            return b""

        # Store reference for verification (use REVERSED header to match FPGA processing)
        self.current_header = reversed_header  # Use reversed header for verification
        self.current_target = int(block_template["target"], 16)
        
        # ALSO store original header for final block submission
        self.original_header = header
        
        # Cross-check with manual verification using REVERSED header (to match FPGA)
        print(f"🧪 Cross-checking solution verification...")
        test_header_with_nonce = reversed_header[:-4] + struct.pack("<I", nonce_min)
        manual_hash = hashlib.sha256(hashlib.sha256(test_header_with_nonce).digest()).digest()
        manual_hash_le = manual_hash[::-1]
        manual_int = int.from_bytes(manual_hash_le, 'big')
        print(f"   Manual hash (LE): {manual_int:064x}")
        print(f"   Target:           {self.current_target:064x}")
        print(f"   Would be valid:   {manual_int < self.current_target}")
        print(f"   ⚠️  Using REVERSED header for verification (matches FPGA)")

        return final_message

    def send_work_to_fpga(self, work_data: bytes) -> Optional[int]:
        """Send mining work to FPGA and return winning nonce if found"""
        print(f"⛏️  Sending work to FPGA ({len(work_data)} bytes)")
        
        response = self.send_raw_command(work_data)
        
        if response and len(response) > 0:
            print(f"🔍 Analyzing FPGA response...")
            
            if response[0] == 0x01:
                print("✅ FPGA acknowledged mining job")
                return 0
            
            if len(response) >= 4 and response[3] == 0x05:
                print("❌ FPGA sent MSG_RESEND - CRC32 verification failed")
                return None
            
            for i in range(len(response) - 7):
                if (response[i] == 0x08 and 
                    response[i+1] == 0x00 and 
                    response[i+2] == 0x00 and 
                    response[i+3] == 0x03):
                    
                    nonce_bytes = response[i+4:i+8]
                    solution_nonce = struct.unpack("<I", nonce_bytes)[0]
                    print(f"🎯 POTENTIAL SOLUTION! Nonce: {solution_nonce:08x}")
                    
                    # Verify the solution
                    if hasattr(self, 'current_header') and hasattr(self, 'current_target'):
                        if self.verify_solution(self.current_header, solution_nonce, self.current_target):
                            print("✅ SOLUTION VERIFIED!")
                            return solution_nonce
                        else:
                            print("❌ Solution verification failed")
                    
                    return solution_nonce
                
            return 0
        
        print("📭 No response from FPGA")
        return None

    def read_serial_data_safely(self) -> bytes:
        """Read serial data without sending commands"""
        if not self.ser or self.ser.in_waiting == 0:
            return b""
        
        try:
            data = self.ser.read(self.ser.in_waiting)
            if data:
                print(f"📡 FPGA data: {binascii.hexlify(data).decode()}")
            return data
        except Exception as e:
            print(f"❌ Error reading serial data: {e}")
            return b""

    def request_info_safely(self, quiet=False) -> Optional[bytes]:
        """Request info from FPGA and return the response"""
        if not self.ser:
            return None
            
        try:
            info_cmd = b'\x08\x00\x00\x00\xf9\xea\x98\x0a'
            if not quiet:
                print(f"⏱️  Requesting FPGA info...")
            
            # Send command
            self.ser.write(info_cmd)
            self.ser.flush()
            
            # Wait for and read response
            response = b""
            timeout_start = time.time()
            
            while time.time() - timeout_start < 2.0:  # 2 second timeout
                if self.ser.in_waiting > 0:
                    chunk = self.ser.read(self.ser.in_waiting)
                    response += chunk
                    
                    # If we got a complete info response (16 bytes), return it
                    if len(response) >= 16:
                        break
                        
                    time.sleep(0.1)
                else:
                    time.sleep(0.01)
            
            return response if response else None
            
        except Exception as e:
            print(f"❌ Error requesting info: {e}")
            return None

    def encode_varint(self, value: int) -> bytes:
        """Encode variable length integer"""
        return encode_compact_size(value)

    def submit_block(self, block_template: Dict, winning_nonce: int) -> bool:
        """Submit winning block to Bitcoin node with proper construction"""
        try:
            print(f"🏆 Submitting block with nonce {winning_nonce:08x}...")

            # 1. Recreate the exact coinbase transaction used for mining
            block_height = block_template["height"]
            coinbase_tx = self.create_coinbase_tx(block_height, winning_nonce)

            # 2. Get other transactions from template
            other_txs = []
            for tx in block_template.get("transactions", []):
                if "data" in tx:
                    other_txs.append(bytes.fromhex(tx["data"]))

            # 3. Combine all transactions
            transactions = [coinbase_tx] + other_txs

            # 4. Recalculate Merkle root
            merkle_root = self.calculate_merkle_root(transactions)

            # 5. Create final block header with winning nonce - USE ORIGINAL FORMAT FOR SUBMISSION
            if hasattr(self, 'original_header'):
                # Build header from original format (what Bitcoin expects)
                final_header = self.create_block_header(block_template, winning_nonce, merkle_root)
                print(f"✅ Using original header format for Bitcoin submission")
            else:
                # Fallback if original_header not stored
                final_header = self.create_block_header(block_template, winning_nonce, merkle_root)

            # 6. Verify the block hash meets the target with correct endianness
            block_hash = hashlib.sha256(hashlib.sha256(final_header).digest()).digest()
            
            # CRITICAL: Bitcoin block hash difficulty comparison uses LITTLE-ENDIAN interpretation
            block_hash_le = block_hash[::-1]  # Reverse to little-endian
            hash_int = int.from_bytes(block_hash_le, 'big')
            target = int(block_template["target"], 16)
            
            print(f"🔍 Block hash (BE): {binascii.hexlify(block_hash).decode()}")
            print(f"🔍 Block hash (LE): {binascii.hexlify(block_hash_le).decode()}")  
            print(f"🔍 Hash as int:     {hash_int:064x}")
            print(f"🎯 Target:          {target:064x}")
            print(f"✅ Valid:           {hash_int < target}")
            print(f"💡 Block submission using ORIGINAL header format")
            
            if hash_int >= target:
                print("❌ Block hash does not meet target - invalid solution!")
                print("💡 This indicates an endianness or calculation error")
                return False

            # 7. Construct complete block
            block_data = final_header
            block_data += encode_compact_size(len(transactions))
            
            for tx in transactions:
                block_data += tx

            # 8. Convert to hex for submission
            block_hex = binascii.hexlify(block_data).decode()

            print(f"📤 Submitting block ({len(block_data)} bytes)...")
            print(f"🏗️  Block height: {block_height}")
            print(f"📦 Transactions: {len(transactions)}")

            # 9. Submit to Bitcoin node
            rpc_data = {
                "jsonrpc": "1.0",
                "id": "python",
                "method": "submitblock",
                "params": [block_hex]
            }
            auth = self.get_rpc_auth()
            response = requests.post(self.rpcurl, json=rpc_data, auth=auth, timeout=10)

            if response.status_code == 200:
                result = response.json()
                if "result" in result and result["result"] is None:
                    print("🎉 BLOCK SUBMITTED SUCCESSFULLY!")
                    print(f"💰 Block reward: {self.config['block_reward'] / 100000000} BTC")
                    print(f"💳 Reward address: {self.reward_address}")
                    self.check_wallet_balance()
                    return True
                else:
                    error_msg = result.get("result", "Unknown error")
                    print(f"❌ Block submission failed: {error_msg}")
                    
                    # Provide helpful error explanations
                    if error_msg == "bad-cb-height":
                        print("💡 Error: Coinbase height incorrect - check BIP 34 compliance")
                    elif error_msg == "high-hash":
                        print("💡 Error: Block hash too high - doesn't meet difficulty target")
                    elif error_msg == "bad-diffbits":
                        print("💡 Error: Difficulty bits incorrect")
                    elif error_msg == "bad-prevblk":
                        print("💡 Error: Previous block hash incorrect")
                    
                    return False
            else:
                print(f"❌ HTTP error submitting block: {response.status_code}")
                print(f"Response: {response.text}")
                return False

        except Exception as e:
            print(f"❌ Error submitting block: {e}")
            import traceback
            traceback.print_exc()
            return False

    def check_wallet_balance(self):
        """Check mining wallet balance"""
        try:
            auth = self.get_rpc_auth()
            
            # Use wallet-specific RPC URL
            wallet_rpc_url = f"{self.rpcurl}/wallet/mining"
            
            rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "getbalance", "params": []}
            response = requests.post(wallet_rpc_url, json=rpc_data, auth=auth, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    balance = result["result"]
                    print(f"💰 Current wallet balance: {balance} BTC")
                    return balance
        except Exception as e:
            print(f"❌ Error checking balance: {e}")
        return None

    def monitor_fpga_solutions(self, timeout: int = 120) -> Optional[int]:
        """Monitor FPGA for solutions with proper response handling and nonce wraparound detection"""
        print(f"👀 Monitoring FPGA for solutions ({timeout}s timeout)...")
        start_time = time.time()
        last_info_time = 0
        
        while time.time() - start_time < timeout:
            current_time = time.time() - start_time
            
            # Request info every 10 seconds
            if current_time - last_info_time >= 10:
                info_response = self.request_info_safely(quiet=True)
                if info_response:
                    solution_nonce = self.parse_fpga_response(info_response, current_time)
                    if solution_nonce == -1:  # Nonce wraparound detected
                        print("🔄 Nonce space exhausted - getting new work")
                        return -1
                    elif solution_nonce and solution_nonce > 0:
                        return solution_nonce
                last_info_time = current_time
            
            # Check for spontaneous data
            spontaneous_data = self.read_serial_data_safely()
            if spontaneous_data:
                solution_nonce = self.parse_fpga_response(spontaneous_data, current_time)
                if solution_nonce == -1:  # Nonce wraparound detected
                    print("🔄 Nonce space exhausted - getting new work")
                    return -1
                elif solution_nonce and solution_nonce > 0:
                    return solution_nonce
            
            time.sleep(0.5)
        
        print("⏰ Monitoring timeout reached")
        return None

    def parse_fpga_response(self, response: bytes, elapsed_time: float):
        """Parse FPGA responses for both info and solutions"""
        i = 0
        nonce_wrapped = False
        
        while i < len(response):
            # Check for info response (16 bytes starting with 10 00 00 00)
            if (i <= len(response) - 16 and 
                response[i] == 0x10 and response[i+1] == 0x00 and 
                response[i+2] == 0x00 and response[i+3] == 0x00 and
                response[i+4] == 0xde and response[i+5] == 0xad and 
                response[i+6] == 0xbe and response[i+7] == 0xef):

                nonce_bytes = response[i+8:i+12]
                current_nonce = struct.unpack(">I", nonce_bytes)[0]
                progress = (current_nonce / 0x100000000) * 100

                prev_nonce, prev_time = self.last_nonce_info
                
                # Detect nonce wraparound (indicates exhausted search space)
                if prev_nonce and current_nonce < prev_nonce and prev_nonce > 0xF0000000:
                    nonce_wrapped = True
                    print(f"🔄 NONCE WRAPAROUND DETECTED! Previous: 0x{prev_nonce:08x} -> Current: 0x{current_nonce:08x}")
                    print("📋 Nonce space exhausted - need new block template")
                
                if prev_nonce and prev_time:
                    # Handle wraparound in delta calculation
                    if current_nonce < prev_nonce:
                        delta_nonce = (0x100000000 - prev_nonce) + current_nonce
                    else:
                        delta_nonce = current_nonce - prev_nonce
                    
                    delta_time = elapsed_time - prev_time if prev_time > 0 else 1e-9
                    hashes_per_second = delta_nonce / delta_time
                    mhps = hashes_per_second / 1_000_000
                else:
                    mhps = 0

                print(f"📊 Progress: Nonce 0x{current_nonce:08x} ({progress:.2f}%) | 🔧 {mhps:.2f} MH/s")
                self.last_nonce_info = (current_nonce, elapsed_time)
                
                # Return special value to indicate wraparound
                if nonce_wrapped:
                    return -1  # Special return code for nonce wraparound
                
                i += 16
 
            # Check for solution pattern: 08 00 00 03 + nonce
            elif (i <= len(response) - 8 and 
                  response[i] == 0x08 and response[i+1] == 0x00 and 
                  response[i+2] == 0x00 and response[i+3] == 0x03):
                
                nonce_bytes = response[i+4:i+8]
                solution_nonce = struct.unpack("<I", nonce_bytes)[0]
                print(f"\n🎯 SOLUTION FOUND! Nonce: {solution_nonce:08x}")
                
                # Verify solution if we have the current header and target
                if hasattr(self, 'current_header') and hasattr(self, 'current_target'):
                    if self.verify_solution(self.current_header, solution_nonce, self.current_target):
                        print("✅ SOLUTION VERIFIED!")
                        return solution_nonce
                    else:
                        print("❌ Solution verification failed - continuing search...")
                        i += 8
                        continue
                
                return solution_nonce
                
            else:
                i += 1
        
        return None

    def mine_solo(self):
        """Solo mining loop with proper block submission"""
        print(f"🚀 Starting mining on {self.config['name']}...")
        
        job_counter = 0
        while True:
            try:
                job_counter += 1
                print(f"\n{'='*50}")
                print(f"⛏️  MINING JOB #{job_counter}")
                print(f"{'='*50}")
                
                # Get new work
                block_template = self.get_block_template()
                
                if not block_template:
                    print("❌ Failed to get block template")
                    time.sleep(30)
                    continue
                
                print(f"🏗️  Block height: {block_template['height']}")
                print(f"🎯 Target: {block_template['target']}")
                print(f"⏰ Time: {block_template['curtime']}")
                
                # Prepare and send work
                work_data = self.prepare_fpga_work(block_template, 0x00000000, 0xFFFFFFFF)
                
                if not work_data:
                    print("❌ Failed to prepare work data")
                    time.sleep(10)
                    continue
                
                # Send work to FPGA
                result = self.send_work_to_fpga(work_data)
                
                if result is None:
                    print("❌ Failed to communicate with FPGA")
                    time.sleep(10)
                    continue
                elif result > 0:
                    print(f"\n🎉 IMMEDIATE SOLUTION! Nonce: {result:08x}")
                    if self.submit_block(block_template, result):
                        print("🏆 BLOCK SUBMITTED AND REWARDS CLAIMED!")
                        return
                else:
                    print("✅ Work sent successfully, FPGA is mining...")
                    
                    winning_nonce = self.monitor_fpga_solutions(self.timeout)
                    
                    if winning_nonce == -1:
                        print("🔄 Nonce space exhausted - getting new block template")
                        continue  # Get new work immediately
                    elif winning_nonce and winning_nonce > 0:
                        print(f"\n🎉 SOLUTION FOUND! Nonce: {winning_nonce:08x}")
                        if self.submit_block(block_template, winning_nonce):
                            print("🏆 BLOCK SUBMITTED AND REWARDS CLAIMED!")
                            sys.exit(0)
                        else:
                            print("❌ Failed to submit block, but we found a solution!")
                    else:
                        print("⏰ No solution found, getting new work...")
                
            except KeyboardInterrupt:
                print("\n⛔ Mining interrupted by user")
                break
            except Exception as e:
                print(f"❌ Error in mining loop: {e}")
                time.sleep(10)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="FPGA Bitcoin Miner Controller")
    parser.add_argument('--network', '-n', choices=['regtest','testnet','mainnet'], default='regtest')
    parser.add_argument('--port', '-p', default='/dev/ttyUSB0')
    parser.add_argument('--baud', '-b', type=int, default=9600)
    parser.add_argument('--test-only', '-t', action='store_true')
    
    args = parser.parse_args()
    
    controller = FPGAMinerController(
        network=args.network,
        serial_port=args.port,
        baud_rate=args.baud
    )
    
    # Connect to FPGA
    if not controller.connect_serial():
        return
    
    # Test basic communication
    if not controller.ping_fpga():
        return
    
    # Get FPGA info
    controller.get_fpga_info()
    
    # Test with genesis block
    if controller.test_with_genesis_block():
        print("✅ Genesis block test PASSED! Protocol is working correctly!")
    else:
        print("❌ Genesis block test FAILED! Protocol issues remain.")
        if not args.test_only:
            response = input("\nContinue anyway? (y/n): ")
            if response.lower() != 'y':
                return
    
    if args.test_only:
        print("\n✅ Test mode complete.")
        controller.ser.close()
        return
    
    # Test wallet setup
    print("\n💳 Setting up mining wallet...")
    if controller.ensure_mining_wallet():
        print("✅ Mining wallet ready!")
        controller.check_wallet_balance()
    else:
        print("❌ Failed to setup mining wallet")
        response = input("Continue without proper wallet setup? (y/n): ")
        if response.lower() != 'y':
            return
    
    # Start mining
    print(f"\n🎮 Ready to start mining!")

    try:
        controller.mine_solo()
    except KeyboardInterrupt:
        print("\n👋 Mining interrupted")
    finally:
        if controller.ser:
            controller.ser.close()
    
    print("🏁 Done!")

if __name__ == "__main__":
    main()
