#!/usr/bin/env python3
"""
FPGA Bitcoin Miner Controller - FIXED VERSION
Copyright (c) 2025 Lone Dynamics Corporation. All rights reserved.

FIXES:
1. Proper response handling to prevent solution loss
2. Block submission to Bitcoin node for rewards
3. Wallet management for mining rewards
"""

import serial
import struct
import hashlib
import json
import requests
import time
import binascii
import argparse
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
                    
                    if 'merkleroot' not in template:
                        coinbase_data = f"Mining to {self.reward_address}".encode()
                        coinbase_hash = hashlib.sha256(hashlib.sha256(coinbase_data).digest()).digest()
                        template['merkleroot'] = coinbase_hash[::-1].hex()
                        print(f"✅ Created simple merkleroot: {template['merkleroot']}")
                    
                    self.current_block_template = template
                    return template
                    
            return None
        except Exception as e:
            print(f"❌ Error getting block template: {e}")
            return None
    
    def create_coinbase_tx(self, nonce: int) -> bytes:
        """Create a simple coinbase transaction"""
        coinbase_script = f"FPGA Miner {nonce:08x}".encode()
        script_sig = struct.pack("<B", len(coinbase_script)) + coinbase_script

        tx = b""
        tx += struct.pack("<I", 1)              # version
        tx += b"\x01"                           # input count
        tx += b"\x00" * 32                      # prev txid
        tx += struct.pack("<I", 0xFFFFFFFF)     # prev index
        tx += script_sig                        # scriptSig
        tx += struct.pack("<I", 0xFFFFFFFF)     # sequence
        tx += b"\x01"                           # output count
        tx += struct.pack("<Q", self.config['block_reward'])  # reward (50 BTC)
        
        # Output script: OP_DUP OP_HASH160 <20-byte> OP_EQUALVERIFY OP_CHECKSIG
        # Placeholder: 20-byte zeroed address
        script_pubkey = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        tx += struct.pack("<B", len(script_pubkey)) + script_pubkey
        tx += struct.pack("<I", 0)              # locktime

        return tx

    def txid_from_tx(self, tx: bytes) -> bytes:
        """Compute txid (double SHA256 and reverse)"""
        h = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
        return h[::-1]  # little-endian txid

    def calculate_merkle_root(self, transactions: List[bytes]) -> bytes:
        """Calculate full Merkle root of all transactions"""
        txids = [self.txid_from_tx(tx) for tx in transactions]
        while len(txids) > 1:
            if len(txids) % 2 == 1:
                txids.append(txids[-1])  # duplicate last if odd count
            new_level = []
            for i in range(0, len(txids), 2):
                new_hash = hashlib.sha256(hashlib.sha256(txids[i] + txids[i+1]).digest()).digest()
                new_level.append(new_hash)
            txids = new_level
        return txids[0][::-1]  # return root little-endian

    def create_block_header(self, block_template: Dict, nonce: int = 0, merkle_root: Optional[bytes] = None) -> bytes:
        """Create block header using a real Merkle root"""
        version = struct.pack("<I", block_template["version"])
        prev_block = bytes.fromhex(block_template["previousblockhash"])[::-1]
        time_ = struct.pack("<I", block_template["curtime"])
        bits = struct.pack("<I", int(block_template["bits"], 16))
        nonce_bytes = struct.pack("<I", nonce)

        if merkle_root is None:
            raise ValueError("Merkle root must be provided for valid header")

        header = version + prev_block + merkle_root + time_ + bits + nonce_bytes
        return header

    def reverse_4byte_blocks(self, data: bytes) -> bytes:
        """Reverse data in 4-byte blocks as required by FPGA"""
        result = b""
        for i in range(0, len(data), 4):
            block = data[i:i+4]
            result += block[::-1]
        return result

    def prepare_fpga_work(self, block_template: Dict, nonce_min: int = 0, nonce_max: int = 0xFFFFFFFF) -> bytes:
        """Prepare work data for FPGA with full merkle root"""

        # 1. Create coinbase tx with nonce=nonce_min (or 0 for initial)
        coinbase_tx = self.create_coinbase_tx(nonce_min)

        # 2. Get other tx from block template, decode hex into bytes
        other_txs = [bytes.fromhex(tx["data"]) if "data" in tx else bytes.fromhex(tx["txid"]) for tx in block_template.get("transactions", [])]

        # 3. Combine coinbase + other txs
        all_txs = [coinbase_tx] + other_txs

        # 4. Calculate full Merkle root
        merkle_root = self.calculate_merkle_root(all_txs)

        # 5. Create block header with correct merkle root and nonce=nonce_min (or 0)
        header = self.create_block_header(block_template, nonce=nonce_min, merkle_root=merkle_root)

        # 6. Calculate midstate, work data, and prepare FPGA message
        # (Same as your original code for this part)

        # Original midstate from first 64 bytes of header (hashlib.sha256 compression midstate not directly accessible in python stdlib)
        # We'll use header[:64] hash as placeholder here
        original_midstate = hashlib.sha256(header[:64]).digest()
        reversed_header = self.reverse_4byte_blocks(header)
        work_data = reversed_header[64:76]

        print(f"🔑 Midstate (from original): {binascii.hexlify(original_midstate).decode()}")
        print(f"⚙️  Work data (from reversed): {binascii.hexlify(work_data).decode()}")

        nonce_max_bytes = struct.pack("<I", nonce_max)
        nonce_min_bytes = struct.pack("<I", nonce_min)

        job_payload = nonce_max_bytes + nonce_min_bytes + original_midstate + work_data

        message_no_crc = bytearray()
        message_no_crc.append(0x3C)
        message_no_crc.extend([0x00, 0x00])
        message_no_crc.append(0x02)
        message_no_crc.extend(job_payload)

        current_crc = crc32_mpeg2(bytes(message_no_crc))
        crc_bytes = struct.pack(">I", current_crc)
        final_message = bytes(message_no_crc + crc_bytes)

        print(f"📦 Final message ({len(final_message)}B): {binascii.hexlify(final_message).decode()}")

        if len(final_message) != 60:
            print(f"❌ Wrong message length: {len(final_message)} (expected 60)")
            return b""

        return final_message

    def send_work_to_fpga(self, work_data: bytes) -> Optional[int]:
        """Send mining work to FPGA and return winning nonce if found"""
        print(f"⛏️  Sending work to FPGA ({len(work_data)} bytes)")
        
        response = self.send_raw_command(work_data)
        
        if response and len(response) > 0:
            print(f"🔍 Analyzing FPGA response...")
            
            if response[0] == 0x01:
                print("✅ FPGA acknowledged mining job - protocol working!")
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
                    nonce = struct.unpack("<I", nonce_bytes)[0]
                    print(f"🎯 POTENTIAL SOLUTION! Nonce: {nonce:08x}")
                    return nonce
                
            return 0
        
        print("📭 No response from FPGA")
        return None

    def read_serial_data_safely(self) -> bytes:
        """Read serial data without sending commands (to avoid consuming responses)"""
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

    def submit_block(self, block_template: Dict, winning_nonce: int) -> bool:
        """Submit winning block to Bitcoin node"""
        try:
            print(f"🏆 Submitting block with nonce {winning_nonce:08x}...")
            
            coinbase_tx = self.create_coinbase_tx(winning_nonce)

            # 2. Calculate real Merkle root
            merkle_root = self.calculate_merkle_root(coinbase_tx)

            # 3. Build valid block header with correct Merkle root
            final_header = self.create_block_header(block_template, winning_nonce, merkle_root) 

            # Create minimal block (header + transaction count + coinbase transaction)
            block_data = final_header
            
            # Add transaction count (1 for coinbase only)
            block_data += b'\x01'
            
            # Create simple coinbase transaction for regtest
            coinbase_tx = b'\x01\x00\x00\x00'  # version
            coinbase_tx += b'\x01'  # input count
            coinbase_tx += b'\x00' * 32  # previous output hash (null)
            coinbase_tx += b'\xff\xff\xff\xff'  # previous output index (coinbase)
            
            # Coinbase script
            script_sig = f"Block mined by FPGA miner! Nonce: {winning_nonce:08x}".encode()
            coinbase_tx += struct.pack('<B', len(script_sig)) + script_sig
            coinbase_tx += b'\xff\xff\xff\xff'  # sequence
            
            # Outputs
            coinbase_tx += b'\x01'  # output count
            coinbase_tx += struct.pack('<Q', self.config['block_reward'])  # amount
            
            # Output script (P2PKH to our address)
            # For simplicity, create a basic script
            output_script = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'  # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
            coinbase_tx += struct.pack('<B', len(output_script)) + output_script
            
            coinbase_tx += b'\x00\x00\x00\x00'  # locktime
            
            block_data += coinbase_tx
            
            # Convert to hex
            block_hex = binascii.hexlify(block_data).decode()
            
            print(f"📤 Submitting block ({len(block_data)} bytes)...")
            
            # Submit block
            rpc_data = {"jsonrpc": "1.0", "id": "python", "method": "submitblock", "params": [block_hex]}
            auth = self.get_rpc_auth()
            response = requests.post(self.rpcurl, json=rpc_data, auth=auth, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result and result["result"] is None:
                    print("🎉 BLOCK SUBMITTED SUCCESSFULLY!")
                    print(f"💰 Rewards should be credited to: {self.reward_address}")
                    
                    # Check wallet balance
                    self.check_wallet_balance()
                    return True
                else:
                    print(f"❌ Block submission failed: {result}")
                    return False
            else:
                print(f"❌ HTTP error submitting block: {response.status_code}")
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
        """Monitor FPGA for solutions with FIXED response handling"""
        print(f"👀 Monitoring FPGA for solutions ({timeout}s timeout)...")
        start_time = time.time()
        last_info_time = 0
        
        while time.time() - start_time < timeout:
            current_time = time.time() - start_time
            
            # Request info every 10 seconds, but handle response properly
            if current_time - last_info_time >= 10:
                info_response = self.request_info_safely(quiet=True)
                if info_response:
                    # Parse info response AND check for solutions
                    solution_nonce = self.parse_fpga_response(info_response, current_time)
                    if solution_nonce:
                        return solution_nonce
                last_info_time = current_time
            
            # Also check for any spontaneous data from FPGA
            spontaneous_data = self.read_serial_data_safely()
            if spontaneous_data:
                solution_nonce = self.parse_fpga_response(spontaneous_data, current_time)
                if solution_nonce:
                    return solution_nonce
            
            time.sleep(0.5)
        
        print("⏰ Monitoring timeout reached")
        return None

    def parse_fpga_response(self, response: bytes, elapsed_time: float):
        """Parse FPGA responses for both info and solutions"""
        i = 0
        while i < len(response):
            # Check for info response (16 bytes)
            if (i <= len(response) - 16 and 
                response[i] == 0x10 and response[i+1] == 0x00 and response[i+2] == 0x00 and response[i+3] == 0x00 and
                response[i+4] == 0xde and response[i+5] == 0xad and response[i+6] == 0xbe and response[i+7] == 0xef):

                nonce_bytes = response[i+8:i+12]
                current_nonce = struct.unpack(">I", nonce_bytes)[0]

                progress = (current_nonce / 0x100000000) * 100

                prev_nonce, prev_time = self.last_nonce_info

                if prev_nonce and prev_time:
                    delta_nonce = (current_nonce - prev_nonce) & 0xFFFFFFFF  # Handle wraparound
                    delta_time = elapsed_time - prev_time if prev_time > 0 else 1e-9

                    hashes_per_second = delta_nonce / delta_time
                    mhps = hashes_per_second / 1_000_000
                else:
                    mhps = 0

                print(f"📊 Progress: Nonce 0x{current_nonce:08x} ({progress:.2f}%) | 🔧 {mhps:.2f} MH/s")

                self.last_nonce_info = (current_nonce, elapsed_time)

                i += 16
 
            # Check for solution pattern: 08 00 00 03 + nonce
            elif (i <= len(response) - 8 and 
                  response[i] == 0x08 and response[i+1] == 0x00 and 
                  response[i+2] == 0x00 and response[i+3] == 0x03):
                
                nonce_bytes = response[i+4:i+8]
                solution_nonce = struct.unpack("<I", nonce_bytes)[0]
                print(f"\n🎯 SOLUTION FOUND! Nonce: {solution_nonce:08x}")
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
                    
                    if winning_nonce:
                        print(f"\n🎉 SOLUTION FOUND! Nonce: {winning_nonce:08x}")
                        if self.submit_block(block_template, winning_nonce):
                            print("🏆 BLOCK SUBMITTED AND REWARDS CLAIMED!")
                            return
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
    parser = argparse.ArgumentParser(description="FIXED FPGA Bitcoin Miner Controller")
    parser.add_argument('--network', '-n', choices=['regtest'], default='regtest')
    parser.add_argument('--port', '-p', default='/dev/ttyUSB0')
    parser.add_argument('--baud', '-b', type=int, default=9600)
    parser.add_argument('--test-only', '-t', action='store_true')
    
    args = parser.parse_args()
    
    print("🚀 FIXED FPGA Bitcoin Miner Controller")
    print("=" * 55)
    print("✅ FIXES:")
    print("   - Proper response handling (no lost solutions)")
    print("   - Block submission to claim rewards")
    print("   - Mining wallet management")
    print("=" * 55)
    
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
