import re
import threading

class GetTheLoot:
    def __init__(self):
        # Thread lock to prevent race conditions during concurent file I/O and decryption
        self._lock = threading.Lock()

    def decode_payload_to_file(self, hex_payload: str, ghidra_text: str, output_file: str) -> None:
        with self._lock:
            # Use a dictionary to map the exact index to the exact key
            keys = {}
            
            for line in ghidra_text.splitlines():
                # 1. Handle Index 0 (The pointer dereference *DAT_...)
                if '*DAT_' in line and '^' in line:
                    match = re.search(r'\^ (0x[0-9a-fA-F]+|\d+)\);', line)
                    if match:
                        val = match.group(1)
                        keys[0] = int(val, 16) if val.startswith('0x') else int(val)
                
                # 2. Handle all other indices (pcVar1[index])
                else:
                    match = re.search(r'\[(0x[0-9a-fA-F]+|\d+)\] = .*?\^ (0x[0-9a-fA-F]+|\d+)\);', line)
                    if match:
                        idx_str = match.group(1)
                        key_str = match.group(2)
                        
                        # Convert both index and key to integers
                        idx = int(idx_str, 16) if idx_str.startswith('0x') else int(idx_str)
                        key = int(key_str, 16) if key_str.startswith('0x') else int(key_str)
                        keys[idx] = key
            
            payload_bytes = bytearray.fromhex(hex_payload)
            decoded = bytearray()
            
            # Perform the Inline XOR decryption using exact indices
            for i in range(len(payload_bytes)):
                if i in keys:
                    decoded.append(payload_bytes[i] ^ keys[i])
                else:
                    # If a key is missing for some reason, append the raw byte
                    decoded.append(payload_bytes[i])
            
            with open(output_file, 'wb') as f:
                f.write(decoded)
            
            print(f"[+] Successfully decrypted {len(decoded)} bytes.")
            print(f"[+] Raw shellcode saved to: {output_file}")

if __name__ == "__main__":
    #shellcode (without tail)
    hex_payload = ""
    
    # func decompiled
    ghidra_text = """
    
    """
    
    decoder = GetTheLoot()
    decoder.decode_payload_to_file(hex_payload, ghidra_text, "decrypted_shellcode.bin")
