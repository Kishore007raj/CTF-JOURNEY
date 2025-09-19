# CTF Starter Pack Plan

**One-line plan:**
Start with Linux & scripting + enumeration → learn 1 domain at a time (Web → Crypto → Forensics → Pwn/Reverse) → practice small challenges daily → join a beginner CTF or team within **4–6 weeks**.

---

## 🎯 Concrete beginner priorities (in order)

1. **Linux + terminal basics** — file ops, permissions, processes, redirection
2. **Python scripting** — small parsing/automation scripts
3. **Enumeration & recon** — how to gather info fast
4. **Web basics** — HTTP, cookies, forms
5. **Binary basics & reversing** — reading assembly, running with GDB (intro level)
6. **Crypto & encodings** — base64/hex/xor
7. **Forensics / stego** — images, pcaps
8. **Pwn / exploitation** — buffer overflow (later, after comfort with binaries)

---

## 2-Month beginner schedule

**Daily time:** \~1.5–3 hrs (adapt to college hours)

### Week 0 — Setup

* Install: WSL (or Linux VM), Python3, Git.
* Install tools: `nmap`, `netcat` (`nc`), `python3-pip`, `binwalk`, `exiftool`, `gdb`, Ghidra (or `radare2`).
* Create a folder `~/ctf` and a git repo for notes.

### Week 1 — Linux + Scripting (Day 2–7)

* Learn: `ls`, `cd`, `chmod`, `ps`, `grep`, `awk`, `sed`, `tar`, `ssh`, `scp`.
* Write 5 tiny Python scripts:

  * read file
  * parse lines
  * regex find
  * download URL
  * run a command and parse output
* Practice: OverTheWire — **Bandit** (first 5 levels).

### Week 2 — Recon & Enumeration

* Tools: `nmap` (basic scans), `ffuf`/`gobuster` (directory fuzzing), `netcat`.
* Learn: `nmap` basics, directory brute-forcing, reading `robots.txt`, basics of DNS/subdomain discovery.
* Practice: TryHackMe beginner CTF rooms.

### Week 3 — Web basics

* Learn: HTTP basics, cookies/sessions, common vulns (SQLi, XSS, file upload). Burp Suite workflow.
* Tools: Burp Suite Community or browser dev tools.
* Practice: simple SQLi / XSS challenges on picoCTF or TryHackMe web rooms. Use `sqlmap` only to learn how payloads look.

### Week 4 — Crypto & Encodings

* Learn: base64, hex, ROT, XOR, simple RSA ideas. Use CyberChef frequently.
* Practice: picoCTF crypto problems; write one writeup per solved challenge.

### Week 5 — Forensics & Stego

* Tools: `strings`, `binwalk`, `exiftool`, `steghide`, `pngcheck`.
* Practice: Solve 5 stego/forensics problems (VulnHub or CTFlearn).

### Week 6–7 — Intro to Binaries and Reversing

* Learn assembly basics (x86\_64), run binaries with `gdb`, use `objdump -d`.
* Practice: very easy pwnable.kr problems or beginner reversing on Crackmes.one.

### Week 8 — Practice CTF + Team Play

* Join a beginner CTF (picoCTF, local college event, or CTFtime beginner-friendly event).
* Use notes/scripts, split tasks (you: web; teammate: pwn), and write at least **3 short writeups**.

---

## 🧰 Must-install tools & quick commands

*Use WSL/Ubuntu or a Kali VM*

**Install core system packages**

```bash
sudo apt update && sudo apt install -y git python3 python3-pip net-tools nmap gcc gdb
```

**Useful Python packages**

```bash
pip3 install pwntools ropper capstone
```

**Recon & quick commands**

```bash
nmap -sC -sV -oA scan 10.10.10.10      # basic nmap scan w/ scripts and version
python3 -m http.server 8000            # quick file serving
nc -lvnp 9001                          # netcat reverse shell listener
strings -n 8 binary | less             # strings on binary
binwalk -e file.png                    # extract files from image
```

---

## 🧠 How to approach a single challenge (repeatable checklist)

1. Read the challenge text **twice**. Note inputs/outputs and any files.
2. Enumerate: `nmap` for services / `strings` for files.
3. Try obvious transforms: base64/hex/rot/xor with CyberChef or small scripts.
4. Search the web for specific error messages or hints **only if allowed**.
5. Automate repetitive parts with a tiny script.
6. If stuck 30–60 mins, mark it, move to another challenge; come back later.
7. Write a **5–10 line** note describing how you eventually solved it — helps future you.

---

## 🧑‍🤝‍🧑 CTF Team roles

1. Recon / Enumeration
2. Web Exploitation
3. Pwn / Exploit Developer
4. Reverse Engineer
5. Crypto / Math
6. Forensics / Stego
7. OSINT / Reconnaissance
8. Misc / DevOps / Infrastructure
9. Scripting / Automation
10. Scoreboard / Triage / Coordination (Team Lead)
11. Writeups / Documentation

> Tip: In small teams one person may do many roles; in bigger teams you specialize.

---

## 🧩 CTF challenge categories / themes

* Web
* Pwn / Binary Exploitation
* Reverse Engineering
* Crypto
* Forensics
* Steganography
* OSINT / Recon
* Miscellaneous / Programming
* Hardware / IoT (rare for beginners)
* Mobile
* Networking
* Binary Exploit Challenges (pwnable services)
* King of the Hill / Attack-Defend

---

## 👀 How to pick your role (practical)

* Like puzzles & reading code → **Reverse + Pwn**
* Like web dev & HTTP → **Web**
* Like math & reasoning → **Crypto**
* Like detective work (logs/networks) → **Forensics + Networking**
* Like automating tasks → **Scripting/Tools**
  **Pick 1 primary and 1 secondary role.** Focus: **70% primary, 30% secondary**.

---

## 📝 How to keep notes + build a cheat repo

**Suggested repo structure**

```
notes/                # short commands, tricks
scripts/              # reusable parsing & exploitation scripts
writeups/<ctf-name>/<challenge>.md   # writeups
```

* Every solved challenge → **1 writeup** (commands, thought process, final flag). Even small ones.

---

## 🔁 Daily practice routine (1–2 hours)

* **15 min:** read a short tutorial or watch 1 video.
* **60 min:** solve 1–2 easy challenges (web/crypto/forensics).
* **15 min:** update notes and a short writeup.
* **Weekend:** 3–4 hour practice CTF or redo past writeups.

---

## 🧩 Where to practice (beginner friendly)

* **Beginner platforms:** OverTheWire, picoCTF, TryHackMe (free rooms)
* **Intermediate:** HackTheBox, CTFlearn
* **Advanced:** pwnable.kr, CSAW archives, CTFtime.org competitions
* **Learning resources:**

  * LiveOverflow (YouTube) — pwn & reversing
  * ippsec (YouTube) — HackTheBox walkthroughs
  * CryptoHack — crypto-only practice

---

## ⚠️ Mental game & time management

* Don’t try to learn everything at once. One domain at a time.
* If stuck: leave a breadcrumb for teammates, move on, come back later.
* Keep a growth mindset — **writeups** are how you level up fast.

---

## ✅ CTF playbook (the day of the event)

* **Before event:** sync tools, clone your `~/ctf` repo, ensure Burp and Ghidra open.
* **First hour:** fast enumeration on all targets; assign tasks.
* Aim to solve **2–4 easy** challenges for morale.
* Keep notes in a shared Google Doc or repo.
* **After:** write 3 short public writeups (learning & resume fodder).

---

## 🛠️ Core skills you need

1. **Linux & Scripting** — Bash, quick Python (pwntools), automation
2. **Networking** — TCP/IP, `nmap`, `netcat`, Wireshark, `tcpdump`
3. **Web Exploitation** — SQLi, XSS, file upload bypass, Burp Suite, `ffuf`
4. **Cryptography** — classical ciphers, hash cracking, XOR, CyberChef, Hashcat
5. **Binary Exploitation (pwn)** — buffer overflows, shellcode basics, `gdb`, `pwntools`
6. **Reverse Engineering** — static/dynamic analysis, Ghidra/IDA/radare2
7. **Forensics** — file carving, metadata, steganography, `binwalk`, `strings`, `exiftool`
8. **OSINT** — Google dorks, WHOIS, public repo search

---

## Short checklist you can copy/paste

```text
# Setup
- [ ] Install WSL or Linux VM
- [ ] Install Python3 & Git
- [ ] Create ~/ctf and init git repo

# Week-by-week
- [ ] Week 1: Bandit levels 1-5, 5 tiny Python scripts
- [ ] Week 2: nmap basics, ffuf/gobuster, TryHackMe recon rooms
- [ ] Week 3: HTTP, Burp, basic SQLi/XSS practice
- [ ] Week 4: Crypto basics, CyberChef, picoCTF crypto
- [ ] Week 5: Forensics tools, solve 5 stego problems
- [ ] Week 6-7: Intro reversing: gdb, objdump, easy crackmes
- [ ] Week 8: Join beginner CTF, write 3 writeups
```

---

If you want, I can save this as a Markdown file named **`CTF-Starter-Plan.md`** and provide it for download — tell me the filename you prefer.
