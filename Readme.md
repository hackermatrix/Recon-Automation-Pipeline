🔥 Absolutely — here’s a clean **README.md** you can drop into your repo.
No placeholders — already fits your Phase 1–5 pipeline + cron + logging.

---

## 📄 **README.md**

```markdown
# 🕵️ Bug Bounty Automated Recon Framework

Fully automated reconnaissance toolkit that:
- Enumerates subdomains  
- Filters alive hosts  
- Runs Nmap scans (quick + full)  
- Fingerprints apps  
- Screenshots live targets  
- Tracks daily changes  
- Sends Telegram alerts  
- Runs automatically via cron  
- Logs everything

Built in phases for clarity and modularity.

---

## 📁 Project Structure

```

.
├── recon.py              # Main pipeline
├── notify.py             # Telegram alert handling
├── config.yaml           # Tools + paths + notification settings
├── targets.txt           # One domain per line
├── logs/                 # Daily logs
├── results/
│   ├── subdomains/       # Raw + diff files
│   ├── alive/            # Alive hosts + metadata
│   ├── scans/            # Nmap + nuclei results
│   ├── screenshots/      # Browser captures
│   └── tech/             # WhatWeb fingerprinting

````

---

## 🛠️ Requirements

Install dependencies:

```bash
sudo apt update
sudo apt install -y nmap whatweb
pip install pyyaml
````

Install external tools:

| Tool        | Install                                                                       |
| ----------- | ----------------------------------------------------------------------------- |
| Subfinder   | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Amass       | `snap install amass` or build                                                 |
| Assetfinder | `go install github.com/tomnomnom/assetfinder@latest`                          |
| httpx       | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`            |
| nuclei      | `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`       |

Make sure `$GOPATH/bin` is in PATH.

---

## ⚙️ Configuration

Edit **config.yaml**:

```yaml
sub_enum_tools:
  subfinder: "subfinder -silent -d {domain}"
  amass: "amass enum -passive -d {domain}"
  assetfinder: "assetfinder --subs-only {domain}"

tools:
  httpx: "httpx -silent -status-code -title -tech-detect"
  nmap_quick: "nmap -T4 -Pn -n -p 1-1000"
  nmap_full: "nmap -T4 -Pn -n -p-"
  nuclei: "nuclei -silent -severity critical,high,medium"
  eyewitness: "eyewitness --web -f {file} -d {outdir} --timeout 10 --no-prompt"
  whatweb: "whatweb --input-file={file} --aggression=3 --log-verbose={outfile}"

paths:
  subdomain_output: "results/subdomains"
  alive_output: "results/alive"
  scan_output: "results/scans"
  screenshot_output: "results/screenshots"
  tech_output: "results/tech"


notify:
  enabled: false
  telegram:
    token: "YOUR_BOT_TOKEN_HERE"
    chat_id: "YOUR_CHAT_ID_HERE"

```

---

## 🎯 Usage

Add targets (one per line) in:

```
targets.txt
```

Run manually:

```bash
python3 recon.py
```

---

## ⭐ Features

### ✔ Subdomain Enumeration

Runs:

* Subfinder
* Amass passive
* Assetfinder

Merges + deduplicates output.

### ✔ Daily Diff Tracking

Creates:

```
example.com_2026-01-07.txt
example.com_2026-01-07_new.txt
```

### ✔ Alive checks

Uses httpx to save:

* `*_alive_full.txt` — URL + status + tech
* `*_alive.txt` — clean host list

### ✔ Nmap Scanning

* Quick scan for all alive hosts
* Full scan only if ports like 8080/8443 detected

### ✔ Vulnerability Scanning

Runs nuclei with high-impact templates.

### ✔ Tech Fingerprinting & Screenshots

* WhatWeb — tech stack
* (If configured earlier) EyeWitness screenshots

### ✔ Telegram Alerts

Get notified when:

* New subdomains discovered

---

## 🤖 Automation with Cron

Edit cron:

```bash
crontab -e
```

Add:

```bash
0 1 * * * cd /path/to/recon && /usr/bin/python3 recon.py >> logs/cron.log 2>&1
```

Logs rotate daily.

---

## 📝 Logs

Check output:

```bash
tail -f logs/cron.log
```

---

## 🧠 Why This Matters

* Companies deploy new assets every day
* New subdomains = new bugs
* Automated recon gives **first mover advantage**
* Stop burning time running manual tools

---

## 🚀 Future Roadmap

* Git auto-commit to track historical recon
* Screenshot diffing
* Dir brute forcing on selected hosts
* Slack / Discord alert support
* Multi-thread + async performance mode

---

## 🤝 Contributions

Pull requests, issues, ideas — all welcome.

Happy hunting 👑

```

