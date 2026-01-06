import subprocess
import yaml
from pathlib import Path
from datetime import datetime

CONFIG = yaml.safe_load(open("config.yaml"))
RESULT_DIR = Path(CONFIG["paths"]["subdomain_output"])
RESULT_DIR.mkdir(parents=True, exist_ok=True)

def run_cmd(cmd):
    """Execute a shell command and return output lines."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(f"[ERROR] {cmd}: {e}")
        return []

def enumerate_subdomains(domain):
    print(f"\n[*] Enumerating subdomains for {domain}")
    subs = set()

    for name, template in CONFIG["tools"].items():
        cmd = template.format(domain=domain)
        print(f"   └─ Running {name}...")
        subs.update(run_cmd(cmd))

    return sorted(subs)

def save_results(domain, subs):
    today = datetime.now().strftime("%Y-%m-%d")
    outfile = RESULT_DIR / f"{domain}_{today}.txt"

    with open(outfile, "w") as f:
        f.write("\n".join(subs))

    print(f"   [+] Saved {len(subs)} subdomains → {outfile}")

def main():
    targets = Path("targets.txt").read_text().splitlines()

    for domain in targets:
        subs = enumerate_subdomains(domain)
        save_results(domain, subs)

if __name__ == "__main__":
    main()
