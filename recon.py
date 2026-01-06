import subprocess
import yaml
from pathlib import Path
from datetime import datetime
from notify import new_subdomains_alert


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


def load_previous_results(domain):
    """Return yesterday's subdomain list if available."""
    files = sorted(RESULT_DIR.glob(f"{domain}_*.txt"))
    if len(files) < 2:
        return set()
    return set(Path(files[-2]).read_text().splitlines())

def save_and_diff(domain, subs):
    today = datetime.now().strftime("%Y-%m-%d")
    outfile = RESULT_DIR / f"{domain}_{today}.txt"

    # Save today's results
    with open(outfile, "w") as f:
        f.write("\n".join(subs))

    print(f"   [+] Saved {len(subs)} subdomains → {outfile}")

    # Load yesterday’s list
    previous = load_previous_results(domain)

    # Compute new subs
    new_subs = set(subs) - previous

    if new_subs:
        diff_file = RESULT_DIR / f"{domain}_{today}_new.txt"
        with open(diff_file, "w") as f:
            f.write("\n".join(sorted(new_subs)))
        print(f"   [🔥] {len(new_subs)} new subdomains found!")
        for s in new_subs:
            print(f"       ➤ {s}")
        new_subdomains_alert(domain, new_subs)
    else:
        print("   [✓] No new subdomains today.")

    return new_subs


def check_alive(domain, subdomains):
    """Run httpx and save only alive subdomains."""
    alive_dir = Path(CONFIG["paths"]["alive_output"])
    alive_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Checking alive subdomains for {domain}...")

    # Run httpx directly with stdin input
    cmd = f"echo \"{chr(10).join(subdomains)}\" | {CONFIG['tools']['httpx']}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    alive_subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    # Save alive list only
    alive_file = alive_dir / f"{domain}_alive.txt"
    with open(alive_file, "w") as f:
        f.write("\n".join(alive_subs))

    print(f"[+] Alive: {len(alive_subs)} → {alive_file}")
    return alive_subs




def main():
    targets = Path("targets.txt").read_text().splitlines()

    for domain in targets:
        subs = enumerate_subdomains(domain)
        new_subs = save_and_diff(domain, subs)
        alive_subs = check_alive(domain, subs)

if __name__ == "__main__":
    main()
