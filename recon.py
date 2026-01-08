#!/usr/bin/env python3
import subprocess
import os
import logging

import yaml
from pathlib import Path
from datetime import datetime
from notify import new_subdomains_alert


CONFIG = yaml.safe_load(open("config.yaml"))
RESULT_DIR = Path(CONFIG["paths"]["subdomain_output"])
RESULT_DIR.mkdir(parents=True, exist_ok=True)

INTERESTING_PORTS = ["8080", "8443", "8888", "3000", "5000"]

def run_cmd(cmd):
    """Execute a shell command and return output lines."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        logging.error(f"{cmd}: {e}")
        return []

def enumerate_subdomains(domain):
    logging.info(f"Enumerating subdomains for {domain}")
    subs = set()

    for name, template in CONFIG["sub_enum_tools"].items():
        cmd = template.format(domain=domain)
        logging.info(f"Running {name}...")
        subs.update(run_cmd(cmd))

    return sorted(subs)

def save_results(domain, subs):
    today = datetime.now().strftime("%Y-%m-%d")
    outfile = RESULT_DIR / f"{domain}_{today}.txt"

    with open(outfile, "w") as f:
        f.write("\n".join(subs))

    logging.info(f"Saved {len(subs)} subdomains → {outfile}")


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

    logging.info(f"Saved {len(subs)} subdomains → {outfile}")

    # Load yesterday’s list
    previous = load_previous_results(domain)

    # Compute new subs
    new_subs = set(subs) - previous

    if new_subs:
        diff_file = RESULT_DIR / f"{domain}_{today}_new.txt"
        with open(diff_file, "w") as f:
            f.write("\n".join(sorted(new_subs)))
        logging.info(f"{len(new_subs)} new subdomains found!")
        for s in new_subs:
            logging.info(f"New subdomain: {s}")
        new_subdomains_alert(domain, new_subs)
    else:
        logging.info("No new subdomains today.")

    return new_subs,outfile


def check_alive(domain, subdomains_save_path):
    """Run httpx and save both full info and clean hosts."""
    alive_dir = Path(CONFIG["paths"]["alive_output"])
    alive_dir.mkdir(parents=True, exist_ok=True)

    logging.info(f"Checking alive subdomains for {domain}...")

    # Run httpx with stdin
    cmd = f"cat {subdomains_save_path} | {CONFIG['tools']['httpx']}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    full_output = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    
    # Save full info
    full_file = alive_dir / f"{domain}_alive_full.txt"
    with open(full_file, "w") as f:
        f.write("\n".join(full_output))

    clean_hosts = []   # used for Nmap/Nuclei
    raw_urls = []      # used for EyeWitness/WhatWeb

    for line in full_output:
        url = line.split()[0].strip()
        raw_urls.append(url)

        host = url.replace("http://", "").replace("https://", "").rstrip("/")
        clean_hosts.append(host)

    # Save clean hosts
    clean_file = alive_dir / f"{domain}_alive.txt"
    with open(clean_file, "w") as f:
        f.write("\n".join(clean_hosts))

    logging.info(f"Alive full info saved → {full_file}")
    logging.info(f"Clean hosts saved → {clean_file}")

    return clean_hosts, raw_urls



def nmap_quick_scan(domain, alive_subs):
    scans_dir = Path(CONFIG["paths"]["scan_output"])
    scans_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    logging.info(f"Running quick Nmap scan on {len(alive_subs)} hosts...")

    for host in alive_subs:
        out_file = scans_dir / f"{host.replace(':','_')}_quick.txt"
        cmd = f"{CONFIG['tools']['nmap_quick']} {host}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        with open(out_file, "w") as f:
            f.write(result.stdout)

        results[host] = result.stdout
        logging.info(f"Quick scan saved → {out_file}")

    return results

def nmap_full_scan(quick_results):
    logging.info("Checking for interesting ports...")

    full_targets = [
        host for host, output in quick_results.items()
        if any(p in output for p in INTERESTING_PORTS)
    ]

    if not full_targets:
        logging.info("No hosts need full scan.")
        return

    logging.info(f"Running full scans on {len(full_targets)} hosts...")

    scans_dir = Path(CONFIG["paths"]["scan_output"])

    for host in full_targets:
        out_file = scans_dir / f"{host.replace(':','_')}_full.txt"
        cmd = f"{CONFIG['tools']['nmap_full']} {host}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        with open(out_file, "w") as f:
            f.write(result.stdout)

        logging.info(f"Full scan saved → {out_file}")


def run_nuclei(domain, alive_subs):
    scans_dir = Path(CONFIG["paths"]["scan_output"])
    scans_dir.mkdir(parents=True, exist_ok=True)

    logging.info(f"Running nuclei against {len(alive_subs)} hosts...")

    temp = scans_dir / f"{domain}_alive_for_nuclei.txt"
    with open(temp, "w") as f:
        f.write("\n".join(alive_subs))

    cmd = f"{CONFIG['tools']['nuclei']} -l {temp}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    findings = result.stdout.strip()

    if findings:
        logging.warning("Vulnerabilities found:")
        logging.warning(findings)
        # Optional: send Telegram alert later
    else:
        logging.info("Nuclei found nothing interesting.")

    return findings

def run_eyewitness(domain, alive_subs):
    """Run EyeWitness on alive hosts and save HTML report + screenshots."""
    if not alive_subs:
        logging.info("No alive hosts for EyeWitness.")
        return

    today = datetime.now().strftime("%Y-%m-%d")
    out_dir = Path(CONFIG["paths"]["screenshot_output"]) / f"{domain}_{today}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Create input file for EyeWitness
    temp_file = f"/tmp/{domain}_alive_for_eyewitness.txt"
    with open(temp_file, "w") as f:
        f.write("\n".join(alive_subs))
        f.flush()

    cmd = CONFIG["tools"]["eyewitness"].format(file=temp_file, outdir=out_dir)
    logging.info(f"Running EyeWitness on {len(alive_subs)} hosts...")
    subprocess.run(cmd, shell=True)

    logging.info(f"EyeWitness report saved → {out_dir}")

    os.remove(temp_file)



def run_whatweb(domain, alive_subs):
    """Fingerprint tech stack using whatweb."""
    if not alive_subs:
        logging.info("No alive hosts for whatweb.")
        return

    today = datetime.now().strftime("%Y-%m-%d")
    tech_dir = Path(CONFIG["paths"]["tech_output"])
    tech_dir.mkdir(parents=True, exist_ok=True)

    output_file = tech_dir / f"{domain}_{today}_tech.txt"

    # Create input file for whatweb
    temp_file = tech_dir / f"{domain}_alive_for_whatweb.txt"
    with open(temp_file, "w") as f:
        f.write("\n".join(alive_subs))

    cmd = CONFIG["tools"]["whatweb"].format(file=temp_file, outfile=output_file)
    logging.info(f"Running whatweb on {len(alive_subs)} hosts...")
    subprocess.run(cmd, shell=True)

    logging.info(f"whatweb fingerprints saved → {output_file}")


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    targets = Path("targets.txt").read_text().splitlines()

    for domain in targets:
        subs = enumerate_subdomains(domain)
        new_subs,save_path = save_and_diff(domain, subs)
        clean_alive, alive_urls = check_alive(domain, save_path)
        quick = nmap_quick_scan(domain, clean_alive)
        nmap_full_scan(quick)
        run_nuclei(domain, clean_alive)
        run_eyewitness(domain, alive_urls)
        run_whatweb(domain, alive_urls)

if __name__ == "__main__":
    main()

