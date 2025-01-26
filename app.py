#!/usr/bin/env python

import streamlit as st
import requests
import pandas as pd
import concurrent.futures
from urllib.parse import urlparse, parse_qs
import os
import dns.resolver
import socket
import asyncio
import aiohttp
import ssl
import xml.etree.ElementTree as ET
from tqdm import tqdm
import multiprocessing
import subprocess
import re
import shutil
import whois
import requests
from bs4 import BeautifulSoup
import subprocess

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

#Set the path to the Nikto script
NIKTO_PATH = "/home/vishal/nikto/program/nikto.pl" 

SECURITYTRAILS_API_KEY = "ddiwUR3oESCHlQWwWwc8Ydp81tRH8POh"



import os

# Streamlit UI
st.title("GitHub Repository Cloner and Installer")
st.write("This app clones the `gau` repository, builds it, and installs the executable.")

# # Git repository URL
repo_url = "https://github.com/lc/gau.git"

# Clone and Install Steps
if st.button("Clone and Install"):
    try:
        # Clone the repository
        st.info("Cloning the repository...")
        clone_result = subprocess.run(
            ["git", "clone", repo_url, "cloned_repo"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if clone_result.returncode == 0:
            st.success("✅ Repository cloned successfully!")
        else:
            st.error("❌ Failed to clone the repository.")
            st.error(clone_result.stderr)
            st.stop()

        # Navigate to the cloned directory and build the Go project
        st.info("Building the project...")
        build_dir = os.path.join("cloned_repo", "cmd")
        build_result = subprocess.run(
            ["go", "build"], cwd=build_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if build_result.returncode == 0:
            st.success("✅ Project built successfully!")
        else:
            st.error("❌ Failed to build the project.")
            st.error(build_result.stderr)
            st.stop()

        # Move the built executable to /usr/local/bin
        st.info("Installing the executable...")
        move_result = subprocess.run(
            ["sudo", "mv", "gau", "/usr/local/bin/"],
            cwd=build_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if move_result.returncode == 0:
            st.success("✅ Executable installed successfully!")
        else:
            st.error("❌ Failed to move the executable.")
            st.error(move_result.stderr)
            st.stop()

        # Check the version of the installed executable
        st.info("Verifying the installation...")
        version_result = subprocess.run(
            ["gau", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if version_result.returncode == 0:
            st.success(f"✅ Installation verified! Version: {version_result.stdout.strip()}")
        else:
            st.error("❌ Failed to verify the installation.")
            st.error(version_result.stderr)

    except Exception as e:
        st.error(f"❌ An unexpected error occurred: {e}")



def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

async def query_crt_sh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for entry in data:
                        if 'name_value' in entry:
                            subdomains.add(entry['name_value'].strip())
                    return subdomains
                else:
                    st.error(f"Error fetching data from crt.sh. Status code: {response.status}")
                    return set()
        except Exception as e:
            st.error(f"An error occurred while querying crt.sh: {str(e)}")
            return set()

async def query_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for entry in data.get('passive_dns', []):
                        if 'hostname' in entry:
                            subdomains.add(entry['hostname'].strip())
                    return subdomains
                else:
                    st.error(f"Error fetching data from AlienVault. Status code: {response.status}")
                    return set()
        except Exception as e:
            st.error(f"An error occurred while querying AlienVault: {str(e)}")
            return set()

async def query_securitytrails(domain):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": SECURITYTRAILS_API_KEY
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    for subdomain in data.get('subdomains', []):
                        subdomains.add(f"{subdomain}.{domain}")
                    return subdomains
                else:
                    st.error(f"Error fetching data from SecurityTrails. Status code: {response.status}")
                    return set()
        except Exception as e:
            st.error(f"An error occurred while querying SecurityTrails: {str(e)}")
            return set()

async def get_subdomains_from_dns(domain):
    subdomains = set()
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, 'NS')
        ns_servers = [str(rdata.target) for rdata in answers]
        
        for ns in ns_servers:
            try:
                zone = await asyncio.to_thread(dns.zone.from_xfr, dns.query.xfr(ns, domain))
                for name, node in zone.nodes.items():
                    subdomains.add(f"{name}.{domain}".strip('.'))
            except:
                pass
    except:
        pass
    return subdomains

async def check_alive(subdomain):
    protocols = ['http://', 'https://']
    async with aiohttp.ClientSession() as session:
        for protocol in protocols:
            url = f"{protocol}{subdomain}"
            try:
                async with session.get(url, timeout=5, allow_redirects=True) as response:
                    if response.status == 200:
                        return subdomain
            except:
                pass
    
    try:
        await asyncio.to_thread(socket.gethostbyname, subdomain)
        return subdomain
    except:
        pass
    
    return None

async def run_gau_on_subdomains(file_path, output_file):
    if not os.path.exists(file_path):
        st.error("Error: active_subdomains.txt not found.")
        return

    with open(file_path, 'r') as file:
        domains = file.readlines()

    with open(output_file, 'w') as out_file:
        for domain in tqdm(domains, desc="Running gau", dynamic_ncols=True):
            domain = domain.strip()
            if domain:
                st.write(f"[+] Running gau on {domain} ...")
                result = await asyncio.create_subprocess_exec(
                    'gau', domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                out_file.write(stdout.decode())

    with open(output_file, 'r') as file:
        lines = file.readlines()
    unique_lines = sorted(set(lines))

    with open(output_file, 'w') as file:
        file.writelines(unique_lines)

    st.success(f"gau completed. Output saved to {output_file}")

async def check_status_codes(urls, output_file):
    async with aiohttp.ClientSession() as session:
        with open(output_file, 'w') as f:
            for url in tqdm(urls, desc="Checking status codes", dynamic_ncols=True):
                try:
                    async with session.head(url, timeout=5, allow_redirects=True) as response:
                        status_code = response.status
                        if status_code == 200:
                            f.write(f"{url}\n")
                except Exception as e:
                    pass  # Ignore errors and non-200 status codes

def has_parameters(url):
    parsed = urlparse(url)
    return bool(parse_qs(parsed.query))

async def test_sql_injection(urls):
    sql_payloads = ["'", '"', "sleep(5000)"]
    results = {}

    async with aiohttp.ClientSession() as session:
        for url in tqdm(urls, desc="Testing SQL injection", dynamic_ncols=True):
            if has_parameters(url):
                for payload in sql_payloads:
                    parsed = urlparse(url)
                    query = parse_qs(parsed.query)
                    for param in query:
                        query[param] = [f"{query[param][0]}{payload}"]
                    new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
                    test_url = parsed._replace(query=new_query).geturl()
                    
                    try:
                        async with session.get(test_url, timeout=5, allow_redirects=True) as response:
                            status_code = response.status
                            if status_code == 403 or status_code == 500:
                                results[test_url] = f"<span style='color:red'>{status_code} Error</span>"
                            else:
                                results[test_url] = f"{status_code} OK"
                    except Exception as e:
                        results[test_url] = f"<span style='color:red'>Error: {str(e)}</span>"
    
    return results

async def run_nmap(subdomain, output_dir):
    try:
        xml_output = os.path.join(output_dir, f"{subdomain}.xml")
        html_output = os.path.join(output_dir, f"{subdomain}.html")
        
        process = await asyncio.create_subprocess_exec(
            'nmap', '-sV', '-sC', '-p-', '-T4', '--max-retries', '2', 
            '--min-rate', '1000', '--reason',
            '-oX', xml_output, subdomain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if os.path.exists(xml_output):
            # Convert XML to HTML using xsltproc
            xsltproc_process = await asyncio.create_subprocess_exec(
                'xsltproc', xml_output, '-o', html_output,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            xsltproc_stdout, xsltproc_stderr = await xsltproc_process.communicate()
            
            # Parse XML output
            tree = ET.parse(xml_output)
            root = tree.getroot()
            
            host_result = {"host": subdomain, "ports": [], "os": "", "hostnames": []}
            
            for host in root.findall('host'):
                # Get OS information
                os_elem = host.find('os/osmatch')
                if os_elem is not None:
                    host_result["os"] = os_elem.get('name', '')

                # Get hostnames
                for hostname in host.findall('hostnames/hostname'):
                    host_result["hostnames"].append(hostname.get('name', ''))

                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state')
                    state_value = state.get('state') if state is not None else "unknown"
                    reason = state.get('reason') if state is not None else "unknown"
                    
                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', 'unknown')
                        product = service.get('product', '')
                        version = service.get('version', '')
                        extrainfo = service.get('extrainfo', '')
                    else:
                        service_name = "unknown"
                        product = ""
                        version = ""
                        extrainfo = ""
                    
                    scripts = []
                    for script in port.findall('script'):
                        script_id = script.get('id')
                        script_output = script.get('output')
                        scripts.append({"id": script_id, "output": script_output})
                    
                    host_result["ports"].append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state_value,
                        "reason": reason,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "scripts": scripts
                    })
            
            # Clean up XML file
            os.remove(xml_output)
            return host_result
        else:
            return None
    
    except Exception as e:
        st.error(f"Error running Nmap for {subdomain}: {str(e)}")
        return None

async def check_ssl_security(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                
                # Check SSL/TLS version
                version = secure_sock.version()
                
                # Check certificate expiration
                import datetime
                exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_to_expire = (exp_date - datetime.datetime.utcnow()).days
                
                return {
                    "version": version,
                    "days_to_expire": days_to_expire,
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject'])
                }
    except Exception as e:
        return {"error": str(e)}

async def detect_waf(url):
    try:
        process = await asyncio.create_subprocess_exec(
            'wafw00f', url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            st.error(f"Error detecting WAF for {url}: {stderr.decode()}")
            return None
        return stdout.decode()
    except Exception as e:
        st.error(f"An error occurred while detecting WAF for {url}: {str(e)}")
        return None

def parse_waf_output(output):
    lines = output.split('\n')
    for line in lines:
        if 'is behind' in line.lower():
            match = re.search(r'is behind (.*) WAF', line, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    return "No WAF detected"

def clean_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

async def run_nikto(url, output_file):
    if not os.path.exists(NIKTO_PATH):
        st.warning(f"Nikto script not found at {NIKTO_PATH}. Skipping Nikto scan.")
        return None

    try:
        process = await asyncio.create_subprocess_exec(
            'perl', NIKTO_PATH, '-h', url, '-o', output_file, '-Format', 'txt',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            st.error(f"Error running Nikto for {url}: {stderr.decode()}")
            return None
        with open(output_file, 'r') as f:
            return f.read()
    except Exception as e:
        st.error(f"An error occurred while running Nikto for {url}: {str(e)}")
        return None

import requests
from bs4 import BeautifulSoup
import re

async def perform_whois(domain):
    url = f"https://www.whois.com/whois/{domain}"
    try:
        response = await asyncio.to_thread(requests.get, url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        whois_data = soup.find('pre', {'class': 'df-raw'})
        if whois_data:
            whois_text = whois_data.text.strip()
            
            # Remove the specified part
            pattern = re.compile(r'URL of the ICANN WHOIS Data Problem Reporting System:.*?Failure to comply with these terms may result in termination of access to the Whois database\. These terms may be subject to modification at any time without notice\.', re.DOTALL)
            cleaned_whois = re.sub(pattern, '', whois_text)
            
            # Remove extra newlines
            cleaned_whois = re.sub(r'\n{3,}', '\n\n', cleaned_whois.strip())
            
            return cleaned_whois
        else:
            return f"Error: Unable to parse WHOIS data for {domain}"
    except Exception as e:
        return f"Error performing WHOIS lookup: {str(e)}"

async def main():
    st.title("Chakravyuh: The Hidden Cipher")
    
    # Sidebar setup
    st.sidebar.title("About")
    st.sidebar.markdown("""
    ### 🔍 **Chakravyuh: The Hidden Cipher**
    **A Comprehensive Cyber Security Tool**

    - 🛡️ **Query Subdomains:** Extract subdomains with ease.
    - 💡 **Alive Check:** Identify responsive subdomains quickly.
    - 🌐 **URL Fuzzing:** Leverage gau to gather URLs for potential attack surfaces.
    - 🔒 **Port Scanning:** Perform detailed DNS scans to uncover open ports and services.
    - 🔐 **SSL Security:** Check SSL/TLS configuration and certificate details.
    - 🕵️ **Nikto Scan:** Perform web server scanning for vulnerabilities.
    - 📋 **WHOIS Lookup:** Retrieve domain registration information.

    > **Empower your cybersecurity with advanced features and intuitive interface.**
    """)

    results_dir = "results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    st.sidebar.title("Domain Selection")
    uploaded_file = st.sidebar.file_uploader("Upload your domain list", type=["txt"])
    if uploaded_file:
        domains = uploaded_file.read().decode("utf-8").splitlines()
        domain = st.sidebar.selectbox("Select a domain to query", domains)
    else:
        domain = st.sidebar.text_input("Enter the domain to query", "")

    if not domain:
        st.warning("Please enter or select a domain name.")
        return

    st.sidebar.title("Select Scans")
    deep_scan = st.sidebar.checkbox("Deep Scan (Run All)")
    
    scans = {
        "Subdomain Discovery": st.sidebar.checkbox("Subdomain Discovery", value=deep_scan),
        "Alive Check": st.sidebar.checkbox("Alive Check", value=deep_scan),
        "URL Fuzzing": st.sidebar.checkbox("URL Fuzzing (gau)", value=deep_scan),
        "Port Scanning": st.sidebar.checkbox("Port Scanning (Nmap)", value=deep_scan),
        "SSL Security": st.sidebar.checkbox("SSL/TLS Security Check", value=deep_scan),
        "WAF Detection": st.sidebar.checkbox("WAF Detection", value=deep_scan),
        "SQL Injection": st.sidebar.checkbox("SQL Injection Testing", value=deep_scan),
        "Nikto Scan": st.sidebar.checkbox("Nikto Scan", value=deep_scan),
        "WHOIS Lookup": st.sidebar.checkbox("WHOIS Lookup", value=deep_scan)
    }

    if st.button("Start Analysis"):
        results_domain_dir = os.path.join(results_dir, domain)
        create_directory(results_domain_dir)

        all_subdomains = []
        alive_subdomains = []
        subdomains_file = os.path.join(results_domain_dir, "active_subdomains.txt")
        output_file_gau = os.path.join(results_domain_dir, "gau_output.txt")

        for scan_name, scan_selected in scans.items():
            if scan_selected:
                if scan_name == "Subdomain Discovery":
                    with st.spinner("Discovering subdomains..."):
                        progress_bar = st.progress(0)
                        subdomains_crt, subdomains_alienvault, subdomains_dns, subdomains_securitytrails = await asyncio.gather(
                            query_crt_sh(domain),
                            query_alienvault(domain),
                            get_subdomains_from_dns(domain),
                            query_securitytrails(domain)
                        )
                        all_subdomains = list(set(subdomains_crt | subdomains_alienvault | subdomains_dns | subdomains_securitytrails))
                        progress_bar.progress(100)

                    if all_subdomains:
                        st.subheader(f"Subdomains found for {domain}:")
                        subdomains_df = pd.DataFrame(all_subdomains, columns=['Subdomain'])
                        st.dataframe(subdomains_df.style.set_properties(**{'text-align': 'left'}))

                        with open(subdomains_file, "w") as file:
                            for subdomain in all_subdomains:
                                file.write(subdomain + "\n")
                        st.success(f"All subdomains saved to {subdomains_file}")
                    else:
                        st.warning("No subdomains discovered.")

                elif scan_name == "Alive Check":
                    if all_subdomains:
                        with st.spinner("Checking for active subdomains..."):
                            progress_bar = st.progress(0)
                            with concurrent.futures.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
                                alive_subdomains = list(filter(None, await asyncio.gather(*[check_alive(subdomain) for subdomain in all_subdomains])))
                                for i in range(len(all_subdomains)):
                                    progress_bar.progress((i + 1) / len(all_subdomains))

                        if alive_subdomains:
                            st.subheader("Active Subdomains:")
                            alive_df = pd.DataFrame(alive_subdomains, columns=['Active Subdomain'])
                            st.dataframe(alive_df.style.set_properties(**{'text-align': 'left'}))

                            with open(subdomains_file, "w") as file:
                                for subdomain in alive_subdomains:
                                    file.write(subdomain + "\n")
                            st.success(f"Active subdomains saved to {subdomains_file}")
                        else:
                            st.warning("No active subdomains found.")
                    else:
                        st.error("No subdomains to check. Please run Subdomain Discovery first.")

                elif scan_name == "URL Fuzzing":
                    if os.path.exists(subdomains_file):
                        with st.spinner("Running URL fuzzing with gau..."):
                            progress_bar = st.progress(0)
                            await run_gau_on_subdomains(subdomains_file, output_file_gau)
                            progress_bar.progress(100)
                            st.success(f"URL fuzzing completed. Results saved to {output_file_gau}")
                    else:
                        st.error("Subdomains file not found. Please run Subdomain Discovery first.")

                elif scan_name == "Port Scanning":
                    if alive_subdomains:
                        with st.spinner("Running Nmap scans..."):
                            nmap_output_dir = os.path.join(results_domain_dir, "nmap_results")
                            create_directory(nmap_output_dir)
                            progress_bar = st.progress(0)
                            nmap_tasks = [run_nmap(subdomain, nmap_output_dir) for subdomain in alive_subdomains]
                            nmap_results = await asyncio.gather(*nmap_tasks)
                            for i in range(len(alive_subdomains)):
                                progress_bar.progress((i + 1) / len(alive_subdomains))
                            
                            st.subheader("Nmap Scan Results:")
                            for result in nmap_results:
                                if result:
                                    st.write(f"**Host: {result['host']}**")
                                    port_data = []
                                    for port in result['ports']:
                                        port_data.append({
                                            "Port": port['port'],
                                            "State": port['state'],
                                            "Service": port['service'],
                                            "Product": port['product'],
                                            "Version": port['version']
                                        })
                                    st.table(pd.DataFrame(port_data))
                            
                            st.success(f"Detailed Nmap results saved to {nmap_output_dir}")
                    else:
                        st.error("No active subdomains to scan. Please run Alive Check first.")

                elif scan_name == "SSL Security":
                    with st.spinner("Checking SSL/TLS security..."):
                        progress_bar = st.progress(0)
                        ssl_results = await check_ssl_security(domain)
                        progress_bar.progress(100)
                        st.subheader("SSL/TLS Security Check:")
                        st.json(ssl_results)

                elif scan_name == "WAF Detection":
                    if alive_subdomains:
                        with st.spinner("Detecting WAF..."):
                            progress_bar = st.progress(0)
                            waf_tasks = [detect_waf(f"http://{subdomain}") for subdomain in alive_subdomains]
                            waf_outputs = await asyncio.gather(*waf_tasks)
                            for i in range(len(alive_subdomains)):
                                progress_bar.progress((i + 1) / len(alive_subdomains))

                            st.subheader("WAF Detection Results:")
                            waf_results = {}
                            for subdomain, waf_output in zip(alive_subdomains, waf_outputs):
                                if waf_output:
                                    firewall = parse_waf_output(waf_output)
                                    firewall_clean = clean_ansi_escape_sequences(firewall)
                                    waf_results[subdomain] = firewall_clean
                            
                            waf_df = pd.DataFrame(list(waf_results.items()), columns=['Subdomain', 'WAF'])
                            st.dataframe(waf_df)

                            waf_file = os.path.join(results_domain_dir, "waf_results.txt")
                            with open(waf_file, 'w') as f:
                                for subdomain, firewall in waf_results.items():
                                    f.write(f"{subdomain}: {firewall}\n")
                            st.success(f"WAF detection results saved to {waf_file}")
                    else:
                        st.error("No active subdomains to check for WAF. Please run Alive Check first.")

                elif scan_name == "SQL Injection":
                    if os.path.exists(output_file_gau):
                        with st.spinner("Testing SQL injection..."):
                            progress_bar = st.progress(0)
                            with open(output_file_gau, 'r') as gau_file:
                                urls = [line.strip() for line in gau_file.readlines() if line.strip()]
                            sql_injection_results = await test_sql_injection(urls)
                            progress_bar.progress(100)

                            st.subheader("SQL Injection Testing Results:")
                            results_df = pd.DataFrame(list(sql_injection_results.items()), columns=['URL', 'Result'])
                            st.write(results_df.to_html(escape=False), unsafe_allow_html=True)

                            sql_results_file = os.path.join(results_domain_dir, "sql_results.txt")
                            with open(sql_results_file, 'w') as f:
                                for url, result in sql_injection_results.items():
                                    f.write(f"{url}: {result}\n")
                            st.success(f"SQL injection results saved to {sql_results_file}")
                    else:
                        st.error("URL fuzzing results not found. Please run URL Fuzzing first.")

                elif scan_name == "Nikto Scan":
                    if alive_subdomains:
                        with st.spinner("Running Nikto scans..."):
                            nikto_output_dir = os.path.join(results_domain_dir, "nikto_results")
                            create_directory(nikto_output_dir)
                            progress_bar = st.progress(0)
                            
                            nikto_tasks = []
                            for subdomain in alive_subdomains:
                                nikto_output_file = os.path.join(nikto_output_dir, f"{subdomain}_nikto.txt")
                                nikto_tasks.append(run_nikto(f"http://{subdomain}", nikto_output_file))
                            
                            nikto_results = await asyncio.gather(*nikto_tasks)
                            
                            st.subheader("Nikto Scan Results:")
                            nikto_ran = False
                            for i, (subdomain, result) in enumerate(zip(alive_subdomains, nikto_results)):
                                if result:
                                    nikto_ran = True
                                    st.write(f"**Nikto scan for {subdomain}:**")
                                    st.text(result[:500] + "..." if len(result) > 500 else result)  # Display first 500 characters
                                    st.write(f"Full results saved to {nikto_output_dir}/{subdomain}_nikto.txt")
                                progress_bar.progress((i + 1) / len(alive_subdomains))

                            if nikto_ran:
                                combined_nikto_file = os.path.join(results_domain_dir, "combined_nikto_results.txt")
                                with open(combined_nikto_file, 'w') as combined_file:
                                    for subdomain, result in zip(alive_subdomains, nikto_results):
                                        if result:
                                            combined_file.write(f"Nikto scan for {subdomain}:\n")
                                            combined_file.write(result)
                                            combined_file.write("\n\n" + "="*50 + "\n\n")
                                st.success(f"Combined Nikto results saved to {combined_nikto_file}")
                            else:
                                st.warning(f"No Nikto scans were performed. Make sure Nikto is installed at {NIKTO_PATH}")
                    else:
                        st.error("No active subdomains to scan with Nikto. Please run Alive Check first.")

                elif scan_name == "WHOIS Lookup":
                    with st.spinner("Performing WHOIS lookup..."):
                        progress_bar = st.progress(0)
                        whois_result = await perform_whois(domain)
                        progress_bar.progress(100)

                        st.subheader("WHOIS Lookup Results:")
                        st.text(whois_result)

                        whois_file = os.path.join(results_domain_dir, "whois_results.txt")
                        with open(whois_file, 'w') as f:
                            f.write(whois_result)
                        st.success(f"WHOIS lookup results saved to {whois_file}")

if __name__ == "__main__":
    asyncio.run(main())
