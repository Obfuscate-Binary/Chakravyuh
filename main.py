#!/usr/bin/env python

import streamlit as st
import requests
import pandas as pd
import concurrent.futures
import subprocess
from urllib.parse import urlparse, parse_qs
import os

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Function to create the domain-specific directory if it doesn't exist
def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def has_parameters(url):
    """Check if the URL has parameters."""
    parsed = urlparse(url)
    return bool(parse_qs(parsed.query))

def query_crt_sh(domain):
    """
    Query crt.sh for subdomains for a given domain.

    Args:
        domain (str): The domain to query.

    Returns:
        list: A list of unique subdomains found on crt.sh.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()  # Using a set to automatically handle duplicates
            for entry in data:
                if 'name_value' in entry:
                    subdomains.add(entry['name_value'].strip())
            return list(subdomains)
        else:
            st.error(f"Error fetching data from crt.sh. Status code: {response.status_code}")
            return []
    except Exception as e:
        st.error(f"An error occurred while querying crt.sh: {str(e)}")
        return []

def check_alive(subdomain):
    """
    Check if a subdomain is alive (responds to HTTP/HTTPS request).

    Args:
        subdomain (str): The subdomain to check.

    Returns:
        str: The subdomain if alive, None otherwise.
    """
    protocols = ['http://', 'https://']
    for protocol in protocols:
        url = f"{protocol}{subdomain}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return subdomain
        except Exception as e:
            pass
    return None

def run_gau_on_subdomains(file_path, output_file):
    """
    Run gau tool on each subdomain in the file and save the output.

    Args:
        file_path (str): Path to the file containing subdomains.
        output_file (str): Path to the output file.
    """
    if not os.path.exists(file_path):
        st.error("Error: subdomains.txt not found.")
        return

    with open(file_path, 'r') as file:
        domains = file.readlines()

    with open(output_file, 'w') as out_file:
        for domain in domains:
            domain = domain.strip()
            if domain:
                st.write(f"[+] Running gau on {domain} ...")
                result = subprocess.run(['gau', domain], capture_output=True, text=True)
                out_file.write(result.stdout)

    # Sort and make output unique
    with open(output_file, 'r') as file:
        lines = file.readlines()
    unique_lines = sorted(set(lines))

    with open(output_file, 'w') as file:
        file.writelines(unique_lines)

    st.write(f"[+] gau completed. Output saved to {output_file}")


def check_status_codes(urls, output_file):
    """
    Check HTTP status codes for each URL and save them based on status code.

    Args:
        urls (list): List of URLs to check.
        output_file (str): Path to the output file.
    """
    with open(output_file, 'w') as f:
        for url in urls:
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                status_code = response.status_code
                if status_code == 200:
                    f.write(f"200 OK: {url}\n")
                elif status_code == 403:
                    f.write(f"403 Forbidden: {url}\n")
                elif status_code == 500:
                    f.write(f"500 Internal Server Error: {url}\n")
                else:
                    f.write(f"{status_code}: {url}\n")
            except Exception as e:
                st.error(f"Error checking status for {url}: {str(e)}")   

def test_sql_injection(urls):
    """
    Test URLs with parameters for SQL injection vulnerabilities.

    Args:
        urls (list): List of URLs to test.

    Returns:
        dict: Dictionary with URL as key and status code as value.
    """
    sql_payloads = ["'", '"', "'sleep(5000)"]
    results = {}

    for url in urls:
        if has_parameters(url):
            for payload in sql_payloads:
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                for param in query:
                    query[param] = [f"{query[param][0]}{payload}"]
                new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
                test_url = parsed._replace(query=new_query).geturl()
                
                try:
                    response = requests.get(test_url, timeout=5, allow_redirects=True)
                    status_code = response.status_code
                    if status_code == 403 or status_code == 500:
                        results[test_url] = f"<span style='color:red'>{status_code} Error</span>"
                    else:
                        results[test_url] = f"{status_code} OK"
                except Exception as e:
                    results[test_url] = f"<span style='color:red'>Error: {str(e)}</span>"
    
    return results

def run_nmap(subdomains, output_file):
    """
    Run Nmap port scan on the list of subdomains with all ports and fast timing.

    Args:
        subdomains (list): List of subdomains to scan.
        output_file (str): Path to the output file.
    """
    with open(output_file, 'w') as f:
        for subdomain in subdomains:
            try:
                # Adjust the nmap command to scan all ports quickly
                subprocess.run(['nmap', '-Pn', '-p-', '-T4', '--max-rtt-timeout', '100ms', '--min-rtt-timeout', '50ms', '--max-retries', '1', subdomain], stdout=f, stderr=subprocess.PIPE, timeout=300)
            except subprocess.TimeoutExpired:
                st.warning(f"Nmap scan for {subdomain} timed out.")
            except Exception as e:
                st.error(f"Error running Nmap for {subdomain}: {str(e)}")

def main():
    st.title("Chakravyuh: The Hidden Cipher")

    # Create results directory if it doesn't exist
    results_dir = "results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    # Add a sidebar with some information and settings
    st.sidebar.title("About")
    st.sidebar.markdown("""
    ### 🔍 **Chakravyuh: The Hidden Cipher**
    **A Comprehensive Cyber Security Tool**

    - 🛡️ **Query Subdomains:** Extract subdomains with ease.
    - 💡 **Alive Check:** Identify responsive subdomains quickly.
    - 🌐 **URL Fuzzing:** Leverage gau to gather URLs for potential attack surfaces.
    - 🔒 **Port Scanning:** Perform detailed DNS scans to uncover open ports and services.

    > **Empower your cybersecurity with advanced features and intuitive interface.**
    """)

    # Add a file uploader to allow users to upload their own list of domains
    uploaded_file = st.sidebar.file_uploader("Upload your domain list", type=["txt"])
    if uploaded_file:
        domains = uploaded_file.read().decode("utf-8").splitlines()
        domain = st.sidebar.selectbox("Select a domain to query", domains)
    else:
        domain = st.text_input("Enter the domain to query crt.sh", "")

    if not domain:
        st.warning("Please enter or select a domain name.")
        return

    if st.button("Query crt.sh"):
        results_domain_dir = os.path.join(results_dir, domain)
        create_directory(results_domain_dir)

        subdomains = query_crt_sh(domain)
        if subdomains:
            st.subheader(f"Subdomains found for {domain}:")
            subdomains_df = pd.DataFrame(subdomains, columns=['Subdomain'])
            st.dataframe(subdomains_df)

            # Check which subdomains are alive using HTTP/HTTPS requests
            alive_subdomains = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(check_alive, subdomain) for subdomain in subdomains]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        alive_subdomains.append(result)

            # Remove duplicates from alive subdomains
            alive_subdomains = list(set(alive_subdomains))

            if alive_subdomains:
                st.subheader("Alive Subdomains:")
                alive_df = pd.DataFrame(alive_subdomains, columns=['Alive Subdomain'])
                st.dataframe(alive_df)

                # Save alive subdomains to subdomains.txt in results/domain/
                subdomains_file = os.path.join(results_domain_dir, "subdomains.txt")
                with open(subdomains_file, "w") as file:
                    for subdomain in alive_subdomains:
                        file.write(subdomain + "\n")

            # Run gau on alive subdomains
            output_file_gau = os.path.join(results_domain_dir, "gau_output.txt")
            run_gau_on_subdomains(subdomains_file, output_file_gau)

            # Run status code check on URLs from gau output
            with open(output_file_gau, 'r') as gau_file:
                urls = [line.strip() for line in gau_file.readlines() if line.strip()]
            
            output_file_active_urls = os.path.join(results_domain_dir, "active_urls.txt")
            check_status_codes(urls, output_file_active_urls)
            st.success(f"Status codes checked. Results saved to {output_file_active_urls}")

            # Test URLs for SQL injection vulnerabilities
            st.subheader("SQL Injection Testing Results:")
            sql_injection_results = test_sql_injection(urls)
            results_df = pd.DataFrame(list(sql_injection_results.items()), columns=['URL', 'Result'])
            st.write(results_df.to_html(escape=False), unsafe_allow_html=True)

            # Save SQL injection results to sql_results.txt
            sql_results_file = os.path.join(results_domain_dir, "sql_results.txt")
            with open(sql_results_file, 'w') as f:
                for url, result in sql_injection_results.items():
                    f.write(f"{url}: {result}\n")
            st.success(f"SQL injection results saved to {sql_results_file}")

            # ... (keep the rest of the function as it is)

if __name__ == "__main__":
    main()
