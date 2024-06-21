# Chakravyuh: The Hidden Cipher
# Introduction
"Chakravyuh: The Hidden Cipher" is an advanced cybersecurity tool designed to assist in reconnaissance and vulnerability assessment of web domains. This tool integrates various techniques such as subdomain enumeration, alive subdomain checking, URL fuzzing, SQL injection testing, and Nmap port scanning to provide comprehensive insights into potential attack surfaces and vulnerabilities.

# Why Chakravyuh?
The increasing complexity and frequency of cyber threats necessitate robust tools for proactive defense measures. "Chakravyuh" addresses this need by automating the discovery of subdomains, assessing their accessibility and potential vulnerabilities, and scanning for open ports. It empowers cybersecurity professionals, penetration testers, and researchers to identify and mitigate security risks before they can be exploited.

# What We Have Used
"Chakravyuh" leverages several key technologies and methodologies:

Python: The core programming language for implementing the tool's functionalities.
Streamlit: A powerful Python library for creating interactive web applications, used for the user interface.
Requests: A Python library for making HTTP requests, utilized for querying crt.sh and checking subdomain accessibility.
Concurrent.futures: Enables concurrent execution of tasks, enhancing performance during subdomain alive checks.
Subprocess: Facilitates the execution of external commands like Nmap and gau for URL fuzzing and port scanning.
Pandas: Used for data manipulation and presenting results in tabular format within the Streamlit interface.
How This Tool Is Useful
# Features and Functionality:
## Subdomain Enumeration: 

Queries crt.sh to enumerate all subdomains associated with a given domain, providing a comprehensive list for analysis.

## Alive Subdomain Check: 

Verifies the accessibility of subdomains using HTTP and HTTPS requests, identifying which are actively responding.

## URL Fuzzing (gau): 

Conducts URL fuzzing on alive subdomains to uncover potential URLs and endpoints that may be vulnerable to attacks.

## SQL Injection Testing: 

Tests URLs with parameters for SQL injection vulnerabilities, generating detailed reports on potential risks.
Nmap Port Scanning: Performs detailed port scans on alive subdomains to identify open ports and services, aiding in network security assessments.
## User Interface:
The tool features an intuitive web interface powered by Streamlit, allowing users to:
Upload a domain list or enter a domain name for analysis.
Visualize and explore discovered subdomains, active subdomains, URLs with parameters, and SQL injection test results.
View comprehensive reports generated for each analyzed domain, including Nmap scan results and detailed vulnerability findings.

# Future Implications

# Potential Enhancements and Extensions:

## Enhanced Reporting: 

Integrate graphical representations and interactive charts for visualizing scan results and vulnerabilities.

## Automation: 

Implement scheduled scans and continuous monitoring capabilities to detect changes in domain landscapes and security postures.

## Additional Security Checks: 

Expand functionality to include more advanced vulnerability assessments, such as XSS (Cross-Site Scripting) and CSRF (Cross-Site Request Forgery) testing.

## Integration with Security Frameworks: 

Enable integration with existing security frameworks and tools to facilitate streamlined workflows and comprehensive security assessments.
# Community and Collaboration:

As an open-source tool, "Chakravyuh" encourages community contributions and feedback to enhance its functionality, reliability, and applicability in diverse cybersecurity scenarios. Collaborative efforts can drive continuous improvement and adaptation to emerging cybersecurity challenges.
