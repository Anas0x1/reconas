# Reconas
Reconas is a powerful and customizable reconnaissance tool designed to assist in information gathering and vulnerability assessment during security assessments and bug hunting. It provides a comprehensive set of features and modules that automate various reconnaissance tasks, helping security professionals gather valuable intelligence about target systems and identify potential vulnerabilities.
# Methodology for Domain Recon
- Getting domain IP.
- Gathering all DNS records.
- Performing DNS enumeration.
- Scanning for DNS zone transfer.
- Collecting emails.
- Identifying domain technologies.
- Gathering information about the domain.
- Collecting subdomains.
- Extracting live subdomains.
- Converting live subdomains into IP addresses.
- Conducting port scanning on IP addresses.
- Utilizing Shodan dorks.
- Utilizing GitHub dorks.
- Scanning for CORS misconfiguration.
- Scanning for subdomain takeover.
- Scanning for CRLF injection.

# Methodology for Subdomain Recon
- Obtaining IP addresses of subdomains.
- Performing directory fuzzing.
- Performing backup files fuzzing.
- Collecting parameters using ParamSpider and Arjun.
- Gathering all links from the Wayback Machine.
- Extracting and scanning JavaScript (JS) files.
- Scanning for Cross-Site Scripting (XSS).
- Collecting possible vulnerable parameters with xss,sqli,lfi,ssrf, and open redirect.
- Conducting port scanning.
- Running Nuclei on collected parameters.

# Required Tools
- whois
- dig
- host
- dnsrecon
- whatweb
- emailharvester
- subfinder
- assetfinder
- amass
- naabu
- nmap
- gitdorks_go
- corscanner
- crlfuzz
- subzy
- dirsearch
- arjun
- paramspider
- nuclei
- waybackurls
- kxss
- gf
- gf-patterns
- subjs

# Updates
- Improving the performance of the code.
- Shodan dorking.
- Google dorking.
- Saving the results of each function in a single directory.
- Saving the results of each command in a single file.

# Installation
```
git clone https://github.com/0x0anas/reconas.git
cd reconas/
sudo chmod +x setup.sh reconas.sh
sudo ./setup.sh
pip3 install -r requirements.txt
echo "Your_Github_Token" > files/token.txt
./reconas -h
```
# Usage
`./reconas.sh -h`
This will display the help menu, providing an overview of the available options and their usage.

![carbon (5)](https://github.com/0x0anas/reconas/assets/78263620/831a1d95-b6cc-4059-8b4b-3b6c63cc7a49)

- The `-t` option is required for GitHub dorking.
- Specify the target domain by using the `-d` flag followed by the domain name and `-t` flag followed by your github token file path. For example:
```
sudo ./reconas.sh -d domain.com -t files/token.txt
```
- The `-s` option is required alone to perform reconnaissance on this subdomain.
- Specify the target subdomain by using `-s` flag followed by the subdomain name. For example:
```
sudo ./reconas.sh -s sub.domain.com
```



