# Reconas
Reconas is a powerful and customizable reconnaissance tool designed to assist in information gathering and vulnerability assessment during security assessments and bug hunting. It provides a comprehensive set of features and modules that automate various reconnaissance tasks, helping security professionals gather valuable intelligence about target systems and identify potential vulnerabilities.
# Methodology for domain recon
- Getting domain IPs
- Gathering all DNS records
- Performing DNS enumeration
- Scanning for DNS zone transfer
- Collecting emails
- Identifying domain technologies
- Gathering information about the domain
- Collecting subdomains
- Extracting live subdomains
- Converting live subdomains into IP addresses
- Conducting port scanning on IP addresses
- Utilizing Shodan dorks
- Utilizing GitHub dorks
- Scanning for CORS misconfiguration
- Scanning for subdomain takeover
- Scanning for CRLF injection

# Methodology for subdomain recon
- Obtaining IP addresses of subdomains
- Performing directory fuzzing
- Collecting parameters using ParamSpider and Arjun
- Gathering all links from the Wayback Machine
- Extracting and scanning JavaScript (JS) files
- Scanning for Cross-Site Scripting (XSS)
- Collecting possible vulnerable parameters with xss,sqli,lfi,ssrf, and open redirect
- Conducting port scanning
- Running Nuclei on collected parameters

# Installation
```
git clone https://github.com/0x0anas/reconas.git
cd reconas/
sudo chmod +x setup.sh reconas.sh
sudo ./setup.sh
echo "Your_Github_Token" > files/token.txt
shodan init "Your_Shodan_API"
./reconas -h
```
# Usage
`./reconas.sh -h`
This will display the help menu, providing an overview of the available options and their usage.
```

 #####   ######   ####    ####   #    #    ##     ####
 #    #  #       #    #  #    #  ##   #   #  #   #
 #    #  #####   #       #    #  # #  #  #    #   ####
 #####   #       #       #    #  #  # #  ######       #
 #   #   #       #    #  #    #  #   ##  #    #  #    #
 #    #  ######   ####    ####   #    #  #    #   ####   v1

                                                        twitter:0xanas
                                                        by @Anas Ibrahim
Usage:
        ./reconas.sh [options]
Options:
        -h   ,  --help            Print this help message.
        -d   ,  --domain          Check the domain format.
        -tf  ,  --token_file      Enter a file includes github token.
        -sub ,  --subdomain       Enter subdomain to recon it.
```
Specify the target domain by using the `-d` flag followed by the domain name and `-tf` flag followed by your github token file path. For example:
```
sudo ./reconas.sh -d domain.com -tf files/token.txt
```
Specify the target subdomain by using `-sub` flag followed by the subdomain name. For example:
```
sudo ./reconas.sh -sub sub.domain.com
```



