#!/bin/bash

#colors
END="\e[1m"
Red="\e[31m"
BOLDRED="\e[1m${Red}"
GREEN="\e[32m"
BOLDGREEN="\e[1m${GREEN}"
YELLOW="\033[0;33m"
Cyan="\e[0;36m"
BOLDCYAN="\e[1m${Cyan}"
white="\e[0;37m"

#banner for Script to look cool
function banner() {
        echo -e "
${BOLDRED}
 #####   ######   ####    ####   #    #    ##     ####
 #    #  #       #    #  #    #  ##   #   #  #   #
 #    #  #####   #       #    #  # #  #  #    #   ####
 #####   #       #       #    #  #  # #  ######       #
 #   #   #       #    #  #    #  #   ##  #    #  #    #
 #    #  ######   ####    ####   #    #  #    #   ####   v1

                                                        twitter:0xanas
                                                        by @Anas_Ibrahim ${white}"
}

function display_help() {
	echo "Usage: $0 [OPTIONS]..."
	echo "Gathering information and conducting reconnaissance on targets in a creative way."
	echo ""
	echo "Options:"
	echo "	-h: Display this help message"
	echo "	-d: Specify target name"
	echo "	-t: Specify github token file"
	echo "	-s: Specify subdomain"
}

function info() {
	# Get the current date and time.
	current_date=$(date "+%Y-%m-%d %H:%M:%S")
	echo -e "[${BOLDCYAN}INFO${white}] The current date and time: ${BOLDGREEN}$current_date ${white}"

	#Creating info directory
	mkdir info

	# Get the IP address of the domain
	echo -e "${BOLDCYAN}################# Identifying Domain IP ################# ${white}\n"
	dig +short $domain | tee info/domain_ips.txt
	echo -e "\n${BOLDCYAN} [+] Domain ip result saved in ${BOLDGREEN} $PWD/info/domain_ips.txt ${white}\n"
                        
	#Get CIDRs
	echo -e "${BOLDCYAN}################# Identifying Domain CIDRs ################# ${white}\n"
	asnmap -i $PWD/info/domain_ips.txt -silent | tee info/cidrs.txt
	echo -e "\n${BOLDCYAN} [+] CIDR results saved in ${BOLDGREEN} $PWD/info/cidrs.txt ${white}\n"

	#Get info using host command
	echo -e "${BOLDCYAN}################# Scanning host to get NS,MX,TXT,CNAME Records ################# ${white}\n"
	host -t any $domain | tee -a info/host.txt
	echo -e "\n${BOLDCYAN} [+] DNS records results saved in ${BOLDGREEN} $PWD/info/host.txt ${white}\n"

	#Get info using whois command
	echo -e "${BOLDCYAN}################# Collecting info from the target ################# ${white}\n"
	whois $domain | tee -a info/whois.txt
	echo -e "\n${BOLDCYAN} [+] whois results saved in ${BOLDGREEN} $PWD/info/whois.txt ${white} \n"

	#Get info using whatweb
	echo -e "${BOLDCYAN}################# Identifying technologies of the target ################# ${white}\n"
	whatweb -v -a 3 $domain| tee info/whatweb.txt
	echo -e "\n${BOLDCYAN} [+] Identifying technologies results saved in ${BOLDGREEN} $PWD/info/whatweb.txt ${white}\n"

	#Collecting emails
	echo -e "${BOLDCYAN}################# Collecting leaked emails about the company ################# ${white}\n"
	emailharvester -d $domain --noprint | tee info/emails.txt
	echo -e "\n${BOLDCYAN} [+] Emails results saved in ${BOLDGREEN} $PWD/info/emails.txt ${white}\n"
}

function dns() {
	#Create dns directory
	mkdir dns

	echo  -e "${BOLDCYAN}################# DNS Enumeration ################# ${white}\n"
	dnsrecon -d $domain | tee dns/dnsrecon.txt
	echo -e "\n${BOLDCYAN} [+] Results saved in ${BOLDGREEN} $PWD/dns/dnsrecon.txt ${white} \n"

	echo -e "${BOLDCYAN}################# Collecting name servers ################# ${white}\n"
	dnsrecon -d $domain | grep 'NS ' | cut -d ' ' -f 4 | tee dns/name_servers.txt
	echo -e "\n${BOLDCYAN} [+] The Name Servers saved in: ${BOLDGREEN}$PWD/dns/name_servers.txt ${white}\n"

	echo -e "${BOLDCYAN}################# Scanning Zone Transfer ################# ${white}\n"
	for name_server in $name_servers; do
		host -l $domain $name_server | tee  dns/zone_transfer.txt
	done
	echo -e "\n${BOLDCYAN} [+] Zone Transfer saved in: ${BOLDGREEN}$PWD/dns/zone_transfer.txt ${white}\n"
}

function subdomains() {
	#creating subdomains directory
	mkdir subdomains

	# Collecting subdomains using subfinder
	echo -e "${BOLDCYAN}################# Collecting Subdomains using subfinder ################# ${white}\n"
	subfinder -d $domain -silent -o subdomains/subfinder.txt
	echo -e "\n${BOLDCYAN} [+] subdfinder subdomains results saved in ${BOLDGREEN} $PWD/subdomains/subfinder.txt ${white}\n"

	# Collecting subdomains using assetfinder
	echo -e "${BOLDCYAN}################# Collecting Subdomains using assetfinder ################# ${white}\n"
	assetfinder --subs-only $domain | tee subdomains/assetfinder.txt
	echo -e "\n${BOLDCYAN} [+] assetfinder subdomains results saved in ${BOLDGREEN} $PWD/subdomains/assetfinder.txt ${white}\n"

	# Collecting subdomains using amass
	echo -e "${BOLDCYAN}################# Collecting Subdomains using amass ################# ${white}\n"
	amass enum -passive -d $domain -o subdomains/amass.txt
	echo -e "\n${BOLDCYAN} [+] amass subdomains results saved in ${BOLDGREEN} $PWD/subdomains/amass.txt ${white}\n"

	#Collecting subdomains using crt.sh website
	echo -e "${BOLDCYAN}################# Collecting Subdomains using crt.sh ################# ${white}\n"
	curl -s https://crt.sh/\?q\=\$domain\&output\=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | tee subdomains/crt.txt
	echo -e "\n${BOLDCYAN} [+] crt.sh subdomains results saved in ${BOLDGREEN} $PWD/subdomains/crt.txt ${white}\n"
	# Merging all the results into one file
	cat subdomains/*.txt | sort -u | tee subdomains/all_subs.txt

	#Collecting Live Subdomains
	echo -e "${BOLDCYAN}################# Collecting Live Subdomains ################# ${white}\n"
	cat subdomains/all_subs.txt | httpx -mc 200,201,202,203,300,301,302,303,401,403 -silent | tee subdomains/live_subs.txt
	echo -e "\n${BOLDCYAN} [+] Collecting Live Subdomains results saved in ${BOLDGREEN} $PWD/subdomains/live_subs.txt ${white}\n"
}

function ip() {
	#Creating ip directory
	mkdir ip

	#Converting live subdomains into IPs
	echo -e "${BOLDCYAN}################# Converting Live Subdomains into IPs ################# ${white}\n"
	cat $PWD/subdomains/live_subs.txt | cut -d "/" -f 3 | while read line ; do host -t A $line ; done | grep "has address" | cut -d " " -f 4 | sort -u | tee ip/live_ips.txt
	echo -e "\n${BOLDCYAN} [+] Converting Live Subdomains into IPs results saved in ${BOLDGREEN} $PWD/ip/live_ips.txt ${white}\n"


	#Scanning live IPs using naabu command concatenated wit nmap
	echo -e "${BOLDCYAN}################# Scanning Live Subdomains ################# ${white}\n"
	cat $PWD/ip/live_ips.txt | naabu -nmap-cli 'nmap -sV -oX ip/nmap_output.txt'
	echo -e "\n${BOLDCYAN} [+] Scanning Live Subdomains results saved in ${BOLDGREEN} $PWD/ip/nmap_output.txt ${white}\n"
}

# Define a function to run a Shodan search on a given dork
function shodan_search() {
    mkdir shodan  

    #Extract domain name without tld
    echo $domain | cut -d '.' -f 1 | tee tld.txt
    tld=$(cat tld.txt)

    echo -e "${BOLDCYAN} [+] Shodan dorks with the full domain ${white}\n"
    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:21 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A21\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:22 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A22\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:23 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A23\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:25 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A25\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:53 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A53\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:8080 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A8080\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:8888 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A8888\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:8000 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A8000\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}$domain port:3306 ${white}"
    echo -e "https://www.shodan.io/search?query=$domain%20port%3A3306\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}hostname:$domain ${white}"
    echo -e "https://www.shodan.io/search?query=hostname%3A$domain\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}ssl:$domain ${white}"
    echo -e "https://www.shodan.io/search?query=ssl%3A$domain\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}ssl.cert.issuer.cn:$domain ${white}"
    echo -e "https://www.shodan.io/search?query=ssl.cert.issuer.cn%3A$domain\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}ssl.cert.subject.cn:$domain ${white}"
    echo -e "https://www.shodan.io/search?query=ssl.cert.subject.cn%3A$domain ${white}\n"

    echo -e "${BOLDCYAN} [+] Shodan dorks without the TLD: $tld ${white}\n"
    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld 'MongoDB Server Information' port:27017 -authentication ${white}"
    echo -e "${BOLDGREEN}https://www.shodan.io/search?query=org%3A$tld%20%27MongoDB%20Server%20Information%27%20port%3A27017%20-authentication\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld 'Set-Cookie: mongo-express=' '200 OK' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20%27Set-Cookie%3A%20mongo-express=%27%20%27200%20OK%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld mysql port:'3306' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20mysql%20port%3A%273306%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:5432 PostgreSQL ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A5432%20PostgreSQL\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:'9200' all:'elastic indices' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A%279200%27%20all%3A%27elastic%20indices%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld proftpd port:21 ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20proftpd%20port%3A21\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:21 vsftpd 3.0.3 ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A21%20vsftpd%203.0.3\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld '230 Login successful.' port:21 ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20%27230%20Login%20successful.%27%20port%3A21\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld openssh port:22 ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20openssh%20port%3A22\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:'23' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A%2723%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:'25' product:'exim' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A%2725%27%20product%3A%27exim%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:'11211' product:'Memcached' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A%2711211%27%20product%3A%27Memcached%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld 'X-Jenkins' 'Set-Cookie: JSESSIONID' http.title:'Dashboard' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20%27X-Jenkins%27%20%27Set-Cookie%3A%20JSESSIONID%27%20http.title%3A%27Dashboard%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld 'port:53' Recursion: Enabled ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20%27port%3A53%27%20Recursion%3A%20Enabled\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld product:'Apache httpd' port:'80' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20product%3A%27Apache%20httpd%27%20port%3A%2780%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld product:'Microsoft IIS httpd' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20product%3A%27Microsoft%20IIS%20httpd%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld product:'nginx' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20product%3A%27nginx%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld port:8080 product:'nginx' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20port%3A8080%20product%3A%27nginx%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld remote desktop 'port:3389' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20remote%20desktop%20%27portV3389%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld 'authentication disabled' 'RFB 003.008' ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20%27authentication%20disabled%27%20%27RFB%20003.008%27\n"

    echo -e "${BOLDCYAN}Dork: ${YELLOW}org:$tld 'Authentication: disabled' port:445 ${white}"
    echo -e "https://www.shodan.io/search?query=org%3A$tld%20%27Authentication%3A%20disabled%27%20port%3A445 ${white}\n"
}

function google() {
	#Creating google directory
	mkdir google

	#google dorks
	echo -e "${BOLDCYAN}################# Google Dorks ################# ${white}\n"
	python3 dorks_hunter/dorks_hunter.py -d $domain -o google_dorks.txt
	echo -e "\n${BOLDCYAN} [+] Github Dorks results saved in ${BOLDGREEN} $PWD/google/google_dorks.txt ${white}\n"

}

function github() {
	#Creating github directory
	mkdir github

	#github dorks
	echo -e "${BOLDCYAN}################# Github Dorks ################# ${white}\n"
	gitdorks_go -gd $PWD/files/allgithub.txt -nws 20 -target $domain -tf $token_file -ew 3 | tee github/github_dorks.txt
	echo -e "\n${BOLDCYAN} [+] Github Dorks results saved in ${BOLDGREEN} $PWD/github/github_dorks.txt ${white}\n"
}

function vulns() {
	#Creating vulns directory
	mkdir vulns

	#Subdomain takeover
	echo -e "${BOLDCYAN}################# Subdomain Takeover ################# ${white}\n"
	subzy run --targets $PWD/subdomains/all_subs.txt | tee vulns/sub_takeover.txt
	echo -e "\n${BOLDCYAN} [+] Subdomain Takeover results saved in ${BOLDGREEN} $PWD/vulns/sub_takeover.txt ${white}\n"

	#cors misconfiguration
	echo -e "${BOLDCYAN}################# CORS Misconfiguration ################# ${white}\n"
	corscanner -i $PWD/subdomains/live_subs.txt -o vulns/cors.txt
	echo -e "\n${BOLDCYAN} [+] CORS Misconfiguration results saved in ${BOLDGREEN} $PWD/vulns/cors.txt ${white}\n"

	#CRLF Injection
	echo -e "${BOLDCYAN}################# CRLF Injection ################# ${white}\n"
	crlfuzz -l $PWD/subdomains/live_subs.txt -s -o vulns/crlf.txt
	echo -e "\n${BOLDCYAN} [+] CRLF Injection results saved in ${BOLDGREEN} $PWD/vulns/crlf.txt ${white}\n"
}

function digging() {
	# Get the IP address of the domain
	ip=$(dig +short $subdomain)
	echo -e "The IP address of ${BOLDCYAN}$subdomain ${white}is ${BOLDGREEN}$ip ${white}\n"
}

function params() {
	#Creating params directory
	mkdir params

	#Collecting parameters using paramspider
	echo -e "${BOLDCYAN}################# Collecting parameters ################# ${white}\n"
	paramspider -d $subdomain -s | tee params/param1.txt
	echo -e "\n${BOLDCYAN} [+] Collecting parameters results saved in ${BOLDGREEN} $PWD/params/param1.txt ${white}\n"

	#Collecting parameters using arjun
	echo -e "${BOLDCYAN}################# Collecting hidden parameters ################# ${white}\n"
	arjun -u http://$subdomain | tee params/param2.txt
	echo -e "\n${BOLDCYAN} [+] Collecting hidden parameters results saved in ${BOLDGREEN} $PWD/params/param2.txt ${white}\n"
}

function fuzzing() {
	#Creating fuzzing directory
	mkdir fuzzing

	#Fuzzing directories
	echo -e "${BOLDCYAN}################# Directory Fuzzing ################# ${white}\n"
	dirsearch -u http://$subdomain | tee fuzzing/dir.txt
	echo -e "\n${BOLDCYAN} [+] Directory Fuzzing results saved in ${BOLDGREEN} $PWD/fuzzing/dir.txt ${white}\n"

	#Fuzzing directories
	echo -e "${BOLDCYAN}################# Fuzzing backup files ################# ${white}\n"
	dirsearch -u http://$subdomain -w $PWD/files/backup_files_only.txt | tee fuzzing/backup.txt
	echo -e "\n${BOLDCYAN} [+] Fuzzing backup files results saved in ${BOLDGREEN} $PWD/fuzzing/backup.txt ${white}\n"
}

function archive() {
	#Creating archive directory
	mkdir archive

	#Collecting directories and files from archive
	echo -e "${BOLDCYAN}################# Wayback Archive ################# ${white}\n"
	echo "$subdomain" | waybackurls | tee archive/archive.txt
	echo -e "\n${BOLDCYAN} [+] Wayback Archive results saved in ${BOLDGREEN} $PWD/archive/archive.txt ${white}\n"
}

function js() {
	#Creating js directory
	mkdir js

	#Collecting JS Files
	echo -e "${BOLDCYAN}################# Collecting and Scanning JS Files ################# ${white}\n"
	cat $PWD/archive.txt | grep ".js" | tee js/js.txt
	subjs -i js.txt | tee js_scan.txt
	echo -e "\n${BOLDCYAN} [+] Collecting JS Files results saved in ${BOLDGREEN} $PWD/js/js.txt ${white}\n"
}

function gf() {
	#Creating gf directory
	mkdir gf

	#Collecting possible vulnerable links
	echo -e "${BOLDCYAN}################# Collecting Possible Vulnerable XSS Links ################# ${white}\n"
	cat $PWD/param1.txt $PWD/param2.txt $PWD/archive.txt | gf xss > gf/xss_params.txt
	echo -e "\n${BOLDCYAN} [+] Possible Vulnerable XSS Links Saved in ${BOLDGREEN} $PWD/ssrf_params.txt ${white}\n"
	
	#Scanning XSS
	echo -e "${BOLDCYAN}################# Scanning XSS ################# ${white}\n"
	cat xss_params.txt | kxss | tee gf/xss_scan.txt
	echo -e "\n${BOLDCYAN} [+] Scanning XSS Results saved in ${BOLDGREEN} $PWD/gf/xss_scan.txt & $PWD/gf/xss_params.txt ${white}\n"

               
	#Collecting possible vulnerable links
	echo -e "${BOLDCYAN}################# Collecting Possible Vulnerable SQLi Links ################# ${white}\n"
	cat $PWD/param1.txt $PWD/param2.txt $PWD/archive.txt | gf sqli > gf/sqli_params.txt
	echo -e "\n${BOLDCYAN} [+] Possible Vulnerable SQLi Links Saved in ${BOLDGREEN} $PWD/ssrf_params.txt ${white}\n"
                
	#Collecting possible vulnerable links
	echo -e "${BOLDCYAN}################# Collecting Possible Vulnerable SSRF Links ################# ${white}\n"
	cat $PWD/archive.txt | gf ssrf > gf/ssrf_params.txt
	echo -e "\n${BOLDCYAN} [+] Possible Vulnerable SSRF Links saved in ${BOLDGREEN} $PWD/gf/ssrf_params.txt ${white}\n"

	#Collecting possible vulnerable links
	echo -e "${BOLDCYAN}################# Collecting Possible Vulnerable LFI Links ################# ${white}\n"
	cat $PWD/archive.txt | gf lfi > gf/lfi_params.txt
	echo -e "\n${BOLDCYAN} [+] Possible Vulnerable LFI Links saved in ${BOLDGREEN} $PWD/gf/lfi_params.txt ${white}\n"

	#Collecting possible vulnerable links
	echo -e "${BOLDCYAN}################# Collecting Possible Vulnerable IDOR Links ################# ${white}\n"
	cat $PWD/archive.txt | gf idor > sqli_params.txt
	echo -e "\n${BOLDCYAN} [+] Possible Vulnerable SQLi Links saved in ${BOLDGREEN} $PWD/idor_params.txt ${white}\n"

	#Collecting possible vulnerable links
	echo -e "${BOLDCYAN}################# Collecting Possible Vulnerable Redirect Links ################# ${white}\n"
	cat $PWD/archive.txt | gf redirect > gf/redirect_params.txt
	echo -e "\n${BOLDCYAN} [+] Possible Vulnerable Redirect Links saved in ${BOLDGREEN} $PWD/gf/redirect_params.txt ${white}\n"
}

function scan() {
	#Creating scan directory
	mkdir scan

	#Scanning nmap
	echo -e "${BOLDCYAN}################# Port Scanning ################# ${white}\n"
	nmap $ip -T4 -sV -Pn -o scan/nmap.txt
	echo -e "\n${BOLDCYAN} [+] Port Scanning results saved in ${BOLDGREEN} $PWD/scan/nmap.txt ${white}\n"

	#nuclei scan
	echo -e "${BOLDCYAN}################# Finding Bugs from archive ################# ${white}\n"
	cat archive.txt | nuclei | tee scan/nuclei1.txt
	echo -e "\n${BOLDCYAN} [+] Finding Bugs from archive results saved in ${BOLDGREEN} $PWD/scan/nuclei1.txt ${white}\n"

	#nuclei scan
	echo -e "${BOLDCYAN}################# Finding Bugs from parameters ################# ${white}\n"
	cat params*.txt | nuclei | tee scan/nuclei2.txt
	echo -e "\n${BOLDCYAN} [+] Finding Bugs from parameters results saved in ${BOLDGREEN} $PWD/scan/nuclei2.txt ${white}\n"
}

# Check if the user entered any options
if [ $# -eq 0 ]; then
        banner
        echo "Please specify an option.
Use -h for help.
        "
        exit 1
fi

#Check if the user entered the -d option
if [[ $1 == "-d" ]] && [[ $# -eq 1 ]]; then
	echo -e "${Red} Error: -d option requires an argument ${white}"
	exit 1
fi

if [[ $3 == "-t" ]] && [[ $# -eq 3 ]]; then
	echo -e "${Red} Error: The token file must be specified after -t option. ${white}"
	exit 1
fi

#Check if the user entered the -s option
if [[ $1 == "-s" ]] && [[ $# -eq 1 ]]; then
	echo -e "${Red} Error: -s option requires an argument ${white}"
	exit 1
fi

# Parse command-line arguments
while getopts ":hdtsa:" opt; do
	case ${opt} in
		h )
			banner
			display_help
			exit 0
			;;
		d )
			domain=$2
			banner
			info
			dns
			subdomains
			ip
			shodan_search
			google
			vulns
			;;
		t )
			token_file=$4
			github
			;;
		s )
			subdomain=$2
			banner
            digging
            params
            fuzzing
            archive
            js
            gf
            scan
            ;;
		\? )
			echo "Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
		esac
done
