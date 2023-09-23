#!/bin/bash

#Update System
sudo apt-get update

#Install dns utilization tools
sudo apt-get install dnsutils -y

#install dorks_hunter
git clone https://github.com/six2dez/dorks_hunter.git

#Install dnsrecon
if ! command -v dnsrecon -h &> /dev/null
		then
		echo "installing dnsrecon now"
		pip3 install dnsrecon &> /dev/null
		echo "httpx has been installed "

else
        echo "dnsrecon is already installed"
fi


#Install emailharvester
if ! command -v emailharvester -h &> /dev/null
		then
		echo "installing emailharvester now"
		pip3 install emailharvester &> /dev/null
		echo "emailharvester has been installed "

else
        echo "emailharvester is already installed"
fi

#Install whois
if ! command -v whois -h &> /dev/null
		then
		echo "whois emailharvester now"
		sudo apt install whois &> /dev/null
		echo "whois has been installed "

else
        echo "whois is already installed"
fi

#Install asnmap
if ! command -v asnmap -h &> /dev/null
		then
		echo "installing asnmap now"
		go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest &> /dev/null
		echo "asnmap has been installed "

else
        echo "asnmap is already installed"
fi


#Install WhatWeb
if ! command -v whatweb -h &> /dev/null
		then
		echo "installing whatweb now"
		pip3 install whatweb &> /dev/null
		echo "whatweb has been installed "

else
        echo "whatweb is already installed"
fi

#Install subfinder
if ! command -v subfinder -h &> /dev/null
		then
		echo "installing subfinder now"
		go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &> /dev/null
		echo "subfinder has been installed "

else
        echo "subfinder is already installed"
fi


#Install assetfinder
if ! command -v assetfinder -h &> /dev/null
		then
		echo "installing assetfinder now"
		go install -v github.com/tomnomnom/assetfinder@latest &> /dev/null
		echo "assetfinder has been installed "

else
        echo "assetfinder is already installed"
fi


#Install amass
if ! command -v amass -h &> /dev/null
		then
		echo "installing amass now"
		go install -v github.com/owasp-amass/amass/v4/...@master &> /dev/null
		echo "amass has been installed "

else
        echo "amass is already installed"
fi

#Install naabu
if ! command -v naabu -h &> /dev/null
		then
		echo "installing naabu now"
		go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &> /dev/null
		echo "naabu has been installed "

else
        echo "naabu is already installed"
fi



#Install gitdorks-go
if ! command -v gitdorks-go -h &> /dev/null
		then
		echo "installing gitdorks-go now"
		go install github.com/damit5/gitdorks_go@latest &> /dev/null
		echo "gitdorks-go has been installed "

else
        echo "gitdorks-go is already installed"
fi


#Install waybackurls
if ! command -v waybackurls -h &> /dev/null
		then
		echo "installing waybackurls now"
		go install github.com/tomnomnom/waybackurls@latest &> /dev/null
		echo "waybackurls has been installed "

else
        echo "waybackurls is already installed"
fi

#Install httpx
if ! command -v httpx -h &> /dev/null
		then
		echo "installing httpx now"
		pip3 install httpx &> /dev/null
		echo "httpx has been installed "

else
        echo "httpx is already installed"
fi


#Install arjun
if ! command -v arjun -h &> /dev/null
		then
		echo "installing arjun now"
		pip3 install arjun &> /dev/null
		echo "arjun has been installed "

else
        echo "arjun is already installed"
fi

#Install paramspider
if ! command -v paramspider -h &> /dev/null
		then
		echo "installing paramspider now"
		pip3 install paramspider &> /dev/null
		echo "paramspider has been installed "

else
        echo "paramspider is already installed"
fi

#Install nuclei
if ! command -v nuclei -h &> /dev/null
		then
		echo "installing nuclei now"
		go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest &> /dev/null
		echo "nuclei has been installed "

else
        echo "nuclei is already installed"
fi

#Install subzy
if ! command -v subzy -h &> /dev/null
		then
		echo "installing subzy now"
		go install -v github.com/LukaSikic/subzy@latest &> /dev/null
		echo "subzy has been installed "

else
        echo "subzy is already installed"
fi

#Install corscanner
if ! command -v corscanner -h &> /dev/null
		then
		echo "installing corscanner now"
		pip3 install corscanner &> /dev/null
		echo "corscanner has been installed "

else
        echo "corscanner is already installed"
fi


#Install crlfuzz
if ! command -v crlfuzz -h &> /dev/null
		then
		echo "installing crlfuzz now"
		go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest &> /dev/null
		echo "crlfuzz has been installed "

else
        echo "crlfuzz is already installed"
fi

#Install dirsearch
if ! command -v dirsearch -h &> /dev/null
		then
		echo "installing dirsearch now"
		pip3 install dirsearch &> /dev/null
		echo "dirsearch has been installed "

else
        echo "dirsearch is already installed"
fi

#Install subjs
if ! command -v subjs -h &> /dev/null
		then
		echo "installing subjs now"
		go install github.com/lc/subjs@latest@latest &> /dev/null
		echo "subjs has been installed "

else
        echo "subjs is already installed"
fi
