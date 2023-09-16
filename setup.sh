#!/bin/bash

#Update System
sudo apt-get update

#Upgrade System
sudo apt-get upgrade

#Install dns utilization tools
sudo apt-get install dnsutils -y

#Install dnsrecon
pip3 install dnsrecon

#Install emailharvester
pip3 install emailharvester

#Install whois
sudo apt install whois

#Install asnmap
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

#Install WhatWeb
pip3 install whatweb

#Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

#Install assetfinder
go install -v github.com/tomnomnom/assetfinder@latest

#Install amass
go install -v github.com/owasp-amass/amass/v4/...@master

#Install naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

#Install uncover
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

#Install gitdorks-go
go install github.com/damit5/gitdorks_go@latest

#Install waybackurls
go install github.com/tomnomnom/waybackurls@latest

#Install httpx
pip3 install httpx

#Install arjun
pip3 install arjun

#Install paramspider
pip3 install paramspider

#Install nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

#Install subzy
go install -v github.com/LukaSikic/subzy@latest

#Install corscanner
pip3 install corscanner

#Install crlfuzz
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

#Install 

#Install dirsearch
pip3 install dirsearch

#Install subjs
go install github.com/lc/subjs@latest@latest

#Install shodan
pip3 install shodan
