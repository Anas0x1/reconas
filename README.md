# Reconas
Reconas is a powerful and customizable reconnaissance tool designed to assist in information gathering and vulnerability assessment during security assessments and bug hunting. It provides a comprehensive set of features and modules that automate various reconnaissance tasks, helping security professionals gather valuable intelligence about target systems and identify potential vulnerabilities.
# Installation
```
git clone https://github.com/0x0anas/reconas.git
cd reconas/
echo "Your_Github_Token" > files/token.txt
sudo chmod +x setup.sh reconas.sh
./setup.sh
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
./reconas.sh -d domain.com -tf files/token.txt
```
Specify the target subdomain by using `-sub` flag followed by the subdomain name. For example:
```
./reconas.sh -sub sub.domain.com
```



