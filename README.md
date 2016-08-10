## Tarsier

Tarsier is a distributed scanning tool implemented in python. It uses unicorn scanner for scanning on a large scale, and it also uses an open source scripts in combination to detect heartbleed, CCS, and Shellshock attacks in a very fast manner.

- running a fast massive scan in the network.
- you need to provide the domain/IP for Tarsier to start scanning .
- trying Zone transfer for the domain	
- grab all the IP space for this domain from custom vips.
- kickoff unicornscan for the list of domains/IPs
- port 443 is opened check heartbleed, and CCS	
- check shellshock .
- add nmap --script ssl-cert,ssl-enum-ciphers -p 443,465,993,995 domain.com 
