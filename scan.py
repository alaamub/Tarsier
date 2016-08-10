#!/usr/bin/env python
# encoding: utf-8
"""
scan.py
Created by Aladdin Mubaied on 2014-11-10.

Tarsier is a distributed scanning tool implemented in python. It uses unicorn scanner 
for scanning on large scale, and it also uses an open source scripts in combination to
detect heartbleed, CCS, and Shellshock attacks in a very fast manner.

The tool requires the following packages:
1. unicornscan
2. dnspython
"""
import sys, getopt, subprocess, dns.query, dns.zone, dns.resolver, socket, shlex, progressbar 
from time import sleep
from subprocess import Popen, PIPE
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *
from DnsDB import DnsDB
from sys import stdout
from yProgressBar import yProgressBar

# defining the main class here
# you need to provide the IP range or single IP for Tarsier to start scanning .

class Tarsier:
	def __init__(self):
		self.argv = sys.argv[1:]

	# zone transfer attack test
	def zoneTransfer(self):
		print '++++++++++++++++++++++++++++++++++++++++++++++++++'
		print 'Stage 2: Trying Zone transfer Attack'
		print '++++++++++++++++++++++++++++++++++++++++++++++++++'
		print "Getting NS records for", self.ydomain
		answers = dns.resolver.query(self.ydomain, 'NS')
		ns = []
		for rdata in answers:
			n = str(rdata)
			print "Found name server:", n
			ns.append(n)
		for n in ns:
			print "\nTrying a zone transfer for %s from name server %s" % (self.ydomain, n)
			try:
				zone = dns.zone.from_xfr(dns.query.xfr(n, self.ydomain, relativize=False, lifetime=2))
			except DNSException, e:
				print "Zone transfer is not allowed for", n
	
	# get list of IP addresses from all-subdomains
	def getIPSpace(self):
		# to do: replace self.ydomain with the list from collectDomains() function.
		# using headless user account, grab DNS information from the server for the specified domain.
		print 'Connectiong to Y! DNS Server, please wait, this may take a few minutes ...'
		# showing progress bar for connectiong
		#threads = []
		#progress_bar = yProgressBar()
		#threads.append(progress_bar)
		#progress_bar.start()
		key = "headless_readonly_pass"
		passw = PASSWORD
		my_dnsdb = DnsDB(user="headless_readonly", pw=passw)
		record_list = my_dnsdb.Record.find(name="%"+self.ydomain+"%")
		# get all IP space for the collected domains
		self.myList = []
		# ending progressbar 
		#while len(threads) > 0:
                #        try:
                #                threads = [progress_bar.join(1) for progress_bar in threads if progress_bar is not None and progress_bar.isAlive()]
                #        except KeyboardInterrupt:
                #                print "Ctrl-c received! Sending kill to threads..."
                #                for progress_bar in threads:
                #                        progress_bar.kill_received = True
		#progress_bar.stop()
		# defining progress bar for unicornscan 100% style
		bar = progressbar.ProgressBar(maxval=20, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
		i = 0
		for record in record_list:
			try:
				bar.update(i+1)
				sleep(0.1)
				ipList = socket.gethostbyname(record.name)
				self.myList.append(ipList)
			except:
				continue	
		bar.finish()
		print "Starting The Scan! ... "
		return self.myList

	# kick off unicornscan with list of Ip ranges
	def scanUnicorn(self):
		print '++++++++++++++++++++++++++++++++++++++++++++++++++'
                print 'Stage 1: Scanning .. "' + self.ydomain + '"'
                print '++++++++++++++++++++++++++++++++++++++++++++++++++'
		p = subprocess.Popen(["unicornscan","-vmT"] + self.getIPSpace(), stdin=PIPE, stdout=PIPE).stdout.read()
		print p
	
	# defining the main function 		
	def main(self):
		ydomain = ''
   		try:
			opts, args = getopt.getopt(self.argv,"i:h",["ydomain=", "help"])
		except getopt.GetoptError:
      			print 'scan.py -i <ydomain>'
      			sys.exit(2)
		for opt, arg in opts:
			if opt == '-h':
				print 'scan.py -i <ydomain>'
         			sys.exit()
      			elif opt in ("-i", "--y-domain"):
         			ydomain = arg
   		if ydomain != '':
			self.ydomain = ydomain
			
			# trying Zone transfer for the domain 
			#self.zoneTransfer()
			
			# kickoff unicornscan for the domains
			self.scanUnicorn()
			
			# If port 443 is allowed check heartbleed, and CCS
		 
   		else:
			print 'please provide the domain name, example: yahoo.com'
			print 'scan.py -i <ydomain>'
        		sys.exit()

if __name__ == "__main__":
	scan = Tarsier()
	scan.main()
