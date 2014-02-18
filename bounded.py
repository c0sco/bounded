#!/usr/bin/env python
"""
bounded 0.9: Blackhole hosts abusing your BIND server.

See bounded.py -h for usage.

Matt Stofko <matt@mjslabs.com>
"""

# To do:
## Expire bans of zones and hosts
## Support logrotate (HUP)
## Cas support for multinode use

import sys
import os
import pwd
import grp
import time
import signal
import re
from optparse import OptionParser
import subprocess
import daemon
import datetime
import fileinput
import memcache
import dpkt, pcap
import socket
import dnslib


def process(pkt):
	""" Process packets and determine if their sender needs to be blocked. """
	# Who are we dealing with?
	srcip = socket.inet_ntoa(pkt.ip.src)

	# Skip if it's in our exclusions list
	if opt.exclude and srcip in opt.exclude:
		debug("Excluding query from %s" % srcip)
		return

	try:
		d = dnslib.DNSRecord.parse(pkt.ip.data.data)

	except:
		# Could not parse packet as a DNS request
		return

	if len(d.questions) == 0:
		log("No questions? " + str(d.questions))
		return

	q = d.questions[0]
	if len(d.questions) > 1:
		log("More than one question: %s" % d.questions)

	# Normalize the zone in question
	qname = ''.join([c if ord(c) > 44 and ord(c) < 127 else '--' for c in str(q.qname).lower()])
	if qname == "":
		return

	if exclusion(qname):
		debug("Excluding query for %s" % qname)
		return

	# Query key is name:type
	mq = re.findall(r'^(?:.*?\.)?(\w+\.\w{2,3})$', qname)
	if len(mq) > 0 and mq[0]:
		query = "%s:%s" % (mq[0], q.qtype)

	else:
		query = "%s:%s" % (qname, q.qtype)

	# Get our hit counters in memcached
	qhits = mc.get(query)
	shits = mc.get(srcip)

	if opt.banhammer:
		# -B set, and the zone/query wasn't in our exclude list
		if qhits != "blocked":
			debug("Using the banhammer on zone %s" % query)
			qhits = banZone(query, 1)

		if shits != "blocked":
			debug("Using the banhammer on IP %s" % srcip)
			shits = banIP(srcip, query)

		return

	else:
		# Add the query and the source IP to memcached, or increment their counters if they exist already
		addOrInc(query)
		addOrInc(srcip)
		# Refresh our hit counters
		qhits = mc.get(query)
		shits = mc.get(srcip)

	if qhits and qhits != "blocked":
		debug("Query %s: %d hits" % (query, qhits))

	if shits and shits != "blocked":
		debug("%s: %d hits" % (srcip, shits))

	# Check the hits against this specific query
	if qhits:
		if qhits != "blocked" and qhits >= opt.qcount:
			# This query isn't blocked, but it now needs to be.
			qhits = banZone(query, qhits)

		if qhits == "blocked" and shits and shits != "blocked":
			# We have a currently unblocked host trying to query a banned zone. Ban them.
			return banIP(srcip, query)

	if shits and shits != "blocked" and shits >= opt.count:
		# This host isn't blocked, but it now needs to be.
		banIP(srcip, query)

	return


def banIP(ip, query):
	resolved = resolve(ip)
	mc.set(ip, "blocked", time=opt.block)
	addBlackhole(ip)
	log("[%s] Blocking %s%s due to query %s" % (datetime.datetime.now(), ip, resolved, query))
	return "blocked"


def banZone(zone, hits):
	mc.set(zone, "blocked", time=opt.block)
	log("[%s] Blocking query %s due to %d hits" % (datetime.datetime.now(), zone, hits))
	return "blocked"


def exclusion(qname):
	""" Check the exclusion list for the packet source. """
	if opt.zones:
		# Find the zone that's being queried
		mq = re.findall(r'^(?:.*?\.)?([a-z0-9\-]+\.\w{2,})$', qname)
		if len(mq) > 0:
			# Is it in our exclusion list?
			if mq[0] in opt.zones:
				return True

		else:
			# Check for reverse DNS
			mq = re.findall(r'^(?:\d{1,3}\.){4}in-addr.arpa$', qname)
			if len(mq) > 0:
				if mq[0] in opt.zones:
					return True

			else:
				debug("Couldn't parse '%s' to see if it should be excluded" % qname)
				return False

	return False


def addOrInc(key):
	""" Initialize a key in memcached, or increment it's value if it already exists. """
	if mc.add(key, 1, time=opt.reset) == 0:
		# Already there, but not blocked, increment the counter
		v = mc.get(key)
		if v and v != "blocked":
			if not mc.set(key, int(v)+1, time=opt.reset):
				debug("Couldn't increment %s. Is memcached running?" % key)
				return -1

			return v

	return -1


def resolve(ip):
	""" Return a log-formatted string with the reverse DNS (or not) for a given IP. """
	if opt.resolve:
		try:
			resolved = " (" + socket.gethostbyaddr(ip)[0] + ")"

		except:
			resolved = " (host name not found)"

		return resolved

	else:
		return ""


def rndcReconfig():
	""" Run `rndc reconfig` to make BIND read the updated blackhole.conf """
	return subprocess.Popen(['rndc', 'reconfig'])


def alarmHandler(signum, frame):
	""" Run rndcReconfig() on a SIGALRM """
	global gtimer
	rndcReconfig()
	gtimer = time.time()
	return signal.signal(signal.SIGALRM, signal.SIG_IGN)


def checkAndInitBlackhole():
	""" Make a blackhole.conf in the expected format, should one not exist """
	if not os.path.exists(opt.blackhole):
		try:
			f = open(opt.blackhole, "w")
			f.write("blackhole {\n};\n")
			f.close()

		except:
			sys.exit("Can't initialize %s." % opt.blackhole)

		return True
	else:
		try:
			f = open(opt.blackhole, "r+")

		except:
			sys.exit("Can't open %s for reading/writing." % opt.blackhole)

		if not f.readline() == 'blackhole {\n':
			f.close()
			sys.exit("Blackhole file %s exists but is not in expected format. Remove the file and it will be initialized." % opt.blackhole)

		f.seek(-3, 2)
		if not f.readline() == '};\n':
			f.close()
			sys.exit("Blackhole file %s exists but is not in expected format. Remove the file and it will be initialized." % opt.blackhole)

		f.close()

	return False


def addBlackhole(srcip):
	""" Add an IP to blackhole.conf and tell BIND to reread its config file. """
	if opt.test:
		return

	try:
		# Go to the end of the file and write the IP, and close out the blackhole block
		f = open(opt.blackhole, 'r+')
		f.seek(-3, 2)
		f.writelines([srcip, ';\n', '};\n'])
		f.close()
		os.chown(opt.blackhole, uid, gid)

	except:
		log("Can't add entry to blackhole file: %s" % opt.blackhole)
		return

	global gtimer
	if gtimer and int(time.time()) - int(gtimer) > opt.throttle:
		rndcReconfig()
		gtimer = time.time()
		signal.alarm(0)
		signal.signal(signal.SIGALRM, signal.SIG_IGN)

	else:
		if signal.getsignal(signal.SIGALRM) == 0 or signal.getsignal(signal.SIGALRM) == 1:
			signal.signal(signal.SIGALRM, alarmHandler)
			signal.alarm(opt.throttle)

	return


def debug(msg):
	""" Output debugging info. """
	if opt.debug:
		print msg

	return


def log(msg):
	""" Write an entry to the log file. """
	debug(msg)

	try:
		f = open(opt.log, 'a')
		print >>f, msg
		f.close()

	except:
		debug("Couldn't write to log file %s!" % opt.log)

	return


def pcaploop():
	""" Initialize libpcap and start processing packets. """
	pc = pcap.pcap(name=opt.iface, immediate=True, promisc=False)
	# Use a generic filter to get around bugs on certain systems
	pc.setfilter('tcp or udp')

	try:
		debug("Listening on %s: %s" % (pc.name, pc.filter))
		for ts, pkt in pc:
			ethp = dpkt.ethernet.Ethernet(pkt)
			if hasattr(ethp, 'ip') and hasattr(ethp.ip, 'data') and hasattr(ethp.ip.data, 'dport') and int(ethp.ip.data.dport) == int(opt.port):
				process(ethp)

	except KeyboardInterrupt:
		debug("Received interrupt. Exiting.")
		exit()


def main():
	""" Get it started. """
	if not opt.fore:
		daemon.daemonize(opt.pid)

	pcaploop()


if __name__ == '__main__':
	# Timer for rndc throttling
	gtimer = True

	# Parse command line options
	default = " (default: %default)"
	o = OptionParser(usage="Usage: %prog -i <iface> [options]")
	o.add_option("-b", "--block", dest="block", type="int", help="Seconds until a ban on an IP or zone expires." + default)
	o.add_option("-B", "--banhammer", dest="banhammer", action="store_true", help="Ban any IP or zone that isn't in the exclusion list." + default)
	o.add_option("-c", "--count", dest="count", type="int", help="Number of hits in -r seconds before an IP ban." + default)
	o.add_option("-d", "--debug", dest="debug", action="store_true", help="Print output helpful debugging. Presumes -f." + default)
	o.add_option("-f", "--foreground", dest="fore", action="store_true", help="Stay running in the foreground." + default)
	o.add_option("-g", "--gid", dest="gid", help="GID to chown blackhole.conf to." + default)
	o.add_option("-i", "--interface", dest="iface", help="Interface to listen on")
	o.add_option("-l", "--log", dest="log", help="File to log to." + default)
	o.add_option("-m", "--memcached", dest="memcached", help="IP:port for the memcached server to use." + default)
	o.add_option("-o", "--blackhole", dest="blackhole", help="Path to blackhole.conf where banned IPs are placed." + default)
	o.add_option("-p", "--port", dest="port", help="Port that BIND is listening on." + default)
	o.add_option("-P", "--pid", dest="pid", help="Where to write the PID to.")
	o.add_option("-q", "--qcount", dest="qcount", type="int", help="Number of hits in -r seconds before a zone ban." + default)
	o.add_option("-r", "--reset", dest="reset", type="int", help="Seconds until the hits reset (-c/-q hits in -r seconds)." + default)
	o.add_option("-R", "--resolve", dest="resolve", action="store_true", help="Try to resolve IPs when logging them." + default)
	o.add_option("-t", "--test", dest="test", action="store_true", help="Print out what would have been blocked, but don't actually block anything." + default)
	o.add_option("-T", "--throttle", dest="throttle", type="int", help="Run rndc to read blackhole.conf no more than once every -T seconds." + default)
	o.add_option("-u", "--user", dest="uid", help="UID to chown blackhole.conf to." + default)
	o.add_option("-x", "--exclude", dest="exclude", action="append", help="IP to exclude from blocking.")
	o.add_option("-X", "--exfile", dest="exfile", help="File listing IPs (one per line) to exclude from blocking")
	o.add_option("-z", "--zone", dest="zones", action="append", help="Zone to exclude from blocking.")
	o.add_option("-Z", "--zonefile", dest="zonefile", help="File listing zones (one per line) to exclude from blocking")
	o.set_defaults(
		uid="root",
		gid="bind",
		blackhole="/etc/namedb/blackhole.conf",
		port=53,
		count=200,
		qcount=100,
		log="/var/log/bounded.log",
		memcached="127.0.0.1:11211",
		block=0,
		reset=60,
		fore=False,
		resolve=False,
		debug=False,
		test=False,
		throttle=5,
		banhammer=False,
		pid="/var/run/bounded.pid",
		exclude=[],
		zones=[]
	)
	(opt, args) = o.parse_args()

	debug("Debug level output is on")

	if os.geteuid() != 0:
		sys.exit("You must be root to proceed. Exiting.")

	# Make sure blackhole.conf is there and valid
	checkAndInitBlackhole()

	# Stay in front if debug is specified
	if opt.debug:
		opt.fore = True

	# Check that the specified uid/gid exists on the system
	try:
		uid = pwd.getpwnam(opt.uid).pw_uid
		gid = grp.getgrnam(opt.gid).gr_gid

	except:
		sys.exit("Can't find UID/GID %s/%s" % (opt.uid, opt.gid))

	if not opt.iface:
		sys.exit("Please specify the network interface to listen on with -i.")

	# Excludes file
	if opt.exfile:
		try:
			f = open(opt.exfile)
			opt.exclude += [l.strip() for l in f.readlines()]
			f.close()

		except:
			sys.exit("Can't open and parse %s" % opt.exfile)

	# Dedup and send to those who debug
	opt.exclude = list(set(opt.exclude))
	debug("Adding IP exclusions: %s" % (opt.exclude))

	# Zone excludes
	if opt.zonefile:
		try:
			f = open(opt.zonefile)
			opt.zones += [l.strip() for l in f.readlines()]
			f.close()

		except:
			sys.exit("Can't open and parse %s" % opt.zonefile)

	# Dedup and send to those who debug
	opt.zones = list(set(opt.zones))
	debug("Adding zone exclusions: %s" % (opt.zones))

	# Check the connection to memcached before continuing
	mc = memcache.Client([opt.memcached])
	for s in mc.servers:
		if s.connect() == 1:
			main()
			break

	else:
		sys.exit("Can't connect to memcached. Exiting.")
