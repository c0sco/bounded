bounded v0.9
=======

Blackhole hosts abusing your name server.

Setup
-----
bounded.py generates and updates a blackhole.conf to ban IP addresses (and the zones they use) that abuse your name server. Currently assumes a BIND 9 format.

Add a blackhole.conf include line in the options section of your named.conf, like so

    include "/etc/namedb/blackhole.conf";

If you use a path other than /etc/namedb/blackhole.conf, specify the file with the -o flag. bounded.py will initialize the file in the proper format, no need to create the file yourself. See bounded.py -h for more information.

Usage
-----
All you need to get started is to specify the interface to listen for packets on.

    bounded.py -i <interface> [options]

You probably also want to exclude some IPs and zones from being tracked for banning. Use -x to specify clients that are allowed to use your server for recursion, and -z to specify the zones that you are authoritative for. See also -X and -Z options. For example:

    bounded.py -i if1 -z mydomain.com -x 127.0.0.1 -x 10.20.30.40
