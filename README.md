Srelay - the SOCKS proxy and Relay (with Randomized Balancing)
==============================================================
phoeagon

Added *randomized* downstream balancing: when multiple rules apply, choose any
in a random way.
Added *prioritized random* downstreaming: when multiple downstreams available,
maintain a list of priorities of each downstream. Penalize a downstream if
a connection to it fails. Choose a random downstream in prioritized way. (Useful
for load-balancing multiple SOCKS5 proxy server).

Eg:

		srelay -i 0.0.0.0:9999 \ # Listen on 9999 port
			-P -R \ # Randomized, prioritized
			-c config.conf \ # Choose a config file
			-f  # Stay forground.

The original repo was imported from 
[sourceforge](http://socks-relay.sourceforge.net/).

What is it?
============

* Srelay is a socks 4/5 protocol proxy server.
* Supports socks connect/bind request in the protocol v4, v4a, and v5.
* Supports socks server chaining with both v4 and v5 servers.
* Supports Username/Password authentication in v5 (not recommended).
* Testing on FreeBSD 8.1R, Solaris 8, 10, Linux-i386, MacOS 10.5.
* Supports IPv6 as well as IPv4.
* Srelay is Free.
	      
Documents
=========

Config Sample: [basic config](http://socks-relay.sourceforge.net/samples.html)

References
==========
(These document links do not assure the compliancy of this software. Yeah, indeed.)

* [SOCKS Protocol Version 4](http://socks-relay.sourceforge.net/socks4.protocol.txt)
* [SOCKS Protocol Version 4A socks 4a](http://socks-relay.sourceforge.net/socks4a.protocol.txt)
* SOCKS Protocol Version 5 [RFC 1928](http://www.ietf.org/rfc/rfc1928.txt)
* Username/Password Authentication for SOCKS V5 [RFC 1929](http://www.ietf.org/rfc/rfc1929.txt)
