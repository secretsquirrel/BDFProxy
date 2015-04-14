
#The Backdoor Factory Proxy (BDFProxy) v0.3.2
For security professionals and researchers only.

###NOW ONLY WORKS WITH MITMPROXY >= v.0.11 

To install on Kali:

```
apt-get update
apt-get install bdfproxy
```

DerbyCon 2014 Presentation: http://www.youtube.com/watch?v=LjUN9MACaTs

About 18 minutes in is the BDFProxy portion.

Contact the developer on:
	
	IRC:
 	irc.freenode.net #BDFactory 

 	Twitter:
 	@midnite_runr

This script rides on two libraries for usage:
The Backdoor Factory (BDF) and the mitmProxy.

###Concept:
Patch binaries during download ala MITM.

###Why:
Because a lot of security tool websites still serve binaries via non-SSL/TLS means.

Here's a short list:

		sysinternals.com
		Microsoft - MS Security Essentials
		Almost all anti-virus companies
		Malwarebytes
		Sourceforge
		gpg4win
		Wireshark
		etc...

Yes, some of those apps are protected by self checking mechanisms.  I've been working on a way to automatically bypass NSIS checks as a proof of concept.  However, that does not stop the initial issue of bitflipping during download and the execution of a malicious payload. Also, BDF by default will patch out the windows PE certificate table pointer during download thereby removing the signature from the binary.

---

##Depends:

	Pefile - most recent
	ConfigObj  
	mitmProxy - Kali Build .10
	BDF - most current
	Capstone (part of BDF)

---
##Supported Environment:
Tested on all Kali Linux builds, whether a physical beefy laptop, a Raspberry Pi, or a VM, each can run BDFProxy. 


##Install:
BDF is in bdf/ 

Run the following to pull down the most recent:

	./install.sh

OR:

	git clone https://github.com/secretsquirrel/the-backdoor-factory bdf/


If you get a certificate error, run the following:

	mitmproxy

And exit [Ctr+C] after mitmProxy loads.


##Usage:
Update everything before each use:

	./update.sh

READ THE CONFIG!!!

		-->bdfproxy.cfg

You will need to configure your C2 host and port settings before running BDFProxy. DO NOT overlap C2 PORT settings between different payloads. You'll be sending linux shells to windows machines and things will be segfaulting all over the place. After running, there will be a metasploit resource script created to help with setting up your C2 communications. Check it carefully. By the way, everything outside the [Overall] section updates on the fly, so you don't have to kill your proxy to change settings to work with your environment.

But wait!  You will need to configure your mitm machine for mitm-ing!  If you are using a wifiPineapple I modded a script put out by hack5 to help you with configuration. Run ./wpBDF.sh and enter in the correct configs for your environment.  This script configures iptables to push only http (non-ssl) traffic through the proxy.  All other traffic is fowarded normally.

Then:

	./bdf_proxy.py


Here's some sweet ascii art for possible phyiscal settings of the proxy:

Lan usage:

		<Internet>----<mitmMachine>----<userLan>

Wifi usage:

		<Internet>----<mitmMachine>----<wifiPineapple>)))


##Testing:

	Suppose you want to use your browser with Firefox and FoxyProxy to connect to test your setup.

		Update your config as follows:
		transparentProxy = None

		Configure FoxyProxy to use BDFProxy as a proxy.
		Default port in the config is 8080.



##Logging: 
We have it.  The proxy window will quickly fill with massive amounts of cat links depending on the client you are testing.  Use `tail -f proxy.log` to see what is getting patched and blocked by your blacklist settings.  However, keep an eye on the main proxy window if you have chosen to patch binaries manually, things move fast and behind the scences there is multi-threading of traffic, but the intial requests and responses are locking for your viewing pleasure.

##Attack Scenarios (all with permission of targets):
	-Evil Wifi AP
	-Arp Redirection
	-Physical plant in a wiring closet
	-Logical plant at your favorite ISP

