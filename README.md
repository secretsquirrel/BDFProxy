
##The Backdoor Factory Proxy (BDFProxy) v0.1
For security professionals and researchers only.

This script rides on two libraries for usage:
The Backdoor Factory (BDF) and the mitmProxy.

###Concept:
Patch binaries during download via MITM.

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

Yes, some of those apps are protected by self checking mechanisms.  I've been working on a way to automatically bypass NSIS checks as a proof of concept.  However, that does not stop the initial issue of bitflipping during download and the execution of a malicious payload. Also, BDF by default will patch out the certificate table pointer during download thereby removing the signature from the binary.

---

##Depends:

	Pefile - most recent
	ConfigObj  
	mitmProxy - Kali Build .10
	BDF - most current


---
##Supported Env
Tested on all Kali Linux Builds, whether a physical beefy laptop, a Raspberry Pi, or a VM, each can run BDFProxy. 


##USAGE:

READ THE CONFIG!!! -> bdfproxy.cfg

You will need to configure your C2host and port settings before running BDFProxy. DO NOT overlap C2 PORT settings between different payloads. You'll be sending linux shells to windows machines and things will be segfaulting all over the place. After running, there will be a metasploit resource script created to help with setting up your C2 communications. Check it carefully. By the way, everything outside the [Overall] section updates on the fly, so you don't have to kill your proxy to change settings to work with your environment.

But wait!  You will need to configure your mitm machine for mitm-ing!  If you are using a wifiPineapple I modded a script put out by hack5 to help you with configuration. Run ./wpBDF.sh and enter in the correct configs for your environment.

LOGGING: We have it.  The proxy window will quickly fill with massive amounts of cat links depending on the client you are testing.  Use tail -f proxy.log to see what is getting patched and blocked by your blacklist settings.  However, keep an eye on the main proxy window if you have chosen to patch binaries manually, things move fast and behind the scences there is multi-threading of traffic, but the intial requests and responses are locking for your viewing pleasure.

Here's some sweet ascii art for possible phyiscal settings of the proxy:

Lan usage:

		<Internet>----<mitmMachine>----<userLan>

Wifi usage:

		<Internet>----<mitmMachine>----<wifiPineapple>)))