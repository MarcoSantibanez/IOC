# Ioc
Analyzed an artifact using VirusTotal and captured details about its related indicators of compromise using the Pyramid of Pain.

Tools used: *VirusTotal(https://www.virustotal.com/gui/home/upload)*
            *SIEM tool: Splunk Cloud*
            *Google Slides*

As level one security operations center (SOC) analyst at a financial services company. I received an alert about a suspicious file being downloaded on an employee's computer. 

I investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 

You retrieve the malicious file and create a SHA256 hash of the file.

After assigning the file hash, I used VirusTotal to uncover additional IoCs that are associated with the file.

VirusTotal results:
![image](https://github.com/MarcoSantibanez/IOC/assets/138132151/40c3496f-5796-4f4b-a9ee-6968937dcb99)


Illustration of the Pyramid of Pain:

![image](https://github.com/MarcoSantibanez/IOC/assets/138132151/b0287440-2d41-499f-b4bc-f16f17050ed7)


According to David J Bianco the pyramid Iocs are:
David J Bianco himself:

1. *Hash values: SHA1, MD5, or other similar hashes that correspond to specific suspicious or malicious files. Hash values are often used to provide unique references to specific samples of malware or to files involved in an intrusion.*

2.*IP addresses: As the name suggests, but also includes netblocks.*

2. *Domain names: A domain name itself, or sub domains.* 

3.*Network Artifacts: Adversaries’ network activities that are observable. Typical examples include URI patterns, C2 information embedded in network protocols, distinctive HTTP User-Agent, or SMTP Mailer values, etc.*

4.*Host Artifacts: Observables caused by adversary activities on one or more of your hosts, such as registry keys or values known to be created by specific pieces of malware, files, or directories.*

5.*Tools: Software used by attackers to accomplish their mission. This includes utilities designed to create malicious documents for spear phishing, backdoors used to establish C2 or password crackers, or other host-based utilities.*

6.*Tactics, Techniques and Procedures (TTPs): How the adversary goes about accomplishing their mission, from reconnaissance all the way through data exfiltration and at every step in between.*

Investigation Findings submitted to my lead in the SOC via a GS:

![image](https://github.com/MarcoSantibanez/IOC/assets/138132151/cdb36df6-ed5d-44a3-bb11-8fd911ad9c8b)

![image](https://github.com/MarcoSantibanez/IOC/assets/138132151/1f6811c9-8438-4e52-ba2c-e1ffe4bba693)

Summary:

I determined that the file was malicious using information from a VirusTotal report. I also identified additional indicators of compromise that are associated with this file.








