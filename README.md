# ThreatHunting
I am publishing GPL v3 tools for hunting for threats in your organisations.

# Nexthink modules
Threat hunting - Potential malware downloads v1.0.xml 

This is a report which shows all calls to internet domains from common malware document techniques.  Most endpoint malware - such as macros, Office exploits etc - use the same set of methods to download their payloads.

The methods currently monitored include:

  - rundll32
  - mshta
  - PowerShell
  - wscript/cscript
  - wmic
  - sct remote calls
  - InfDefaultInstall (Inf remote calls)
  
The report will show domains.  You can change the report to show users, executables instead if you want, or investigate each domain 

In terms of false positives, you will very likely want to add a rule to filter out traffic destined for your internal IP ranges, or whitelist domains inside your environment.  For example, when adding a Printer it will call rundll32, and hit the printer for web traffic - which triggers in the report - just whitelist it.
