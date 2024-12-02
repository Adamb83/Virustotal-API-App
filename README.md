# Virustotal-API-App
My first OSINT project. Connects to Virustotal.com API to monitor IP addresses logging the suspicious ones on my network.

Virustotal.com has a free API to access this data, the free version has limits, so this script governed so it works nicely with the free api.
Wireshark is required to run the script.

The script should create a suspiciousip's log
processed_ip's logged file
captured_ip's log file
aswell as a "secret" file for saving your API key.

I tried to have the suspicious IP addresses highlighted in red but couldn't get it working..
