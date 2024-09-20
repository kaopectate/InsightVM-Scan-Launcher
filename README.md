A Script that would be suitable for a scheduled task to launch Rapid 7 Insight VM scans.

Script checks how many scans are running and kicks off scans of sites with the oldest “last scanned date” within a set maximum number of concurrent scans.

Simply add your credentials, base URL for your Insight VM Instance, your max concurrent scan threshold, and any site names that you would like to exclude by name.

Works well with task scheduler or PowerShell Universal.
