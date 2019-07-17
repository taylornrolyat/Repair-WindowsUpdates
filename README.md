# Repair-WindowsUpdates

This PowerShell script automates the repair of Windows Updates on Windows 7 and 10 Operating Systems. This works for domain joined machines that use WSUS. 

The script checks the windows update services, looks for known registry key issues, deletes the SoftwareDistribution folder and initiates an update check. 

If computers in your network are not reporting by the correct hostname in your WSUS environment, then it is probably because the SusClientID in the registry is the same across multiple machines. This occurs when OS images aren't sysprep'd correctly. If you uncomment the first block after step 5 (around line 207) this will fix the issue. 
