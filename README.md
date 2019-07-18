# Repair-WindowsUpdates

Troubleshooting failed Windows updates and WSUS reporting issues on client manchines can be time consuming and tedious to repair. In my experience the Windows update folder can become easily corrupted and in turn, causes Microsoft patches to not install or WSUS reporting to fail. This PowerShell script automates the repair of Windows Updates on Windows 7 and 10 Operating Systems. The script is silent and does not reboot the machines. 

## How the script works:
1. Iterates through list of computers in csv file
2. Stops the Windows Update service as well as cryptsvc, bits, msiserver
3. Deletes C:\Windows\SoftwareDistribution
4. Checks and repairs certain registry keys if they are incorrect (I have seen these changed before and caused all patches to fail to install)
5. Start the Windows Update service as well as cryptsvc, bits, msiserver
6. Detects if the system is Windows 7 or Windows 10 and initiates a scan with WSUS 
7. A report table is generated at the end of the scipt that provides detailed repair results

## Requirements:
Machines must be configured to use WSUS and have PowerShell remoting enabled. 

## Note:
If you notice that computers in your network are not reporting by the correct hostname in your WSUS environment, then it is probably because the SusClientID in the registry is the same across multiple machines. This can occur when OS images aren't sysprep'd correctly. If you uncomment the first block after step 5 (around line 207) this script can also correct that issue. 


## Example:
![Image](https://github.com/taylornrolyat/Repair-WindowsUpdates/blob/master/wsus%20repair%20example.jpg)
