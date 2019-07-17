<#	
	.NOTES
	===========================================================================
	             Created on:   	05/14/2018
                 Modified on:   07/17/2019
	             Created by:   	Taylor Triggs
                 Notes:         Run as Admin
	             Dependancies:  Powershell 5.0, RSAT
	===========================================================================

    .SYNOPSIS
                Repairs WSUS on Windows 7 and 10 client computers

	.DESCRIPTION
				Attempts to fix WSUS patches on clients
                Source list.csv file can be hostname or fqdn as the script will remove everything after the hostname automatically				

    .NOTES
                UsoClient.exe replaces wuaulctl
                RefreshSettings – used to quickly enact any settings changes
                RestartDevice – as the name implies, it restarts the device. Can be used in a script to allow updates to finish installing on next boot.
                ResumeUpdate – used to tell the tool to resume updating after a reboot.
                StartDownload – initiates a full download (from Microsoft) of existing updates
                StartInstall – kicks-off the installation of the downloaded updates
                ScanInstallWait – Combined Scan Download Install
                StartInteractiveScan – we’ve yet to get this one to work, but it suggests that the process may work in a GUI
                StartScan – kicks-off a regular scan

    .EXAMPLE
                FixList
                Comp01
                Comp02
                Comp03

    .LINK
                RSAT if build less than 1809: https://www.microsoft.com/en-us/download/details.aspx?id=45520
                RSAT if build 1809 or greater: https://github.com/taylornrolyat/Install-RSAT-on-Windows-10-1809
#>

#Requires –Version 5
#Requires -Modules ActiveDirectory

Import-Module ActiveDirectory

$computerslist = @()
$resultsList = @() # computers that were fixed after runnning the script

$scriptFolderRoot = Split-Path $MyInvocation.MyCommand.Path
$fixList = "$scriptFolderRoot\list.csv"

if (!(Test-Path $fixList)) 
{ 
    Write-Host -ForegroundColor Red "The CSV file is missing, please create the CSV file with FixList as the first item and run again" 
}

else 
{
    Import-Csv $fixList | ForEach-Object { $computerslist += $_.FixList }

    foreach ($comp in $computerslist)
    {   
        $comp = $comp.Split('.')[0] # removes everything after the hostname.fqdn that comes with the wsus export
        $comp = $comp -replace '(^\s+|\s+$)','' -replace '\s+',' ' # removes any double spaces, tabs, single blank spaces on the line

        $ErrorActionPreference = 'SilentlyContinue'

        if (-not $(Get-ADComputer -Identity "$comp")) 
        { 
            Write-Host -ForegroundColor YELLOW "`n$comp does not exist in AD"                        
        }

        else
        {     
            # First check if the computer is online
            if (Test-Connection -Computername $comp -BufferSize 16 -Count 1 -Quiet)
            {
                Write-Host "`n$comp... " -NoNewline

                $winRMService = (Get-Service -Name WinRM -ComputerName $comp).Status

                # Make sure WinRM service is running
                if ($winRMService -ne "Running")
                {
                    try
                    {
                        Get-Service -Name WinRM -ComputerName $comp | Start-Service -ErrorAction Stop
                    }

                    catch
                    {
                        Write-Host -ForegroundColor Red "WinRM service could not start, moving on to next computer"

                        $resultsList += New-Object psobject -Property @{
                            ComputerName = $comp
                            Status = "Failed"
                            Details = "WinRM service could not start, moving on to next computer"
                        }

                        Continue
                    }
                }

                try 
                {
                    # Create new session with the current computer
                    $so = New-PSSession $comp -ErrorAction Stop

                    Write-Host "connected"

                    # Invoke the commands to fix WSUS updates on the computer
                    $results = Invoke-Command -Session $so -ScriptBlock {
                    
                        $props = @{ComputerName=$env:COMPUTERNAME}                     

                        # 1 - Get verson of windows, 7 or 10
                        $osVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
                        Write-Host "`t$osVersion"

                        # 2 - If the windows update service is running, stop it
                        try 
                        {
                            # (Get-Service -Name wuauserv).starttype
                            # Get-Service -Name wuauserv | set-service -StartupType Disabled

                            $serviceStatus = (Get-Service -Name "Windows Update").Status 

                            if ($serviceStatus -eq "Running")
                            {
                                try 
                                {
                                    Stop-Service -Name "Windows Update" -Force -ErrorAction Stop
                                    Write-Host "`tstopped windows update service"
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tfailed to stop the windows update service"

                                    $props.Add('Status', 'Failed')
                                    $props.Add('Details', 'failed to stop the windows update service')

                                    New-Object -Type PSObject -Property $props

                                    Continue
                                }
                            }

                            else
                            {
                                Write-Host "`twindows Update service was already stopped"
                            }
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tfailed to get the Windows Update service status, moving to the next computer"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'failed to get the Windows Update service status')

                            New-Object -Type PSObject -Property $props

                            Continue 
                        }

                        # 3 - If the other windows update service dependencies are running, stop them
                        try
                        {
                            Stop-Service -Name cryptSVc -Force -ErrorAction Stop
                            Stop-Service -Name bits -Force -ErrorAction Stop
                            Stop-Service -Name msiserver -Force -ErrorAction Stop
                            
                            Write-Host "`tstopped cryptsvc, bits, msiserver services" $Error[0]
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tfailed to stop cryptsvc, bits or msiserver services"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'cryptsvc, bits or msiserver service failed to stop')

                            New-Object -Type PSObject -Property $props

                            Continue
                        }
                    
                        # 4 - delete the C:\windows\softwaredistribution folder
                        try 
                        {
                            Remove-Item C:\Windows\SoftwareDistribution -Recurse -Force 
                            Write-Host "`tdeleted softwaredistribution folder"
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tfailed to delete the software distribution folder"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'unable to delete the software distribution folder')

                            New-Object -Type PSObject -Property $props

                            Continue
                        }

                        # 5 - Check and repair the registry keys, if necessary

                        # Only uncomment this block if you know that computers that have duplicate SusClientId's
                        <#try 
                        {
                            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -ErrorAction Stop
                            Write-Host "`tdeleted the SusClientId reg item"
                        }

                        catch
                        {
                            Write-Host -ForegroundColor Red "`tFailed to delete the SusClientId reg key"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'unable to delete the SusClientID registry item')

                            New-Object -Type PSObject -Property $props

                            Continue
                        }#>

                        $regValueShouldBe = 146432

                        $regPath1 = "Registry::HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
                        $regPath2 = "Registry::HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
                        $regPath3 = "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"                        

                        $regPaths = @($regPath1, $regPath2, $regPath3)

                        # Returns bool for registry existence
                        function Test-RegistryValue
                        {
                            param (
                                [parameter(Mandatory = $true)]
                                [ValidateNotNullOrEmpty()]
                                $Path,
                                [parameter(Mandatory = $true)]
                                [ValidateNotNullOrEmpty()]
                                $Name
                            )
        
                            try
                            {
                                Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Name -ErrorAction Stop | Out-Null
                                return $true
                            }
        
                            catch
                            {
                                return $false
                            }  
                        }

                        # Corrects registry values if they are incorrect
                        function Fix-RegistryValue
                        {
                            param (
                                [parameter(Mandatory = $true)]
                                [ValidateNotNullOrEmpty()]
                                $Path,
                                [parameter(Mandatory = $true)]
                                [ValidateNotNullOrEmpty()]
                                $Name
                            )

                            $regValue = Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Name

                            if ($regValue -ne $regValueShouldBe)
                            {
                                try 
                                { 
                                    Set-ItemProperty -Path $Path -Name $Name -Value $regValueShouldBe -Type DWORD -ErrorAction Stop
                                    Write-Host "`treg value was corrected"
                                }

                                catch 
                                {
                                    Write-Host -ForegroundColor Red "`tReg was not able to be corrected, please look at" $Path

                                    $props.Add('Status', 'Failed')
                                    $props.Add('Details', "registry was not able to be corrected, please look at $Path")

                                    New-Object -Type PSObject -Property $props

                                    Continue
                                }
                            }

                            else 
                            {
                                Write-Host "`tregistry value is good"
                            }
                        }

                        # Check each of the registry paths
                        foreach ($regPath in $regPaths)
                        {
                            $registryTest = Test-RegistryValue -Path $regPath -Name 'State'
    
                            # if the registry exists, check and make sure the value is correct
                            if ($registryTest) 
                            {
                                Fix-RegistryValue -Path $regPath -Name 'State'
                            }

                            else 
                            {
                                try 
                                { 
                                    New-ItemProperty -Path $Path -Name "State" -Value $regValueShouldBe -Type DWORD -ErrorAction Stop
                                    Write-Host "`tCreated the registry item State with value " $regValueShouldBe
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tFailed to create missing registry item, please investigate"

                                    $props.Add('Status', 'Failed')
                                    $props.Add('Details', "missing registry item failed was not able to be created")

                                    New-Object -Type PSObject -Property $props

                                    Continue
                                }
                            }
                        }

                        # 6 - Start the windows update service
                        try
                        {
                            $serviceStartType = (Get-Service -Name "Windows Update" | select starttype).starttype

                            if ($serviceStartType -eq "Disabled")
                            {
                                try
                                {
                                    Get-Service -Name "Windows Update" | Set-Service -StartupType Manual -ErrorAction Stop
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tFailed to set the service to Manual start up"

                                    $props.Add('Status', 'Failed')
                                    $props.Add('Details', "unable to set the Windows Update service to Manual start type")

                                    New-Object -Type PSObject -Property $props

                                    Continue
                                }
                            }
                        }

                        catch
                        {
                            Write-Host "`tFailed to get the Windows Update service start-up status, moving to the next computer"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'cannot lookup the Windows Update service start-up status')

                            New-Object -Type PSObject -Property $props

                            Continue
                        }

                        try 
                        {
                            $serviceStatus = (Get-Service -Name "Windows Update").Status

                            if ($serviceStatus -eq "Stopped")
                            {
                                try 
                                {
                                    Start-Service -Name "Windows Update" -ErrorAction Stop
                                    Write-Host "`tstarting windows update service"
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tFailed to start the service"

                                    $props.Add('Status', 'Failed')
                                    $props.Add('Details', "unable to start the Windows Update service")

                                    New-Object -Type PSObject -Property $props

                                    Continue
                                }
                            }
                        }

                        catch 
                        {
                            Write-Host "`tFailed to get the Windows Update service status, moving to the next computer"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'cannot lookup the Windows Update service service status')

                            New-Object -Type PSObject -Property $props

                            Continue 
                        }

                        # 7 - Start the windows update dependency services
                        try
                        {
                            Start-Service -Name cryptSVc -ErrorAction Stop
                            Start-Service -Name bits -ErrorAction Stop
                            Start-Service -Name msiserver -ErrorAction Stop
                            Write-Host "`tstarting dependency windows update services"
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tFailed to start dependency Windows services, moving on to next computer but please investigate"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'cannot start the dependency Windows Update services')

                            New-Object -Type PSObject -Property $props

                            Continue 
                        }

                        sleep 10

                        # 8 - For win 7, start wuauclt.exe /detectnow, for win 10, start usoclient.exe startscan
                        if ($osVersion -eq "Windows 10 Pro")
                        {
                            $getBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild + '.' + ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR).UBR)
                            Write-Host "`tbuild" $getBuild

                            # Windows 10 1809 for some reason only works with StartInteractiveScan
                            if ($getBuild -ige 17763.0)
                            {
                                #. "C:\Windows\System32\UsoClient.exe" StartInteractiveScan
                                Start-Process "C:\Windows\System32\UsoClient.exe" -ArgumentList "StartInteractiveScan" -Wait
                                Write-Host "`tstarting interactive scan"

                                $props.Add('Status', 'Successful')
                                $props.Add('Details', 'updates were repaired')
                            }

                            # Windows 10 less than 1809 for some reason only works with StartScan
                            else
                            {    
                                #. "C:\Windows\System32\UsoClient.exe" StartScan
                                Start-Process "C:\Windows\System32\UsoClient.exe" -ArgumentList "StartScan" -Wait
                                Write-Host "`tstarting scan"
                                                                
                                $props.Add('Status', 'Successful')
                                $props.Add('Details', 'updates were repaired')
                            }
                        }

                        elseif ($osVersion -eq "Windows 7 Professional")
                        {
                            #. "C:\Windows\System32\Wuauclt.exe" /detectnow
                            Start-Process "C:\Windows\System32\Wuauclt.exe" -ArgumentList "/detectnow" -Wait
                            Write-Host "`tstarting scan"
                                                        
                            $props.Add('Status', 'Successful')
                            $props.Add('Details', 'updates were repaired')
                        }

                        else 
                        {
                            Write-Host "`tOS is not supported"

                            $props.Add('Status', 'Failed')
                            $props.Add('Details', 'this OS is not supported')
                        }

                        New-Object -Type PSObject -Property $props
                    }                    

                    $resultsList += New-Object psobject -Property @{
                        ComputerName = $results.ComputerName
                        Status = $results.Status
                        Details = $results.Details
                    }

                    # Remove the session to allow connection to another computer in the list
                    Remove-PSSession -Session $so
                    Write-Host "`tClosing PSSession"
                }

                catch
                {
                    Write-Host -ForegroundColor Red "Failed to connect"

                    $resultsList += New-Object psobject -Property @{
                        ComputerName = $comp
                        Status = 'Failed'
                        Details = 'unable to connect, check your credentials'
                    }
                }
            } 

            else 
            { 
                Write-Host "`n"
                Write-Host $comp "is offline"

                $resultsList += New-Object psobject -Property @{
                    ComputerName = $comp
                    Status = 'Offline'
                    Details = ''
                }
            }
        } 
        
        $ErrorActionPreference = 'Continue'
    }
}

Write-Host -ForegroundColor Green "`n---- Detailed Repair Results ----"
$resultsList | Format-Table ComputerName, Status, Details | Sort-Object Status, ComputerName

$offlineList = $resultsList | Where-Object Status -like "Offline" | Format-Table ComputerName
if ($offlineList)
{
    Write-Host -ForegroundColor Yellow "`n---- Offline Computers ----"
    $offlineList
}

$failedList = $resultsList | Where-Object Status -like "Failed" | Format-Table ComputerName
if ($failedList)
{
    Write-Host -ForegroundColor Red "`n---- Failed Computers ----"
    $failedList
}