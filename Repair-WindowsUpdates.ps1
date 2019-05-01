<#	
	.NOTES
	===========================================================================
	             Created on:   	05/14/2018
                 Modified on:   02/19/2019
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
$obj = @()

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
        $comp = $comp -replace '(^\s+|\s+$)','' -replace '\s+',' ' #removes any double spaces, tabs, single blank spaces on the line

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
                        Continue
                    }
                }

                try 
                {
                    # Create new session with the current computer
                    $so = New-PSSession $comp -ErrorAction Stop

                    Write-Host "connected"

                    # Invoke the commands to fix WSUS updates on the computer
                    Invoke-Command -Session $so -ScriptBlock {

                        # 1 - Get verson of windows, 7 or 10
                        $osVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
                        Write-Output "`t$osVersion"

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
                                    Write-Output "`tstopped windows update service"
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tfailed to stop the windows update service"
                                    Continue
                                }
                            }

                            else
                            {
                                Write-Output "`twindows Update service was already stopped"
                            }
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tfailed to get the Windows Update service status, moving to the next computer"
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
                            Continue
                        }
                    
                        # 4 - delete the C:\windows\softwaredistribution folder
                        try 
                        {
                            Remove-Item C:\Windows\SoftwareDistribution -Recurse -Force 
                            Write-Output "`tdeleted softwaredistribution folder"
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tfailed to delete the software distribution folder"
                            Continue
                        }

                        # 5 - Check and repair the registry keys, if necessary

                        # Only uncomment this block for computers that have duplicate SusClientId's
                        <#try 
                        {
                            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -ErrorAction Stop
                            Write-Host "`tdeleted the SusClientId reg item"
                        }

                        catch
                        {
                            Write-Host -ForegroundColor Red "`tFailed to delete the SusClientId reg key"
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
                                    Write-Output "`treg value was corrected"
                                }

                                catch 
                                {
                                    Write-Host -ForegroundColor Red "`tReg was not able to be corrected, please look at" $Path
                                }
                            }

                            else 
                            {
                                Write-Output "`treg value is good"
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
                                    Write-Output "`tCreated the registry item State with value " $regValueShouldBe
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tFailed to create missing registry item, please investigate"
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
                                    Write-Host -ForegroundColor Red "`tFailed to set the service to manual"
                                }
                            }
                        }

                        catch
                        {
                            Write-Output "`tFailed to get the Windows Update service start-up status, moving to the next computer"
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
                                    Write-Output "`tstarting windows update service"
                                }

                                catch
                                {
                                    Write-Host -ForegroundColor Red "`tFailed to start the service"
                                }
                            }
                        }

                        catch 
                        {
                            Write-Output "`tFailed to get the Windows Update service status, moving to the next computer"
                            Continue 
                        }

                        # 7 - Start the windows update dependency services
                        try
                        {
                            Start-Service -Name cryptSVc -ErrorAction Stop
                            Start-Service -Name bits -ErrorAction Stop
                            Start-Service -Name msiserver -ErrorAction Stop
                            Write-Output "`tstarting dependency windows update services"
                        }

                        catch 
                        {
                            Write-Host -ForegroundColor Red "`tFailed to start Windows services, moving on to next computer but please investigate"
                            Continue 
                        }

                        # 8 - For win 7, start wuauclt.exe /detectnow, for win 10, start usoclient.exe startscan
                        if ($osVersion -eq "Windows 10 Pro")
                        {
                            $getBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild + '.' + ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name UBR).UBR)
                            Write-Host "`tbuild" $getBuild

                            if ($getBuild -ige 17763.0)
                            {
                                . "C:\Windows\System32\UsoClient.exe" StartInteractiveScan
                                Write-Output "`tstarting interactive scan"
                            }

                            else
                            {    
                                . "C:\Windows\System32\UsoClient.exe" StartScan
                                Write-Output "`tstarting scan"
                            }
                        }

                        elseif ($osVersion -eq "Windows 7 Professional")
                        {
                            Write-Output "`tstarting scan"
                            . "C:\Windows\System32\Wuauclt.exe" /detectnow
                        }

                        else 
                        {
                            Write-Output "`tOS is not supported"
                        }

                    }

                    # Remove the session to allow connection to another computer in the list
                    Remove-PSSession -Session $so
                    Write-Output "`tClosing PSSession"
                }

                catch
                {
                    Write-Host -ForegroundColor Red "Failed to connect"
                }
            } 

            else 
            { 
                Write-Host "`n"
                Write-Host -ForegroundColor Yellow $comp "is offline" 
            }
        } 
        
        $ErrorActionPreference = 'Continue'
    }
}
