Set-ExecutionPolicy -ExecutionPolicy Bypass

function InstallChoco {
    # Ask for elevated permissions if required
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
        }
    # Install Chocolatey to allow automated installation of packages  
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }

    function InstallApps {
        # Install the first set of applications. these are quick so ive added them separately
        choco upgrade firefox microsoft-edge 7zip.install notepadplusplus.install everything --install-if-not-installed -y
    }

    function ApplyDefaultApps {
        dism /online /Import-DefaultAppAssociations:C:\Freshly\Freshly-main\AppAssociations.xml
    }
    
    function ReclaimServer 
    {
        # Ask for elevated permissions if required
        If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
            Exit
        }
    
        ##########
        # Privacy Settings
        ##########
    
        # Disable Telemetry
        #Write-Host "Disabling Telemetry..."
        #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    
        # Enable Telemetry
        # Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
    
        # Disable Wi-Fi Sense
        Write-Host "Disabling Wi-Fi Sense..."
        If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
            New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    
        # Enable Wi-Fi Sense
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
    
        # Disable SmartScreen Filter
        # Write-Host "Disabling SmartScreen Filter..."
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
    
        # Enable SmartScreen Filter
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"

        
        # Disable Location Tracking
        Write-Host "Disabling Location Tracking..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    
        # Enable Location Tracking
        # Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
        # Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
    
        # Disable Feedback
        Write-Host "Disabling Feedback..."
        If (!(Test-Path "HKLM:\Software\Microsoft\Siuf\Rules")) {
            New-Item -Path "HKLM:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    
        # Enable Feedback
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"
    
        # Disable Advertising ID
        Write-Host "Disabling Advertising ID..."
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    
        # Enable Advertising ID
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"
    
        # Disable Cortana
        Write-Host "Disabling Cortana..."
        If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
            New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
        If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
           New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
        If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
           New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    
        # Enable Cortana
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy"
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts"
    
        # Restrict Windows Update P2P only to local network
        Write-Host "Restricting Windows Update P2P only to local network..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3
    
        # Unrestrict Windows Update P2P
        # Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode"
    
       # Remove AutoLogger file and restrict directory
       # Write-Host "Removing AutoLogger file and restricting directory..."
       # $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
       # If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
       #     Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
       # }
       # icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
    
        # Unrestrict AutoLogger directory
        # $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
        # icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
    
        # Stop and disable Diagnostics Tracking Service
        Write-Host "Stopping and disabling Diagnostics Tracking Service..."
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled
    
        # Enable and start Diagnostics Tracking Service
        # Set-Service "DiagTrack" -StartupType Automatic
        # Start-Service "DiagTrack"
      
    
        ##########
        # Service Tweaks
        ##########
    
        #Lower UAC level
        Write-Host "Lowering UAC level..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
    
    
        # Raise UAC level
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
            
        # Disable Firewall
         Write-Host "Disabling Firewall..."
         Set-NetFirewallProfile -Profile * -Enabled False
    
        # Enable Firewall
        # Set-NetFirewallProfile -Profile * -Enabled True
    
        # Disable Windows Defender
        # Write-Host "Disabling Windows Defender..."
        # Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
    
        # Enable Windows Defender
        # Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
    
        # Disable Windows Update automatic restart
        Write-Host "Disabling Windows Update automatic restart..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
    
        # Enable Windows Update automatic restart
        # Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0
            
        # Enable Remote Desktop with Network Level Authentication
         Write-Host "Enabling Remote Desktop with Network Level Authentication..."
         Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
         Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
    
        # Disable Remote Desktop
        # Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
        # Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
        
        #Enable Remote Poweshell Access#
         Enable-PSRemoting -SkipNetworkProfileCheck -Force

        #Disabled IE Enhanced Security for Admins
         $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
         Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
         Stop-Process -Name Explorer

         #Disable RSC on NIC, Mostly for VMHost but does not hurt to run on VMs#
         Disable-NetAdapterRsc *
    
         
        ##########
        # UI Tweaks
        ##########
    
        # Disable Action Center
        Write-Host "Disabling Action Center..."
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer")) {
          New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
    
        # Enable Action Center
        # Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter"
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled"
           
        # Disable Autoplay
        Write-Host "Disabling Autoplay..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
    
        # Enable Autoplay
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
    
        # Disable Autorun for all drives
         Write-Host "Disabling Autorun for all drives..."
         If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
           New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
        }
         Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
    
        # Enable Autorun
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"
    
        #Disable Sticky keys prompt
        Write-Host "Disabling Sticky keys prompt..."
        Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
    
        # Enable Sticky keys prompt
        # Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
    
        # Hide Search button / box
        # Write-Host "Hiding Search Box / Button..."
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    
        # Show Search button / box
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode"
    
        # Hide Task View button
        Write-Host "Hiding Task View button..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    
        # Show Task View button
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton"
    
        # Show known file extensions
        Write-Host "Showing known file extensions..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    
        # Hide known file extensions
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
    
        # Show hidden files
        Write-Host "Showing hidden files..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
    
        # Hide hidden files
        # Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
    
        # Change default Explorer view to "Computer"
        Write-Host "Changing default Explorer view to `"Computer`"..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    
        # Change default Explorer view to "Quick Access"
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo"
    
        # Show Computer shortcut on desktop
        Write-Host "Showing Computer shortcut on desktop..."
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
    
    
        # Hide Computer shortcut from desktop
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
        # Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
              
        ##########
        # Remove unwanted applications
        ##########
    
        # Uninstall Work Folders Client
        # Write-Host "Uninstalling Work Folders Client..."
        # dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
    
        # Install Work Folders Client
        # dism /online /Enable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
    
        # Set Photo Viewer as default for bmp, gif, jpg and png
        Write-Host "Setting Photo Viewer as default for bmp, gif, jpg, png and tif..."
        If (!(Test-Path "HKCR:")) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }
        ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
            New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
            New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
            Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
            Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
        }
    
        # Remove or reset default open action for bmp, gif, jpg and png
        # If (!(Test-Path "HKCR:")) {
        #   New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        # }
        # Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse
        # Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb"
        # Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
        # Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
        # Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
        # Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse
        # Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse
    
        # Show Photo Viewer in "Open with..."
        Write-Host "Showing Photo Viewer in `"Open with...`""
        If (!(Test-Path "HKCR:")) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }
        New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
        New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
        Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
        Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
        Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
    
        # Remove Photo Viewer from "Open with..."
        # If (!(Test-Path "HKCR:")) {
        #   New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        # }
        # Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse
    }
           
    function SonicLocalAdmin{
        ###Create Sonic Support User and add as Local Admin###
        $securepwdfilepath = 'C:\Freshly\Freshly-main\Cred\pass.file'
        $AESKeyFilePath = 'C:\Freshly\Freshly-main\Cred\keys.txt'
        $AESKeyFile = Get-Content $AESKeyFilePath
        $pwdtxt = Get-Content $securepwdfilepath
        $passwd = $pwdtxt | ConvertTo-SecureString -Key $AESKeyFile
        $user = "Sonic"
        #Check if User Exists Already
        $op = Get-LocalUSer | where-Object Name -eq "Sonic" | Measure
        if ($op.Count -eq 0) {
             #Create User and Add to Local Admin Group
             New-LocalUser $user -Password $passwd
             Add-LocalGroupMember -Group "Administrators" -Member $user
        
        } else {
             # Reset Password for User to new Password
             Set-LocalUser -Name $user -Password $passwd
            }
        
        }

        function SetServerName {
            # In our MSP we designate all systems in the format assetid-companyname for example 288111-SS
           
            Add-Type -AssemblyName Microsoft.VisualBasic
            $rename= [Microsoft.VisualBasic.Interaction]::MsgBox('Do you want to Rename this Server?', 'YesNo,Information' , 'Rename This Server?') 
            if ($rename -match "Yes")
            { 
                $ServerName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a Name (DC1, FS1, etc...')
                $CompanyName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter Company Name, Abbreviation', 'Company Initials')
                Write-Output "This computer will be renamed $ServerName-$CompanyName"
                Rename-Computer -NewName "$ServerName-$CompanyName"
            } 
            else 
            {
            Write-Output "This PC will not be renamed at this time"
            }
        }        
        
        function RestartPC{
            #Prompts if reboot is needed or not, if no will display message then end setup script#
            
            $reboot= [Microsoft.VisualBasic.Interaction]::MsgBox('Do  you want to Reboot the Server?' , 'YesNo,Information' , 'Reboot')
            if ($reboot -match "Yes")
            { 
              Restart-Computer  
            } 
            else 
            {
            Write-Output "Reboot has been canceled. Please reboot at your convenivce to complete the setup"
            }
        }

    InstallChoco
    InstallApps
    ApplyDefaultApps
    ReclaimServer
    AutomateShortcut
    SonicLocalAdmin
    SetPCName
    RestartPC        