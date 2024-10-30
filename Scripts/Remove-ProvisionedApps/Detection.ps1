<#
    This script is a modified version of the original script written by Michael Niehaus.
    Original script can be found here: https://github.com/supportmodern/Scripts/blob/master/RemoveWin10Built-inApps/RemoveApps.ps1

    Scriptname: Detection.ps1
    Purposes:
        1. Verify whether the following features are disabled or not:
            - Microsoft Windows Consumer Experiences
            - Chat Auto Install (Microsoft Teams (personal))
            - Chat icon 
        2. Check whether any provisioned apps specified in the input XML file are installed on the computer.
    Last modified date: 05/15/2023
#>

# Check whether Windows is running Online or Offline
if ($env:SYSTEMDRIVE -eq "X:"){
    $script:Offline = $true
    $drives = get-volume | ? {-not [String]::IsNullOrWhiteSpace($_.DriveLetter) } | ? {$_.DriveType -eq 'Fixed'} | ? {$_.DriveLetter -ne 'X'}
    $drives | ? { Test-Path "$($_.DriveLetter):\Windows\System32"} | % { $script:OfflinePath = "$($_.DriveLetter):\" }
}
else{
    $script:Offline = $false
}

# Variables
$AdditionalFeaturesDisabled = $true
$ProvisionedAppsRemoved = $true
$provisionedAppList = @()
$xmlApplist = @()

$CloudContentRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$cloudRegValue = Get-ItemProperty -Path $CloudContentRegPath -ErrorAction SilentlyContinue | Select-Object DisableWindowsConsumerFeatures -ErrorAction SilentlyContinue

if ($cloudRegValue -eq $null -or $($cloudRegValue.DisableWindowsConsumerFeatures) -ne 1){
    $AdditionalFeaturesDisabled = $false
}

$CommunicationsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications"
$comRegValue = Get-ItemProperty -Path $CommunicationsRegPath -ErrorAction SilentlyContinue | Select-Object ConfigureChatAutoInstall -ErrorAction SilentlyContinue

if ($comRegValue -eq $null -or $($comRegValue.ConfigureChatAutoInstall) -ne 0){
    $AdditionalFeaturesDisabled = $false
}

$ChatIconRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
$chatRegValue = Get-ItemProperty -Path $ChatIconRegPath -ErrorAction SilentlyContinue | Select-Object ChatIcon -ErrorAction SilentlyContinue

if ($chatRegValue -eq $null -or $($chatRegValue.ChatIcon) -ne 3){
    $AdditionalFeaturesDisabled = $false
}

if ($script:Offline){
    Get-AppxProvisionedPackage -Path $script:OfflinePath | % { $provisionedAppList += $_.DisplayName }
}
else{
    Get-AppxProvisionedPackage -Online | % { $provisionedAppList += $_.DisplayName }
}

$configFile = "$PSScriptRoot\RemoveApps.xml"
if (Test-Path -Path $configFile){
    # Read the list
    Write-Verbose "Reading list of apps from $configFile"
    $xmlApplist = Get-Content $configFile
}
            
foreach ($app in $provisionedAppList){
    if ($app -in $xmlApplist){
        $ProvisionedAppsRemoved = $false
        break
    }
}

if ($AdditionalFeaturesDisabled -and $ProvisionedAppsRemoved){
    $true
}
