if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    break
}

<#
$RegBackupPath = "C:\Temp\TLSRegBackup"
$DateTime = Get-Date -Format MMddyyyyTHHmmss

# If EAF_Backup folder exists, rename it to append current date/time
if (Test-Path -Path $RegBackupPath){
      Rename-Item -Path $RegBackupPath -NewName "TLSRegBackup_$DateTime" -WhatIf:$false
}

New-Item -ItemType Directory $RegBackupPath -WhatIf:$false

REG EXPORT  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\" "C:\Temp\TLSRegBackup\TLS_Client.reg"
REG EXPORT  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\" "C:\Temp\TLSRegBackup\TLS_Server.reg"
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" "C:\Temp\TLSRegBackup\FWv2_32.reg"
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" "C:\Temp\TLSRegBackup\FWv2_64.reg"
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" "C:\Temp\TLSRegBackup\FWv4_32.reg"
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" "C:\Temp\TLSRegBackup\FWv4_64.reg"
#>

<#
.Synopsis

.Description

.Example
#>

# To Query and Add TLS 1.2 Strong Crypto Keys

#$PSVersionTable.PSVersion

Clear-Host
function Check-TLS {

    try {
        $TLS_Client = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ErrorAction Stop
        $TLS_Server = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ErrorAction Stop
        $FWv2_32 = Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -ErrorAction Stop
        $FWv4_32 = Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop
        $FWv2_64 = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -ErrorAction Stop
        $FWv4_64 = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop

        if ($TLS_Client.DisabledByDefault -eq 0 -and
            $TLS_Client.Enabled -eq 1 -and
            $TLS_Server.DisabledByDefault -eq 0 -and
            $TLS_Server.Enabled -eq 1 -and
            $FWv2_32.SystemDefaultTlsVersions -eq 1 -and
            $FWv2_32.SchUseStrongCrypto -eq 1 -and
            $FWv4_32.SystemDefaultTlsVersions -eq 1 -and
            $FWv4_32.SchUseStrongCrypto -eq 1 -and
            $FWv2_64.SystemDefaultTlsVersions -eq 1 -and
            $FWv2_64.SchUseStrongCrypto -eq 1 -and
            $FWv4_64.SystemDefaultTlsVersions -eq 1 -and
            $FWv4_64.SchUseStrongCrypto -eq 1
        ) {
            Return 'yes'
        }

        else {
            Return 'no'
        }
    }

    catch [System.Management.Automation.ItemNotFoundException] {
        Return 'no'
    }

    catch {
        Write-Host "There was some other error other than the registry entries not being found"
    }
}

function Add-TLS {
    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path
}

function Remove-TLS {
    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 0 -Force -Path $Path


    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    if (-Not (Test-Path $Path)) { New-Item -Path $Path -Force }
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path
}

function Exit-App {
    Write-Host "Press Enter to exit..." -ForegroundColor Yellow
    $x = Read-Host
}

$Present = Check-TLS
if ($Present -eq 'yes') {
    Write-Host "**All TLS 1.2 registry keys are present**" -ForegroundColor Green
    Exit-App
}

elseif ($Present -eq 'no') {
    Write-Host "****At least one registry key is missing, please run update to add the keys****" -ForegroundColor Red
    $x = Read-Host -Prompt "Do you want to add the registry entries? (Y)es or Enter for No"

    if ($x -eq 'y') {
        Write-Host "****Adding TLS 1.2 Registry keys...****" -ForegroundColor Green
        Add-TLS
        Write-Host "****Finished adding the TLS 1.2 Registry Keys****" -ForegroundColor Green
        Exit-App
    }

    else {
        Write-Host "****Not changing anything****" -ForegroundColor Green
        Exit-App
    }
}