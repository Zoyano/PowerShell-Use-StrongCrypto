if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
{
  $arguments = "& '" + $myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  break
}

<#
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" c:\temp\1.reg
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" c:\temp\2.reg
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" c:\temp\3.reg
REG EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" c:\temp\4.reg
#>

<#
.Synopsis
A very brief description of the function. It begins with a verb and tells the user what the function does. It does not include the function name or how the function works. The function synopsis appears in the SYNOPSIS field of all help views.

.Description
Two or three full sentences that briefly list everything that the function can do. The description begins with "The <function name> function…." If the function can get multiple objects or take multiple inputs, use plural nouns in the description. The description appears in the DESCRIPTION field of all Help views.

.PARAMETER something
Brief and thorough. Describe what the function does when the parameter is used. And what legal values are for the parameter. The parameter appears in the PARAMETERS field only in Detailed and Full Help views.

.Example
Illustrate use of function with all its parameters. First example is simplest with only the required parameters. Last example is most complex and should incorporate pipelining if appropriate. The example appears only in the EXAMPLES field in the Example, Detailed, and Full Help views.

.Inputs
Lists the .NET Framework classes of objects the function will accept as input. There is no limit to the number of input classes you may list. The inputs Help tag appears only in the INPUTS field in the Full Help view.

.Outputs
Lists the .NET Framework classes of objects the function will emit as output. There is no limit to the number of output classes you may list. The outputs Help tag appears in the OUTPUTS field only in the Full Help view.

.Notes
Provides a place to list information that does not fit easily into the other sections. This can be special requirements required by the function, as well as author, title, version, and other information. The notes Help tag appear in the NOTES field only in the Full help view.

.Link
Provides links to other Help topics and Internet Web sites of interest. Because these links appear in a command window, they are not direct links. There is no limit to the number of links you may provide. The links appear in the RELATED LINKS field in all Help views.
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
    New-Item -Path $Path -Force
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    New-Item -Path $Path -Force
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 1 -Force -Path $Path


    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 1 -Force -Path $Path
}

function Remove-TLS {
    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    New-Item -Path $Path -Force
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    New-Item -Path $Path -Force
    New-ItemProperty -Name DisabledByDefault -PropertyType DWord -Value 0 -Force -Path $Path
    New-ItemProperty -Name Enabled -PropertyType DWord -Value 0 -Force -Path $Path


    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
    New-Item -Path $Path -Force
    New-ItemProperty -Name SystemDefaultTlsVersions -PropertyType DWord -Value 1 -Force -Path $Path
    New-ItemProperty -Name SchUseStrongCrypto -PropertyType DWord -Value 0 -Force -Path $Path

    $Path = "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    New-Item -Path $Path -Force
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