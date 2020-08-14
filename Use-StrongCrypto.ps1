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



try {
    $TLS_Client = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ErrorAction Stop
    $TLS_Server = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ErrorAction Stop
    $FWv2_32 = Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" -ErrorAction Stop
    $FWv4_32 = Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop
    $FWv2_64 = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -ErrorAction Stop
    $FWv4_64 = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ErrorAction Stop

    Write-Host "**All keys are present**" -ForegroundColor Green

    #Write-Host "TLS 1.2\Client DisabledByDefault is" $TLS_Client.DisabledByDefault "and Enabled" $TLS_Client.Enabled
    #$TLS_Client.DisabledByDefault
    # $TLS_Client.Enabled

    #Write-Host "TLS 1.2\Server DisabledByDefault is" $TLS_Server.DisabledByDefault "and Enabled" $TLS_Server.Enabled
    # $TLS_Server.DisabledByDefault
    # $TLS_Server.Enabled

    # $FWv2_32.SystemDefaultTlsVersions
    # $FWv2_32.SchUseStrongCrypto

    # $FWv4_32.SystemDefaultTlsVersions
    # $FWv4_32.SchUseStrongCrypto

    # $FWv2_64.SystemDefaultTlsVersions
    # $FWv2_64.SchUseStrongCrypto

    # $FWv4_64.SystemDefaultTlsVersions
    # $FWv4_64.SchUseStrongCrypto
}

catch [System.Management.Automation.ItemNotFoundException] {
    Write-Host "**At least one registry key is missing, please run update to add the keys**" -ForegroundColor Red
}

catch {
    Write-Host "Something else"
}

<#
$TLS_Client = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
$TLS_Client.DisabledByDefault
$TLS_Client.Enabled

$TLS_Server = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
$TLS_Server.DisabledByDefault
$TLS_Server.Enabled

$FWv2_32 = Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727"
$FWv2_32.SystemDefaultTlsVersions
$FWv2_32.SchUseStrongCrypto

$FWv4_32 = Get-ItemProperty "HKLM:SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
$FWv4_32.SystemDefaultTlsVersions
$FWv4_32.SchUseStrongCrypto

$FWv2_64 = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
$FWv2_64.SystemDefaultTlsVersions
$FWv2_64.SchUseStrongCrypto

$FWv4_64 = Get-ItemProperty "HKLM:SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
$FWv4_64.SystemDefaultTlsVersions
$FWv4_64.SchUseStrongCrypto
#>

<#
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client]
"DisabledByDefault"=dword:00000000
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server]
"DisabledByDefault"=dword:00000000
"Enabled"=dword:00000001
 

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727]
"SystemDefaultTlsVersions"=dword:00000001
"SchUseStrongCrypto"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319]
"SystemDefaultTlsVersions"=dword:00000001
"SchUseStrongCrypto"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727]
"SystemDefaultTlsVersions"=dword:00000001
"SchUseStrongCrypto"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319]
"SystemDefaultTlsVersions"=dword:00000001
"SchUseStrongCrypto"=dword:00000001
#>