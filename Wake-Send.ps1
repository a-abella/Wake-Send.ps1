<#
    Antonio Abella  -  Sep. 23, 2016
    
    Wake-on-LAN packet sender with subnet selection.
    Resolves host MAC addresses from parsed Nmap data
    held in text files.

    Graphical OU selection provided by MicaH's
    Choose-ADOrganizationalUnit function.
    https://itmicah.wordpress.com/2016/03/29/active-directory-ou-picker-revisited/
    
#>


# Dot-source file containing Choose-ADOrganizationalUnit
# function.
. .\path\to\ChooseADOrganizationalUnit.ps1




Write-Host "`n====================="
Write-Host "Select target PC site"
Write-Host "=====================`n"

# Edit these to reflect your site names.
Write-Host " 1. Site one"
Write-Host " 2. Site two"
Write-Host " 3. Site three"
Write-Host " 4. Site four"
Write-Host " 5. Site five"

$site = Read-Host -Prompt "`nEnter site number [1-5]"

# Edit with FQDNs of a host on the target site's subnet.
# Hosts must have powershell remoting enabled, your user 
# must be allowed to remote to it, and the remote host 
# must have Powershell 3.0 or higher.
$dcs = @("srv-site-one.fqdn.com","srv-site-two.fqdn.com","srv-site-three.fqdn.com","srv-site-four.fqdn.com","srv-site-five.fqdn.com")

# Edit with UNC path to the directory holding your MAC
# address files. Ensure they are in a directory that your
# remote host can access, and that your user account has
# read/write permission.
$filepath = "\\path\to\macaddress\sources\directory"

# Edit with the names of your MAC address files. I keep
# seperate files for each site. These files are generated
# through Nmap parsing on per-site Linux servers  with 
# my bash script macscanner.sh
$macfiles = @("${filepath}\site1-macs.txt","${filepath}\site2-macs.txt","${filepath}\site3-macs.txt","${filepath}\site4-macs.txt","${filepath}\site5-macs.txt")
$machold = Get-Content $macfiles[$site-1]

$oubool = 0
$pcs = @()
$ou = ""
$ouselect = Read-Host -Prompt "`nDo you want to wake all PCs in a given OU? [y/N]"

# Read target hosts from input files if provided.
if ($args.Length) {
    foreach ($arg in $args) {
        Get-Content $arg | foreach-object { $pcs += $_ }
    }
    Write-Host "`n`nUsing hosts from file(s) " -NoNewLine
    foreach ($arg in $args) {
        Write-Host "$arg " -NoNewLine
    }
    $pcs | Format-Wide {$_} -Column 6 -Force
    start-sleep -m 1250
} else {
    # Prompt for Organization Unit selection.
    if (([string]::Compare($ouselect, 'y', $True) -eq 0) -or ([string]::Compare($ouselect, 'yes', $True) -eq 0)){
        $ou = Choose-ADOrganizationalUnit
        $oubool = 1
        $pcs = $(Get-ADComputer -Filter * -SearchBase $ou.distinguishedName)
        $pcs = $pcs.name -split ' '
        Write-Host "Using hosts from OU"$ou.name":"
        $pcs | Format-Wide {$_} -Column 6 -Force
    # Or, enter hosts line-by-line.
    } else {
        $entry = "temp"
        Write-Host "`nEnter valid hostnames one line a time. A list may be pasted in."
        Write-Host "Case insensitive. When finished, enter a blank line.`n"
        while ($entry -ne "") { 
            $entry = Read-Host -Prompt 'Enter hostname'
            
            if ($entry -ne "") { 
                $pcs += $entry 
            }
        }
    }
}

clear

Write-Host "`n=================================="
Write-Host "Waking PCs from"$dcs[$site-1]
Write-Host "==================================`n"

# Establish remote PSSession to server on the target
# subnet. In most instances, this requires being on
# the remote server's same domain.
#
# Uncomment credential parameter if you'd like to 
# connect as a different user.
$s = New-PSSession -ComputerName $dcs[$site-1] #-Credential $(Get-Credential -Credential $null)
Invoke-Command -Session $s -Scriptblock { 

    # Build and send the "magic" packet.
    # Function provided by AdminArsenal blog post:
    # http://www.adminarsenal.com/admin-arsenal-blog/wake-on-lan-wol-magic-packet-powershell/
    function sendWakePacket([string] $Mac) {
    
        $MacByteArray = $Mac -split "[:-]" | ForEach-Object {  
            [Byte] "0x$_"
        }

        Write-Host "Sending Wake command to address"$Mac
        
        [Byte[]] $MagicPacket = (,0xFF * 6) + ($MacByteArray  * 16)
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
        for ($i=1; $i -le 3; $i++){
            $UdpClient.Send($MagicPacket,$MagicPacket.Length) > $null
        }
        $UdpClient.Close()
    }

    $hostArray = $using:pcs
    Write-Host ""

    # Get the individual targets and send the packets.
    echo $using:machold > .\temp.txt
    $hostarray | % {
        $arpgrep = Get-Content .\temp.txt | Select-String $_
        $arpsplit = $arpgrep -split '\s+'
        $cutmac = $arpsplit[1]

        sendWakePacket($cutmac)
    }
    Remove-Item .\temp.txt -Confirm:$false
}
Remove-PSSession $s

Read-Host -Prompt "`nPress [Enter] to close..."