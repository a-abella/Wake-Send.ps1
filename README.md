# Wake-Send.ps1
A Powershell 3.0+ script to send Wake-On-LAN packets to multiple hosts.

Select target PCs from source files passed as parameters, from Organization Units, or from manual entry. Resolves target MAC addresses
from data files generated by macscanner.sh. Sends 3x WoL broadcasts for each host.

Organizational Unit graphical selection dialog provided by MicaH's Choose-ADOrganizationaUnit function. https://itmicah.wordpress.com/2016/03/29/active-directory-ou-picker-revisited/

## How it works ##
1. If working with multiple subnets, select the site/subnet the wake targets are in.
2. Hosts are provided by input files, OU selection, or manual entry.
3. Host MAC addresses are retrieved from data files built from Nmap parsing (macscanner.sh).
4. Enter PS Remote session to Windows host on the target subnet, and pass hostnames and MAC addresses.
5. Create "magic" WoL UDP packets with .NET functions for each host and broadcast from remote host.

## Requirements ##
1. Powershell Remoting enabled on remote host. To establish a PS Remote session, at least one of the following must be true: 
  1. The local PC must be on the same domain as the remote PC. 
  2. The remote host must have the local PC in its trusted hosts. 
  3. You must configure the remote and local PCs to do PS Remoting over HTTPS.
2. Powershell 3.0+ on both the local and remote PCs.
3. ActiveDirectory Powershell module installed on the local PC (available in Windows RSAT).
4. MicaH's ChooseADOrganizationalUnit.ps1 file for dotsourcing. https://itmicah.wordpress.com/2016/03/29/active-directory-ou-picker-revisited/

## Usage ##
1. Pass a list of hosts from a text file by calling <code>Wake-Send.ps1 hostlist.txt[,hostlist2.txt]</code>
2. Call <code>Wake-Send.ps1</code> with no parameters to enter interactive mode.
  1. If waking hosts from AD OU, select the OU from the graphical dialog.
  2. Else, enter hostnames or IPs one by one.

Read through script comments for the lines that must be edited to suit your environment.
