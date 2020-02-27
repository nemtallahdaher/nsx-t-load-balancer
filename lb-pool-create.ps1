
# Script used to create or delete LB Pools in NSX-T
do
{
    try {
    [ValidatePattern('^patch|^delete')]$patchordel = read-host "Do you want to delete or patch"
    } catch {}
} until ($?)

# Input CSV requires this format (First line is a header)
# poolid,algo,group,monitor,snatip,port
$LoadCSV = read-host "Provide path to CSV file"

# Test CSV existance
if (!(Test-Path $LoadCSV)) {
  Write-Host "[$(Get-Date)] CSV with LB pool information not found! ($LoadCSV)" -ForegroundColor "red"
  Exit
}

##### Set up TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

##### Handle Self Signed Certificates
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

##### Prompt for NSX Server if neccessary
$NSXTServer = read-host "Provide NSX-T Server FQDN"

##### Gather Credentials for NSXT
$cred = Get-Credential

##### Build the Header for Authentication
$headerDictionary = @{}
    $base64cred = [system.convert]::ToBase64String(
        [system.text.encoding]::ASCII.Getbytes(
            "$($cred.GetNetworkCredential().username):$($cred.GetNetworkCredential().password)"
        )
    )
$headerDictionary.add("Authorization", "Basic $Base64cred")

##### Setup the URI to NSX to pull a list of NSX Segments
$Method = $patchordel
$Timeout = "600"
$ContentType = "application/json"


################################## Create Function ####################################

Function CreateLBPool() {

    Param (
      [Parameter(Position=0,mandatory=$true)]
        [string] $poolid,
      [Parameter(Position=1,mandatory=$true)]    
        [string]$algo,
      [Parameter(Position=2,mandatory=$true)]   
        [string]$group,
      [Parameter(Position=3,mandatory=$true)]   
        [string]$monitor,
      [Parameter(Position=4,mandatory=$true)]   
        [string]$snatip,
      [Parameter(Position=4,mandatory=$true)]   
        [int]$port)



    ##### Build the Pool

    ##### Setup the call to create pool
    $URI = "/policy/api/v1/infra/lb-pools/$($poolid)"
    $FullURI = "https://$($NSXTServer)$($URI)"
    $Body = @"
    {
      "algorithm": "$algo",
      "member_group": {
        "group_path": "/infra/domains/default/groups/$group",
        "port" : $port,
        "ip_revision_filter": "IPV4"
      },
      "active_monitor_paths": [
        "/infra/lb-monitor-profiles/$monitor"
      ],
      "snat_translation": {
        "ip_addresses": [
          {
            "ip_address": "$snatip"
          }
        ],
        "type": "LBSnatIpPool"
      },
      "id" : "$poolid"
    }
"@ 
$FullURI
$Body 
    $Splat = @{
            "method" = $Method;
            "headers" = $headerDictionary;
            "ContentType" = $ContentType;
            "uri" = $FullURI;
            "TimeoutSec" = $Timeout;
            "Body" = $Body
        }

    ##### Go get the data via a rest call
    try
    {
      $response = invoke-restmethod @Splat
    }
    catch
    {
      Throw "Connection to NSX server $NSXTServer failed : $_"
    }

#End Function
}

###############################################################################################
# Begin Script Function to Build LB Pools
###############################################################################################

# Read the CSV into memory (using delimiter ',' so you can use Excel to modify it)
$csvList = Import-CSV $LoadCSV -Delimiter ','
foreach($csvLine in $csvList)
{
  Write-Host "[$(Get-Date)] Processing LB Pool $($csvLine.poolid)." -ForegroundColor "green"
  CreateLBPool -poolid $csvLine.poolid -algo $csvLine.algo -group $csvLine.group -monitor $csvLine.monitor -snatip $csvLine.snatip -port $csvLine.port
}
