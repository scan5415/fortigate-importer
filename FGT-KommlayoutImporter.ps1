<# 
.SYNOPSIS
    Add Firewall Policies from Com-Layout

.DESCRIPTION 
    Read the downloaded Communication Layout and add the needed rules in the corespondending FortiGate over API.

.NOTES 
    You need the UMB Default Communication Layout and the Firewall Credentials. The Script should be run in the UMB SDMZ Enviroment

.COMPONENT 
    

.LINK 
    

.Parameter ParameterName 
    
#>

#################################
# Disable Certificate Check
#################################
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

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
[ServerCertificateValidationCallback]::Ignore()


#################################
# Functions
#################################

function out-default {$input | out-null}

function FindAddrInformation {
    param( [string]$addrDesc,
    $workbook)
    

    $worksheet = $workbook.Sheets.Item(4)
    $intRowCount = $worksheet.usedRange.Rows.Count

    #Loop through Excel Rows
    for($i=1;$i -le $intRowCount; $i++)
    {
        
        if($worksheet.Cells.Item($i,1).Text -eq $addrDesc)
        {
            $value = $worksheet.Cells.Item($i,2).Value()
            $AddrInformation = @{}
            $AddrInformation.add('addr', $value)
            return $AddrInformation
        }
    }

    $AddrInformation = @{addr = $addrDesc}
    return $AddrInformation
}

function FindPortInformation {
    param( [string]$portDesc,
    $workbook)
    

    $worksheet = $workbook.Sheets.Item(5)
    $intRowCount = $worksheet.usedRange.Rows.Count

    #Loop through Excel Rows
    for($i=1;$i -le $intRowCount; $i++)
    {
        
        if($worksheet.Cells.Item($i,1).Text -eq $portDesc)
        {
            $PortInformation = @{}
            $PortInformation.add('services', $worksheet.Cells.Item($i,2).Value())
            return $PortInformation
        }
    }

    $PortInformation = @{services = $portDesc }
    return $PortInformation
}

Function Get-FileName($initialDirectory) {  
 [System.Reflection.Assembly]::LoadWithPartialName(“System.windows.forms”) |
 Out-Null

 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
 $OpenFileDialog.initialDirectory = $initialDirectory
 $OpenFileDialog.filter = “All files (*.*)| *.*”
 $OpenFileDialog.ShowDialog() | Out-Null
 $OpenFileDialog.filename
}

Function FortiGate_Login {
    param([string] $username,
        [string] $password,
        [string] $IP,
        [int] $port)

    $body = @{
        username = $username
        secretkey = $password
        ack_pre_disclaimer = $true
        ack_post_disclaimer = $true
        request_key = $true
    }

    $parameter = @{
        Method = "POST"
        Uri = "https://$($IP):$($port)/api/v2/authentication"
        Body = ($body | ConvertTo-Json)
        ContentType = "application/json"
    }

    $restResp = Invoke-RestMethod @parameter

    if($restResp.status_code -eq "5") {
        return @{ login = $true; message = $restResp.session_key }
    } else {
        return @{ login = $false; message = $restResp.status_message }
    }
}

Function FortiGate_AddAddress {
    param([string] $ip,
        [string] $mask,
        [hashtable] $fgt)

    if($mask -eq 32) {
        $body = @{
            name = "host_$($ip)"
            type = "ipmask"
            subnet = "$($ip)/32"
        }
    } else {
        $body = @{
            name = "net_$($ip)"
            type = "ipmask"
            subnet = "$($ip)"
        }
    }

    $parameter = @{
        Method = "POST"
        Uri = "https://$($fgt.ip):$($fgt.port)/api/v2/cmdb/firewall/address?access_token=$($fgt.session)"
        Body = ($body | ConvertTo-Json)
        ContentType = "application/json"
    }

    try {
        $restResp = Invoke-RestMethod @parameter
        Write-Host -ForegroundColor Green "Address Object for $($ip) created"
    } catch {
        if($_.Exception.Response.StatusCode.value__ -eq 500) {
            #Write-Host -ForegroundColor Yellow "Error from FortiGate: Object for $($ip) already exists. Please check it."
        } else {
            Write-Host -BackgroundColor Red -ForegroundColor White "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host -BackgroundColor Red -ForegroundColor White "StatusDescription:" $_.Exception.Response.StatusDescription
            exit
        }
    }
}

Function FortiGate_AddService {
    param([string] $service,
        [hashtable] $fgt)

    $proto, $port = $service.split('/')
    
    $body = @{ name = $service.Replace("/","_"); protocol = $proto }
    $body.add("$($proto)-portrange",$port)
    

    $parameter = @{
        Method = "POST"
        Uri = "https://$($fgt.ip):$($fgt.port)/api/v2/cmdb/firewall.service/custom?access_token=$($fgt.session)"
        Body = ($body | ConvertTo-Json)
        ContentType = "application/json"
    }

    try {
        $restResp = Invoke-RestMethod @parameter
        Write-Host -ForegroundColor Green "Service Object for $($service) created"

    } catch {
        if($_.Exception.Response.StatusCode.value__ -eq 500) {
            #Write-Host -ForegroundColor Yellow "Error from FortiGate: Object for $($service) already exists. Please check it."
        } else {
            Write-Host -BackgroundColor Red -ForegroundColor White "ERROR - StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host -BackgroundColor Red -ForegroundColor White "ERROR - StatusDescription:" $_.Exception.Response.StatusDescription
            exit
        }
    }
}

Function FortiGate_AddPolicy {
    param([string] $name,
        [hashtable] $src,
        [hashtable] $dst,
        [hashtable] $service,
        [string] $description,
        [hashtable] $fgt)

        $body = @{
            status = "enable"
            name = $name
            srcintf = @(
                @{ name = $src.interface }
            )
            dstintf = @(
                @{ name = $dst.interface }
            )
            srcaddr = $src.rule
            dstaddr = $dst.rule
            service = $service.rule
            action = "accept"
            schedule = "always"
            logtraffic = "all"
            comments = $description
        }

        $parameter = @{
            Method = "POST"
            Uri = "https://$($fgt.ip):$($fgt.port)/api/v2/cmdb/firewall/policy?access_token=$($fgt.session)"
            Body = ($body | ConvertTo-Json -Depth 4)
            ContentType = "application/json"
        }

        try {
            $restResp = Invoke-RestMethod @parameter
            $policyID = FortiGate_GetPolicyID -name $name
            Write-Host -ForegroundColor Green "Firewall Policy ID $($policyID) created."

            return $policyID

        } catch {
            Write-Host -BackgroundColor Red -ForegroundColor White "ERROR FortiGate: Cannot create Firewall Policy! May Rule alreay exist..." 
            Write-Host -BackgroundColor Red -ForegroundColor White "ERROR FortiGate - StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host -BackgroundColor Red -ForegroundColor White "ERROR FortiGate - StatusDescription:" $_.Exception.Response.StatusDescription
            Read-Host "Press ENTER to continue..."

            return $false
        }
}

Function FortiGate_GetPolicyID {
    param([string] $name)

    $response = Invoke-RestMethod -Uri "https://$($fgt.ip):$($fgt.port)/api/v2/cmdb/firewall/policy?key=name&pattern=$($name)&access_token=$($fgt.session)"
    
    return $response.Results[0].policyid
}

function IsValidIPv4Address ($ip) {
    return ($ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($ip -as [ipaddress]))
}

Function AddAddressToFirewall {
    param([string] $address,
        [hashtable] $fgt)


    # Check if it's an subnet
    if((Select-String -Pattern '/' -InputObject $address | foreach {$_.Matches}).Success) {
        $submask = ($address).Substring(($address).LastIndexOf("/")+1)
        # Add address to firewall
        FortiGate_AddAddress -ip $address -mask $submask -fgt $fgt
        $result = "net_$($address)"

    # If not a subnet, check if a valid IP Host address
    } elseif(IsValidIPv4Address($address)) {
        # Add address to firewall
        FortiGate_AddAddress -ip $address -mask 32 -fgt $fgt
        $result = "host_$($address)"
    }

    return $result
}

Function AddServiceToFirewall {
    param([string] $service,
        [hashtable] $fgt)

    FortiGate_AddService -service $service -fgt $fgt

    return $service.Replace("/","_")
}

Function AddPolicyToFirewall {
    param([hashtable] $src,
    [hashtable] $dst,
    [hashtable] $service,
    [string] $name,
    [string] $comment,
    [string] $user,
    [hashtable] $fgt)


    $date = Get-Date -Format "yyyyMMdd"
    $description = "$($date)/$($user) - $($comment)"

    FortiGate_AddPolicy -name $name -src $src -dst $dst -service $service -description $description -fgt $fgt
}

Function ValidateInputs {
    param([hashtable] $src,
        [hashtable] $dst,
        [hashtable] $service,
        [string] $user,
        [string] $name,
        [string] $comment)

    $validate = $true

    if(-Not ($src.addr.length -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Source Address empty!"
        $validate = $false
    }
    if(-Not ($src.interface.length -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Source Interface empty!"
        $validate = $false
    }
    if(-Not ($dst.addr.length -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Destination Address empty!"
        $validate = $false
    }
    if(-Not ($dst.interface.length -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Destination Interface empty!"
        $validate = $false
    }
    if(-Not ($service.rule.length -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Destination Service empty!"
        $validate = $false
    }
    if(-Not ($user -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Username is empty!"
        $validate = $false
    }
    if(-Not ($comment -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Rule Comment is empty!"
        $validate = $false
    }
    if(-Not ($name -gt 0)) {
        Write-Host -ForegroundColor White -BackgroundColor Red "Rule Name is empty!"
        $validate = $false
    }

    return $validate
}

Function StartBanner {
    Write-Host -ForegroundColor DarkYellow @"
      /##   /## /##      /## /#######         /######   /######
     | ##  | ##| ###    /###| ##__  ##       /##__  ## /##__  ##
     | ##  | ##| ####  /####| ##  \ ##      | ##  \ ##| ##  \__/
     | ##  | ##| ## ##/## ##| #######       | ########| ## /####
     | ##  | ##| ##  ###| ##| ##__  ##      | ##__  ##| ##|_  ##
     | ##  | ##| ##\  # | ##| ##  \ ##      | ##  | ##| ##  \ ##
     |  ######/| ## \/  | ##| #######/      | ##  | ##|  ######/
      \______/ |__/     |__/|_______/       |__/  |__/ \______/
***********************************************************************
                  WELCOME TO FORTIGATE RULE IMPORTER
***********************************************************************
"@
Start-Sleep 2
}

#################################
# Ask User for global Information
#################################
StartBanner
$fgtIP = Read-Host "IP Address of FortiGate"
$fgtPort = Read-Host "FortiGate HTTPS Port"
$user = Read-Host "Your username (e.g. scy)"
$fgt = @{ ip = $fgtIP; port = $fgtPort}

Write-Host "FortiGate Login"
$fgtCred = Get-Credential "fwadmin"

Write-Host "Please open the Communication Layout Excel"
$xlsxFilePath = Get-FileName

# Check if File selected
if($xlsxFilePath.length -eq 0) {
    Write-Host -BackgroundColor Red -ForegroundColor White "No Excel seleted. Stop Script. BYE..."
    exit
}

clear

#################################
# Main Script
#################################

# Test FortiGate Login
$fgtSession = FortiGate_Login -username $fgtCred.GetNetworkCredential().UserName -password $fgtCred.GetNetworkCredential().Password -IP $fgtIP -port $fgtPort


# Check Login was successfull
if($fgtSession.login -ne $true) {
    Write-Host -BackgroundColor Red -ForegroundColor White "FortiGate Login FAILED: $($fgtSession.message)"
    Exit
} else {
    Write-Host -ForegroundColor Green "FortiGate Login SUCCESS"
    $fgt.add('session', $fgtSession.message)
}


$ExcelObject = New-Object -ComObject Excel.Application


Write-Host -ForegroundColor Yellow "Open Excel: Please wait..."
$ExcelWorkBook = $ExcelObject.Workbooks.Open($xlsxFilePath)

$ExcelWorkSheet = $ExcelWorkBook.Sheets.Item(3)
$intRowCount = $ExcelWorkSheet.usedRange.Rows.Count

#Loop through Excel Rows
for($i=1; $i -le $intRowCount; $i++)
{
    if($ExcelWorkSheet.Cells.Item($i,20).Text -eq "Bereit für Implementation") {
        Write-Host -ForegroundColor Yellow "Creating Rule for Row $($i)..."

        #Read Information from Excel
        $sourceInfo = FindAddrInformation -addrDesc $ExcelWorkSheet.Cells.Item($i,7).Text -workbook $ExcelWorkBook
        $sourceInfo.add("interface",$ExcelWorkSheet.Cells.Item($i,6).Text)
        $destInfo = FindAddrInformation -addrDesc $ExcelWorkSheet.Cells.Item($i,14).Text -workbook $ExcelWorkBook
        $destInfo.add("interface",$ExcelWorkSheet.Cells.Item($i,13).Text)
        $destPort = FindPortInformation -portDesc $ExcelWorkSheet.Cells.Item($i,9).Text -workbook $ExcelWorkBook

        #----------------------
        # Create Base Objects
        # Like: Address, Services
        #----------------------

        # Loop through Source - Addresslist
        # Prepare Source List for Firewallrule
        $rule = New-Object System.Collections.ArrayList

        $sourceInfo.addr.Replace(" ","")
        if($sourceInfo.addr.Contains("`n")) {
            foreach($source in $sourceInfo.addr.Split("`n")) {
               $return = AddAddressToFirewall -address $source -fgt $fgt

               $rule.add(@{ name = $return}) 
            }
        } else {
            $return = AddAddressToFirewall -address $sourceInfo.addr -fgt $fgt

            if($return -eq $null) {
                $rule.add(@{ name = $sourceInfo.addr})
            } else {
                $rule.add(@{ name = $return})
            }
        }
        $sourceInfo.add("rule",$rule)

        # Loop through Destination - Addresslist
        # Prepare Destination List for Firewallrule
        $rule = New-Object System.Collections.ArrayList

        $destInfo.addr.Replace(" ","")
        if($destInfo.addr.Contains("`n")) {
            $destInfo.addr.Split("`n") | ForEach {
                $return = AddAddressToFirewall -address $_ -fgt $fgt

                $rule.add(@{ name = $return})
            }
        } else {
            $return = AddAddressToFirewall -address $destInfo.addr -fgt $fgt

            if($return -eq $null) {
                $rule.add(@{ name = $destInfo.addr})
            } else {
                $rule.add(@{ name = $return})
            }
        }
        $destInfo.add("rule", $rule)
        
        # Loop through Destination Services
        # Prepare Port List for Firewallrule
        $rule = New-Object System.Collections.ArrayList

        $destPort.services.Replace(" ","")
        if($destPort.services.Contains("`n")) {
            $destPort.services.Split("`n") | ForEach {
                $return = AddServiceToFirewall -service $_ -fgt $fgt

                $rule.add(@{ name = $return})
            }
        } else {
            $return = AddServiceToFirewall -service $destPort.services -fgt $fgt

            $rule.add(@{ name = $return})
        }
        $destPort.add("rule", $rule)

        $snat = $ExcelWorkSheet.Cells.Item($i,5).Text
        $dnat = $ExcelWorkSheet.Cells.Item($i,12).Text
        $rulename = $ExcelWorkSheet.Cells.Item($i,19).Text
        $comment = $ExcelWorkSheet.Cells.Item($i,3).Text

        # SNAT is not supported
        if($snat -ne "" -or $dnat -ne "") {
            Write-Host -ForegroundColor Red -BackgroundColor Yellow "NAT is not supported. Create Rule for Row $($i) manually."
            Read-Host "Press ENTER to continue"
            continue
        }

        #Validate all inputs¨
        if(-Not (ValidateInputs -dst $destInfo -src $sourceInfo -service $destPort -user $user -name $rulename -comment $comment)) {
            Read-Host "Validation failed. Press ENTER to continue"
            continue
        } else {
            $policyID = AddPolicyToFirewall -src $sourceInfo -dst $destInfo -service $destPort -name $rulename -comment $comment -user $user -fgt $fgt

            if($policyID -ne $false) {
                #Policy successfull added to FGT, Update Excel
                $ExcelWorkSheet.Cells.Item($i,20) = "Done"
                $ExcelWorkSheet.Cells.Item($i,18) = $policyID
                $ExcelWorkSheet.Cells.Item($i,17) = $user

                $ExcelWorkBook.Save()
            }
        }

    }
}

Write-Host -ForegroundColor DarkYellow "Uff... It was a hard work! All ready firewall rules are implemented! YEAH!!!"
Write-Host -ForegroundColor DarkYellow "Thanks for using. See you soon... BYE."
$ExcelWorkBook.Close($false)
$ExcelObject.Quit()


