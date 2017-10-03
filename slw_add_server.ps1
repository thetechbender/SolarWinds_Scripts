<#
This script will add a server to SolarWinds.
Uses different rules and methodologies for dev, test, and prod domains.
#>
#Define parameters
param(
    
    #Set the name of the SolarWinds server.
    [Alias("s", "server")]
    $slw_server = "",

    #Set the ip address of the server to add to SolarWinds
    [Parameter(Mandatory=$true)]
    [Alias("ip")]
    $ipaddress,

    #Set the hostname of the server to add to SolarWinds
    [Parameter(Mandatory=$true)]
    [Alias("h")]
    $hostname
    )


#Define domain naming convention
$dev_domain = ""
$test_domain = ""
$prod_domain = ""


#Load SolarWinds Information Service (SWIS) Snapin and PowerOrion Module
Import-Module SuperPowerOrion

#Validate that the IP address is valid
$is_valid_ip = Test-IsValidIP $ipaddress
If($is_valid_ip -eq $false){
    Write-Host "IP Address $ipaddress is not valid. Please check the IP address and try again." -ForegroundColor Red
    Exit
    }

#Set SWIS variables to use the powershell user's current credentials
Write-Host "Accessing the SolarWinds API using credentials for $env:username..."
$swis = Connect-Swis -Trusted -Hostname $slw_server    

#Test the SWIS connection and make sure user has rights to add nodes
Try{$authorization=@(Get-SwisData $swis "SELECT AccountID, Enabled, AllowNodeManagement
FROM Orion.Accounts
WHERE AccountID LIKE '%$env:username'") }
Catch 
{ 
    Write-Host “Caught an exception when trying to connect to SolarWinds server $slw_server.” -ForegroundColor Red
    Write-Host “Exception Type: $($_.Exception.GetType().FullName)” -ForegroundColor Red
    Write-Host “Exception Message: $($_.Exception.Message)” -ForegroundColor Red
    Exit
    }

If ($authorization.Enabled -ne "Y"){
    Write-Host "The user $env:username is disabled in SolarWinds" -ForegroundColor Red
    Exit
    }
    ElseIf ($authorization.AllowNodeManagement -ne "Y"){
        Write-Host "The user $env:username does not have node management rights" -ForegroundColor Red
        Exit
        }

#Determine if node already exists in SolarWinds. If so, exit the script.
$nodeexists = $null
$nodeexists = Get-OrionNodeID -SwisConnection $swis -IPAddress $ipaddress
If($nodeexists -ne $null){
    Write-Host "Node with IP address $ipaddress already exists in SolarWinds with NodeID $nodeexists." -ForegroundColor Red
    Exit
    }

#Get subnets from IPAM
$subnets = Get-SwisData $swis `
    "SELECT Address, CIDR, Domain
    FROM
	    (SELECT DISTINCT Address, CIDR, 
	    CASE 
		    WHEN FriendlyName LIKE '%dev%' THEN '$dev_domain'
		    WHEN FriendlyName LIKE '%test%' THEN '$test_domain'
		    WHEN FriendlyName LIKE '%prod%' THEN '$prod_domain'
		    WHEN FriendlyName IN (
			    'Prod Subnet 1',
			    'Prod Subnet 2',
			    'Prod Subnet 3') 
			    THEN '$prod_domain'
		    ELSE NULL
		    END AS Domain
	    FROM IPAM.Subnet
	    WHERE Address LIKE '$ip_address_pattern')
    WHERE Domain IS NOT NULL"


#Determine if node is in Dev, Test, or Prod subnet
ForEach($subnet in $subnets){
    $subnet_formatted = $subnet.address+"/"+$subnet.CIDR
    $issubnet = Test-Subnet $subnet_formatted $ipaddress
    If($issubnet -eq "True"){
        $domain=$subnet.Domain 
        break
        }
        Else {
            $domain="unknown"
            }
     }


#Make hostname lower case
$hostname = $hostname.ToLower()

#Add node using method appropriate for each environment
If($domain -eq $dev_domain){    #Do not monitor dev domain servers
    Write-Host "Nodes in $dev_domain are not monitored by SolarWinds at this time." -ForegroundColor Red
    Exit
    }
    ElseIf($domain -eq $test_domain){    #Add a ping monitor for test domain servers
        
        #Check to make sure that the hostname matches the server naming convention
        If($hostname.EndsWith("."+$test_domain) -eq $false){
            Write-Host "The hostname needs to end with .$test_domain"
            Exit
            }

        #Verify that node is pingable before adding it to SolarWinds
        Try{Test-Connection -BufferSize 32 -Count 1 -ComputerName $ipaddress | Out-Null}
            Catch{ 
                Write-Host "Failed to ping node with $ipaddress. Please check the status of the host." -ForegroundColor Red
                Exit
                }
            
        Write-Host "Adding $test_domain node with IP address $ipaddress"
        #Servers in the test domain are only monitored with pings
        New-OrionNode -SwisConnection $swis -IPAddress $ipaddress -NodeName $hostname


        ###
        #Confirm that the action was successful by pulling the NodeID with IP address
        ###


        }
    ElseIf($domain -eq $prod_domain){    #Use the Discovery process to find and add the node.
        
        #Check to make sure that the hostname matches the server naming convention
        If($hostname.EndsWith("."+$prod_domain) -eq $false){
            Write-Host "The hostname needs to end with .$prod_domain"
            Exit
            }

            
        #Verify that node is pingable before adding it to SolarWinds
        $pingTest = $null
        $pingTest = Test-Connection -BufferSize 32 -Count 1 -ComputerName $hostname -ErrorAction SilentlyContinue
        
        If($pingTest -eq $null){                  
        Write-Host "Failed to ping node $hostname. Please check the hostname, status of the host, or DNS records." -ForegroundColor Red
            Exit
            }

        #Verify that the resolved IP address matches the $ipaddress argument
        $pingIP = $pingTest.IPV4Address.IPAddressToString

        If($pingIP -ne $ipaddress){
            Write-Host "Ping test to $hostname returned IP Address $pingIP. This does not match the entered value of $ipaddress." -ForegroundColor Red
            Exit
            }



        Write-Host "Starting discovery for $hostname - $ipaddress"
        #Documentation of the server discovery process comes from here: 
        #https://github.com/solarwinds/OrionSDK/wiki/Discovery
        #The next 4 steps will discover and import the server's components (CPU, mem, disk, etc) using the Network Sonar feature of SolarWinds
        
        #1. Build a discovery context

            #Get a list of all credentials from Orion
            $CredsList = Get-SwisData $swis "SELECT ID, Name, CredentialType, CredentialOwner
                    FROM Orion.Credential"

            #Find the Windows and Linux credential IDs to use in the discovery
            $WindowsCredID =  $CredsList |
                Where-Object {$_.Name -eq "$windows_wmi_creds" -and $_.CredentialType -eq "SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential" -and $_.CredentialOwner -eq "Orion"} |
                    Select-Object -ExpandProperty ID
            $LinuxCredID =   $CredsList | 
                Where-Object {$_.Name -eq "$linux_snmp_creds" -and $_.CredentialType -eq "SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV3" -and $_.CredentialOwner -eq "Orion"} | 
                    Select-Object -ExpandProperty ID

            #Core plugin configuration
                $CorePluginConfigurationContext = ([xml]"
                <CorePluginConfigurationContext xmlns='http://schemas.solarwinds.com/2012/Orion/Core' xmlns:i='http://www.w3.org/2001/XMLSchema-instance'>
                    <BulkList>
                        <IpAddress>
                            <Address>$ipaddress</Address>
                        </IpAddress>
                    </BulkList>
                    <IpRanges>
                    </IpRanges>
                    <Subnets>
                    </Subnets>
                    <Credentials>
                        <SharedCredentialInfo>
                            <CredentialID>$WindowsCredID</CredentialID>
                            <Order>1</Order>
                        </SharedCredentialInfo>
                        <SharedCredentialInfo>
                            <CredentialID>$LinuxCredID</CredentialID>
                            <Order>2</Order>
                        </SharedCredentialInfo>
                    </Credentials>
                    <WmiRetriesCount>1</WmiRetriesCount>
                    <WmiRetryIntervalMiliseconds>1000</WmiRetryIntervalMiliseconds>
                </CorePluginConfigurationContext>
                ").DocumentElement

                $CorePluginConfiguration = Invoke-SwisVerb $swis Orion.Discovery CreateCorePluginConfiguration @($CorePluginConfigurationContext)

            #Interfaces plugin configuration
                $InterfacesPluginConfigurationContext = ([xml]"
                <InterfacesDiscoveryPluginContext xmlns='http://schemas.solarwinds.com/2008/Interfaces' 
                                                    xmlns:a='http://schemas.microsoft.com/2003/10/Serialization/Arrays'>
                    <AutoImportStatus>
                        <a:string>Up</a:string>
                    </AutoImportStatus>
                    <AutoImportVirtualTypes>
                        <a:string>Virtual</a:string> 
                        <a:string>Physical</a:string>
                    </AutoImportVirtualTypes>
                    <AutoImportVlanPortTypes>
                        <a:string>Trunk</a:string>
                        <a:string>Access</a:string>
                        <a:string>Unknown</a:string>
                    </AutoImportVlanPortTypes>
                    <UseDefaults>false</UseDefaults>
                </InterfacesDiscoveryPluginContext>
                ").DocumentElement

                $InterfacesPluginConfiguration = Invoke-SwisVerb $swis Orion.NPM.Interfaces CreateInterfacesPluginConfiguration @($InterfacesPluginConfigurationContext)

            #Build discovery context from plugin configurations
                $EngineID = 1
                $DeleteProfileAfterDiscoveryCompletes = "true"

                $StartDiscoveryContext = ([xml]"
                <StartDiscoveryContext xmlns='http://schemas.solarwinds.com/2012/Orion/Core' xmlns:i='http://www.w3.org/2001/XMLSchema-instance'>
                    <Name>$ipaddress - Script Discovery $([DateTime]::Now)</Name>
                    <EngineId>$EngineId</EngineId>
                    <JobTimeoutSeconds>3600</JobTimeoutSeconds>
                    <SearchTimeoutMiliseconds>2000</SearchTimeoutMiliseconds>
                    <SnmpTimeoutMiliseconds>2000</SnmpTimeoutMiliseconds>
                    <SnmpRetries>1</SnmpRetries>
                    <RepeatIntervalMiliseconds>1500</RepeatIntervalMiliseconds>
                    <SnmpPort>161</SnmpPort>
                    <HopCount>0</HopCount>
                    <PreferredSnmpVersion>SNMP3</PreferredSnmpVersion>
                    <DisableIcmp>false</DisableIcmp>
                    <AllowDuplicateNodes>false</AllowDuplicateNodes>
                    <IsAutoImport>true</IsAutoImport>
                    <IsHidden>$DeleteProfileAfterDiscoveryCompletes</IsHidden>
                    <PluginConfigurations>
                        <PluginConfiguration>
                            <PluginConfigurationItem>$($CorePluginConfiguration.InnerXml)</PluginConfigurationItem>
                            <PluginConfigurationItem>$($InterfacesPluginConfiguration.InnerXml)</PluginConfigurationItem>
                        </PluginConfiguration>
                    </PluginConfigurations>
                </StartDiscoveryContext>
                ").DocumentElement


        #2. Start discovery and get discoveryID
            $DiscoveryProfileID = (Invoke-SwisVerb $swis Orion.Discovery StartDiscovery @($StartDiscoveryContext)).InnerText
            Write-Host "Discovering host details, volumes, and interfaces..."

        #3. Track the progress of discovery job
            do {
                Start-Sleep -Seconds 15
                $Status = Get-SwisData $swis "SELECT Status FROM Orion.DiscoveryProfiles WHERE ProfileID = @profileId" @{profileId = $DiscoveryProfileID}
                Write-Host "..."
            } while ($Status -eq 1)





        #4. Clean up results of Discovery Process
            $Result = Get-SwisData $swis "SELECT Result, ResultDescription, ErrorMessage, BatchID FROM Orion.DiscoveryLogs WHERE ProfileID = @profileId" @{profileId = $DiscoveryProfileID}

            #Get all objects that were imported during the discovery process
            $Imported = Get-SwisData $swis "SELECT EntityType, DisplayName, NetObjectID FROM Orion.DiscoveryLogItems WHERE BatchID = @batchId" @{batchId = $Result.BatchID}
            
            #Remove all application monitors imported from discovery process
            $NewAppsID = $Imported | 
                Where-Object {$_.EntityType -eq "Orion.APM.Application"} | 
                    Select-Object -Property NetObjectID
            
            Write-Verbose "Cleaning up application monitors"
            
            ForEach($app in $NewAppsID){
                $prefix,$appid=$app.NetObjectID.split(':',2)
                Invoke-SwisVerb $swis "Orion.APM.Application" "DeleteApplication" @($appid) | Out-Null
                }

            #Remove unwanted volume monitors from discovery process
            $UnwantedVolumes = "Floppy Disk","Compact Disk"
            $NewVolumes = $Imported | 
                Where-Object {$_.EntityType -eq "Orion.Volumes"} | 
                    Select-Object -Property NetObjectID


            Write-Verbose "Removing volume monitors with types: $UnwantedVolumes"
            ForEach($volume in $NewVolumes){
                $prefix,$volid=$volume.NetObjectID.split(':',2)
                $voltype = Get-SwisData $swis "SELECT VolumeType, Uri FROM Orion.Volumes WHERE VolumeID = @volid" @{volid = $volid}
                If($UnwantedVolumes.Contains($voltype.VolumeType) -eq $true){
                    Remove-SwisObject -SwisConnection $swis -Uri $voltype.Uri
                    }
                }
                         
        #5. Set the caption on the node
            Set-OrionNodeCaption $swis $slw_server $ipaddress $hostname
                
        }
    Else {
        Write-Host "This node is not in one of the defined subnets. Please add it manually in the SolarWinds web console"
        }

#Make sure that the node exists
$nodeexists = $null
$nodeexists = Get-OrionNodeID -SwisConnection $swis -IPAddress $ipaddress
If($nodeexists -eq $null){
    Write-Host "Error adding $hostname to SolarWinds. Please try to add the host manually"
    Exit
    }


Write-Host "Successfully added $hostname to SolarWinds with node ID $nodeexists. Applying custom property values."


#Define custom property values to assign to new nodes.
#Select the first value (alphabeticaly) in the list of values for each custom property
$proplist = @(Get-SwisData $swis "SELECT Field AS Name, Min(Value) AS Value
FROM Orion.CustomPropertyValues
WHERE Field IN ('Node_Performance_Email','Node_Availability_Email')
GROUP BY Field")


#Set custom properties on the nodes
ForEach($prop in $proplist){
    $propname=$prop.name
    $propvalue=$prop.value

    Set-NodeCustomProperty $swis $slw_server $ipaddress $propname $propvalue
    }


Write-Host "Done."
