#region Params
Param (
    [parameter(Mandatory = $true, HelpMessage = "Enter the Address:")]
    [Alias("connection", "netbox")]
    [String]$ip,
    [parameter(Mandatory = $true, HelpMessage = "Enter the Token:")]
    [String]$token,
    [parameter(Mandatory = $true, HelpMessage = "Enter the SCVMM address")]
    [Alias("server")]
    [String]$scvmmServer,
    [parameter(Mandatory = $true, HelpMessage = "Enter the Password:")]
    [Alias("password")]
    [String]$scvmmPassword,
    [parameter(Mandatory = $true, HelpMessage = "Enter the SCVMM User:")]
    [Alias("user")]
    [String]$scvmmUser,
    [parameter(Mandatory = $false, HelpMessage = "Would you like to disable https?")]
    [Boolean]$insecure_http = $false,
    [Parameter(
            Mandatory = $false,
            HelpMessage = "Please enter for `$DebugPreference a value`n('SilentlyContinue','Continue' ,'Inquire' or 'Stop')",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
    )]
    [ValidateSet("SilentlyContinue", "Continue", "Inquire", "Stop")]
    [Alias("dbp", "dbPref")]
    [string]$debugMode = "SilentlyContinue"
)
#endregion

#region global netbox data
write-host "$( "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date) ) Warming up"
$DebugPreference = $debugMode
write-debug "$( "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date) ) Begin execution"
if ($DebugPreference -ne "SilentlyContinue")
{
    $ProgressPreference = "SilentlyContinue"
}

$ErrorActionPreference = "Stop"
[System.Net.ServicePointManager]::MaxServicePointIdleTime = 900000

#region URLs
function createConnectionString([string]$userInput)
{
    if ((-not$userInput -is [string]) -or ($userInput.Trim() -eq ""))
    {
        Throw "Couldnt create connection String from Userinput ($userInput)"
    }
    if ( $userInput.Contains("http"))
    {
        return $userInput
    }
    if ($insecure_http)
    {
        return "http://$userInput"
    }
    return "https://$userInput"
}
$apiBaseUrl = createConnectionString($ip)
$headers = @{
    "Authorization" = "Token $token"
    "Content-Type" = "application/json"
    "Accept" = "application/json"
}

$urlVM = ($apiBaseUrl + "/api/virtualization/virtual-machines/?limit=0")
$urlTenant = ($apiBaseUrl + "/api/tenancy/tenants/?limit=0")
$urlOS = ($apiBaseUrl + "/api/dcim/platforms/?limit=0")
$urlCluster = ($apiBaseUrl + "/api/virtualization/clusters/?limit=0")
$urlClusterType = ($apiBaseUrl + "/api/virtualization/cluster-types/?limit=0")
$urlIPAM = ($apiBaseUrl + "/api/ipam/ip-addresses/?limit=0")
$urlInterface = ($apiBaseUrl + "/api/virtualization/interfaces/?limit=0")
$Global:isOnlyinNB = "=>"
$Global:isNotinNB = "<="
#endregion
#endregion
#region Imports
Import-Module VirtualMachineManager
#endregion
#region generic helper methodes

################################
$global:currentStatus = "Creating Body: "
$global:PorgressbarID = 2
function setCurrentStatus($status)
{
    $global:currentStatus = $status
    $global:PorgressbarID += 1
}
function stepMainProgressBar($complete)
{
    write-progress -id 1 -activity "Main Program: " -PercentComplete $complete -status "Complete: "
}
function stepChildProgressBar($complete)
{
    write-progress -id $global:PorgressbarID -activity $global:currentStatus -PercentComplete $complete -status "Complete: " -ParentId 1
}
function popChildProgressBar()
{
    write-progress -id $global:PorgressbarID -activity $global:currentStatus -status "Complete: " -ParentId 1  -PercentComplete 100 -Completed
}
function writeDebugDate([string]$message)
{
    $date = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    Write-Debug "$date $message"
}

function writeOutputDate([string]$message)
{
    $date = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    Write-Host "$date $message"
}

function getRestResults([String] $URL)
{
    return ((Invoke-RestMethod -Uri $URL -Headers $headers -Method GET).results)
}

function getNameList([String] $URL)
{
    return (getRestResults $URL).Name
}

$MAX_RETRIES = 3
function restBody($body, $url, $verb)
{
    writeDebugDate "Method: $verb; URL: $url; Body: $body"
    writeOutputDate "Waiting for $verb-Answer, please be patient! (This can take up to 15minutes!)"
    $retry = 0
    if ($body -eq "")
    {
        return
    }
    $error = $false
    while ($retry -lt $MAX_RETRIES)
    {
        try
        {
            $retry += 1
            $postVar = (Invoke-RestMethod -Uri $url -Headers $headers -Method $verb -Body $body -Timeoutsec 900 | Out-String)
            $error = $false
            writeDebugDate($postVar)

            break
        }
        catch
        {
            write-warning "$verb did not went well, retrying $retry / $MAX_RETRIES"
            write-warning $_.exception.message
            $error = $true
        }
    }
    if ($error)
    {
        if (-not(Test-Path ".\body.json"))
        {
            New-Item -path ".\" -name "body.json" -type "file"
        }
        write-warning "trying to reach: $url"
        out-file -InputObject $body -FilePath ".\body.json"
        write-warning "please check the body.json for the offending json body, that was posted"
        throw "Exceeding retry limits"
    }
}

function postBody([String] $body, [String] $url)
{
    restBody $body $url 'Post'
}
function patchBody([String] $body, [String] $url)
{
    restBody $body $url 'Patch'
}
function deleteBody([String] $body, [String] $url)
{
    restBody $body $url 'Delete'
}

#endregion
#region global extra data
$nbIPAdresses = getRestResults $urlIPAM
$existingInterfaces = getRestResults $urlInterface
$vmNBList = getRestResults $urlVM
$existingTenants = getRestResults $urlTenant
$osLists = getRestResults $urlOS

$hpVID = -1
function getHyperVTypeID
{
    if ($hpVID -ne -1)
    {
        writeDebugDate "Using cached ID: $hpVID for HyperV"
        return $hpVID
    }
    writeDebugDate "Get ClusterTypes from Netbox; trying to find Name == HyperV"
    $hpVID = (getRestResults $urlClusterType | Where-Object { $_.Name -eq "HyperV" }).Id
    writeDebugDate "Got id: $hpVID for HyperV"
    return $hpVID
}

function getVMIdByName([string]$vmid)
{
    if ($null -eq $vmid -or $vmid -eq "")
    {
        Write-Warning "No VM name provided for ID lookup!"
        continue
    }
    $id = ($vmNBList | Where-Object{ $_.custom_fields.VMId -eq $vmid }).Id

    if ($null -eq $id)
    {
        Write-Warning "The VMID ($vmid) is not in the System"
    }
    return $id
}

function getVMIdNetbox([string]$vmName)
{
    if ($null -eq $vmName -or $vmName -eq "")
    {
        Write-Warning "No VM name provided for ID lookup!"
        continue
    }
    $id = ($vmNBList | Where-Object{ $_.Name -eq $vmName }).Id

    if ($null -eq $id)
    {
        Write-Warning "The VMID ($vmName) is not in the System"
    }
    return $id
}

function splitTenant([string]$tenantName)
{
    $fraIndex = $tenantName.IndexOf("-Fra")
    $doIndex = $tenantName.IndexOf("-Do")
    if ($fraIndex -ne -1) #tenantName contains "-Fra"
    {
        $tenFra = $tenantName.Substring(2, $fraIndex - 2)
        writeDebugDate "Split Tenant Name(original: $tenantName) returned: $tenFra"
        return $tenFra
    }
    elseif($doIndex -ne -1) #tenantName contains "-Do"
    {
        $tenDo = $tenantName.Substring(2, $doIndex - 2)
        writeDebugDate "Split Tenant Name(original: $tenantName) returned: $tenDo"
        return $tenDo
    }
    else
    {
        Write-Warning "Could not determine tenant for : $tenantName!"
        return ""
    }
}

function getTenantIdByName([string]$tenant)
{
    if ($tenant -eq "" -or $tenant -eq $null)
    {
        writeOutputDate "No name given for tenant ID lookup"
        return $null
    }

    $tenantSplit = splitTenant $tenant

    $id = ($existingTenants | Where-Object { $_.Name -eq $tenantSplit }).Id
    if ($null -eq $id)
    {
        Write-Warning "Tenant ($tenant) has no ID"
    }
    writeDebugDate "Lookup for Tenant: $tenant matched ID: $id"
    return $id
}

function getInterfaceIdByComboString([string]$nameStr)
{
    if ($nameStr -eq $null -or $nameStr -eq "")
    {
        Write-Warning "No Name provided for interface ID lookup!"
        return $null
    }

    $id = ($existingInterfaces | Where-Object{ ($_.virtual_machine.Name + $_.Name) -eq $nameStr }).Id
    if ($null -eq $id)
    {
        Write-Warning "Interface ($namestr) has no ID"
    }
    writeDebugDate "Lookup for Interface(virtual_machine.Name + interface.Name): $nameStr matched ID: $id"
    return $id
}
function linear($value, $min, $max, $newMin, $newMax)
{
    if (0 -eq ($max - $min))
    {
        return 0
    }
    $result = (($value - $min) / ($max - $min)) * ($newMax - $newMin) + $newMin
    return $result
}
function createBody($collection, $scriptblock)
{
    writeDebugDate("Creating body with $( $collection.count ) elements")
    $body = "["
    if ($collection.Count -eq 0)
    {
        return ""
    }

    $counter = 0
    foreach ($element in $collection)
    {
        $body += $scriptblock.Invoke($element)
        $counter += 1
        $step = linear $counter 0 ($collection.count) 0 100
        stepChildProgressBar $step
    }
    writeDebugDate( "created $counter body elements")
    popChildProgressBar
    if ($body -eq "[")
    {
        return ""
    }
    $body = $body.subString(0, $body.length - 1) + "]"
    return $body
}

function getHashVMs
{
    $VMs = Get-SCVirtualMachine -VMMServer $vmserver
    $hashVM = @{}

    foreach($vm in $VMs)
    {

        $clusterName = $vm.VMHost.HostCluster.ClusterName
        $singleClusterName = $vm.HostName
        $comboName = $vm.Name + $clusterName
        if($clusterName -eq "" -or $clusterName -eq $null)
        {
            $comboSingleName = $vm.Name + $singleClusterName
            if(-not $hashVM.ContainsKey($comboSingleName))
            {
                $hashVM.Add($comboSingleName,$vm)
                continue
            }
        }
        if(-not $hashVM.ContainsKey($comboName))
        {
            $hashVM.Add($comboName,$vm)
        }
    }
    return $hashVM
}

function getSCVMMVms
{
    $vmArray = @()
    $hashVMValue = getHashVMs
    foreach($vm in $hashVMValue.Values)
    {
        $vmArray += $vm
    }

    return $vmArray
}

$getVMs = getSCVMMVms

#endregion
#region tenant
function createTenantList
{
    $systemTenantList = @()
    $VMs = Get-SCVirtualMachine -VMMServer $vmserver
    writeDebugDate "fetching VirtualMachines from SCVMM: $VMs"
    foreach ($vm in $VMs)
    {
        $tenantName = $vm.Cloud.Name
        if ($null -eq $tenantName)
        {
            continue
        }
        $tenant = splitTenant $tenantName
        $systemTenantList += $tenant
    }
    $systemTenantList = $systemTenantList | Select-Object -Unique
    writeDebugDate "unique Tenant List: $systemTenantList"
    return $systemTenantList
}

function createTenantFilter($systemTenants)
{
    $nbTenants = getNameList $urlTenant
    writeDebugDate "NetBox Tenant List: $nbTenants"
    if ($null -eq $nbTenants)
    {
        return $systemTenants
    }
    $tenantList = Compare-Object -ReferenceObject $systemTenants -DifferenceObject $nbTenants
    $tenantList = $tenantList | Where-Object { $_.SideIndicator -eq $Global:isNotinNB }
    $tenantList = $tenantList.InputObject
    writeDebugDate "difference list tenant (netbox <=> Scvmm): $tenantList"
    return $tenantList
}

function createTenant
{
    writeDebugDate "About to create Tenants"
    $list = createTenantList
    $filter = (createTenantFilter $list) | Select-Object

    writeDebugDate "Should create tenants: $( $filter.length )"
    setCurrentStatus "create tenants"
    $body = createBody $filter {
        param ($teanant)
        return (@{
            "name" = $teanant
            "slug" = $teanant.toString().toLower()
        } | ConvertTo-Json) + ","
    }
    postBody $body $urlTenant
}
#endregion
#region os
function createOSList
{
    $OSs = Get-SCOperatingSystem -VMMServer $vmserver
    writeDebugDate "fetching OS list from SCVMM: $OSs"
    $systemOS = @()
    foreach ($os in $OSs)
    {
        $osName = $os.Name
        $systemOS += $osName
    }
    $systemOS = $systemOS | Select-Object -Unique
    writeDebugDate "unique systemOSs: $systemOS"
    return $systemOS
}

function createOSFilter($systemOS)
{
    $nbOS = getNameList $urlOS
    writeDebugDate "fetching OS list from Netbox: $nbOS"
    if ($null -eq $nbOS)
    {
        return $systemOS
    }
    $osList = Compare-Object -ReferenceObject $systemOS -DifferenceObject $nbOS
    $osList = $osList | Where-Object { $_.SideIndicator -eq $Global:isNotinNB }
    $osList = $osList.InputObject
    writeDebugDate "difference list OS (netbox <=> Scvmm): $osList"
    return $osList
}

function createOS
{
    writeDebugDate "About to create OSs"
    $filter = createOSFilter (createOSList)
    setCurrentStatus "create OS-list"
    $body = createBody $filter {
        param ($os)
        return (@{
            "name" = $os
            "slug" = $os.toString().ToLower() -replace "[ \(\)\/\.\\]", ""
        } | ConvertTo-Json) + ","
    }
    postBody $body $urlOS
}

function getOSIdByName([string]$nameStr)
{
    if ($null -eq $nameStr)
    {
        Write-Warning "No OS"
        return
    }
    if ($nameStr -eq "Unbekannt")
    {
        return
    }
    $id = (($osLists  | Where-Object{ $_.Name -eq $nameStr })).Id

    if ($null -eq $id)
    {
        Write-Warning "OS($namestr) has no ID"
    }
    writeDebugDate "OS ($namestr) matched ID: $id"
    return $id
}
#endregion
#region clusters
function createClusterList
{
    $Clusters = Get-SCVMHostcluster -VMMServer $vmserver
    writeDebugDate "fetching Cluster list from SCVMM: $Clusters"
    $scvmmClusterArray = @()
    foreach ($cluster in $Clusters)
    {
        $scvmmClusterArray += $cluster
    }
    $scvmmClusterArray = $scvmmClusterArray | Select-Object -Unique
    writeDebugDate "unique Clusters: $scvmmClusterArray"
    return $scvmmClusterArray
}

function createClusterFilter($scvmmClusterArray)
{
    $nbClusters = getNameList $urlCluster
    writeDebugDate "fetching Cluster list from netbox: $Clusters"
    if ($null -eq $nbClusters)
    {
        return $scvmmClusterArray
    }
    $clusterList = Compare-Object -ReferenceObject $scvmmClusterArray.ClusterName -DifferenceObject $nbClusters
    $clusterList = $clusterList | Where-Object { $_.SideIndicator -eq $Global:isNotinNB }
    $clusterList = ($clusterList.InputObject)
    if ($null -eq $clusterList)
    {
        return $null
    }
    $ret = $scvmmClusterArray | Where-Object { $clusterList.contains($_.ClusterName) }
    writeDebugDate "difference list Cluster (netbox <=> Scvmm): $ret"
    return $ret
}

function getClusterTypeIDFromName([string]$nameStr)
{
    $clusterTypeList = getRestResults $urlClusterType

    if ($nameStr -eq $null)
    {
        Write-Warning "Cluster Type has not a ID"
        return
    }
    $id = (($clusterTypeList  | Where-Object{ $_.Name -eq $nameStr })).Id
    if ($null -eq $id)
    {
        Write-Warning "Cluster Type ($namestr) has no ID"
    }
    writeDebugDate "Lookup for ClusterType: $nameStr matched ID: $id"
    return $id
}

function createCluster
{
    writeDebugDate "About to create Clusters"
    $list = createClusterList
    $filter = createClusterFilter $list
    setCurrentStatus "create Clusters"
    $body = createBody $filter {
        param($cluster)
        return (@{
            "name" = ($cluster.ClusterName)
            "type" = (getClusterTypeIDFromName $cluster.VirtualizationPlatform)
        } | ConvertTo-Json) + ","
    }
    postBody $body $urlCluster
}

#endregion
#region patchVMs
function createPatchVMList
{
    writeDebugDate "About to createPatchVMList"
    $VMs = $getVMs
    writeDebugDate "fetching VirtualMachines from SCVMM: $VMs"
    $listVMs = @()
    $counter = 0
    setCurrentStatus "creating VM comparison List"
    foreach ($vm in $VMs)
    {
        $counter += 1
        $step = linear $counter 0 ($VMs.count) 0 100
        stepChildProgressBar $step
        $id = (getVMIdByName ($vm.ID))
        if ($id -eq "")
        {
            continue
        }

        $osID = (getOSIdByName ($vm.OperatingSystem.Name))
        $tenantID = (getTenantIdByName ($vm.Cloud.Name))
        $newVM = @{
            "name" = $vm.Name
            "id" = $id
            "vcpus" = "$( $vm.CPUCount ).00"
            "memory" = ($vm.Memory)
            "custom_fields" = @{
                "FQDN" = ($vm.ComputerName)
                "Generation" = ($vm.Generation)
                "Version" = ($vm.Version)
                "VMId" = ($vm.ID)
            }
        }
        if ($vm.ComputerName -eq "getaddrinfo failed: 0xfffffffd Temporary failure in name resolution")
        {
            write-warning "VM: $( $vm.Name ) has wrong FQDN configuration!"
            write-warning "https://social.technet.microsoft.com/Forums/en-US/8e964cbf-f34f-48d0-848b-ca75a5f5c3ea/windows-hyperv-hosting-linux-vms?forum=linuxintegrationservices"
        }
        if ($tenantID)
        {
            $newVM.add("tenant", $tenantID)
        }
        if ($osID)
        {
            $newVM.add("platform", $osID)
        }
        $listVMs += $newVM
    }
    popChildProgressBar
    writeDebugDate "build patching SCVMM VM comparison list: $listVMs"
    return $listVMs
}

function createOldVMList
{
    writeDebugDate "About to createOldVMList"
    $VMs = getRestResults $urlVM
    writeDebugDate "fetching VM List from Netbox (url: $urlVM): $VMs"
    $listVMs = @()
    $counter = 0
    setCurrentStatus "creating old VM List"
    foreach ($vm in $VMs)
    {
        $counter += 1
        $step = linear $counter 0 ($VMs.count) 0 100
        stepChildProgressBar $step
        if($vm.id -is [array])
        {
            foreach($id in $vm.id)
            {
                $newVM = @{
                    "name" = $vm.Name
                    "id" = $vm.id
                    "vcpus" = "" + ($vm.vcpus)
                    "memory" = ($vm.Memory)
                    "custom_fields" = @{
                        "FQDN" = ($vm.custom_fields.fqdn)
                        "Generation" = ($vm.custom_fields.Generation)
                        "Version" = ($vm.custom_fields.Version)
                        "VMId" = ($vm.custom_fields.VMId)
                    }
                }
                if ($vm.platform.id)
                {
                    $newVM.Add("platform", $vm.platform.id)
                }
                if ($vm.tenant.id)
                {
                    $newVM.Add("tenant", $vm.tenant.id)
                }
                $listVMs += $newVM
            }
            continue
        }

        $newVM = @{
            "name" = $vm.Name
            "id" = $vm.id
            "vcpus" = "" + ($vm.vcpus)
            "memory" = ($vm.Memory)
            "custom_fields" = @{
                "FQDN" = ($vm.custom_fields.fqdn)
                "Generation" = ($vm.custom_fields.Generation)
                "Version" = ($vm.custom_fields.Version)
                "VMId" = ($vm.custom_fields.VMId)
            }
        }
        if ($vm.platform.id)
        {
            $newVM.Add("platform", $vm.platform.id)
        }
        if ($vm.tenant.id)
        {
            $newVM.Add("tenant", $vm.tenant.id)
        }
        $listVMs += $newVM
    }
    popChildProgressBar
    writeDebugDate "build patching Netbox VM comparison list: $listVMs"
    return $listVMs
}

function compareLists($existingVMs, $newVMs)
{
    $toPatch = @()
    $counter = 0
    foreach ($vm in $newVMs)
    {

        $counter += 1

        $step = linear $counter 0 ($newVMs.count) 0 100

        stepChildProgressBar $step

        $oldVM = $existingVMs | Where-Object { $_.id -eq $vm.id }
        if (-not$oldVM)
        {
            continue
        }
        $comparison = Compare-DeepObject $vm $oldVM
        if (-not$comparison)
        {
            continue
        }
        $comparison.remove("last_updated") | Out-Null

        if ($comparison.count -eq 0)
        {
            continue
        }
        else
        {
            $toPatch += $vm
        }

    }
    popChildProgressBar
    writeDebugDate "build patching VM list: $toPatch"
    return $toPatch
}

function patchVMList($toPatch)
{
    writeDebugDate "About to patchVMList"
    setCurrentStatus "patch VMs"
    $body = createBody $toPatch {
        param($vm)
        return ($vm | ConvertTo-Json) + ","
    }
    patchBody $body $urlVM
}

function patchVM
{
    writeDebugDate("About to patch VMs")
    $oldVMList = createOldVMList
    $newVMList = createPatchVMList
    $toPatch = compareLists $oldVMList $newVMList
    patchVMList $toPatch
}
#endregion
#region DeepCompare
#https://github.com/kjelderg/Compare-DeepObject/
function Compare-DeepObject
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][AllowNull()][System.Object] $a,
        [Parameter(Mandatory = $true)][AllowNull()][System.Object] $b
    # TODO: max-depth
    )
    PROCESS {

        # if one side is null, return the other side.
        if ($a -eq $null -and $b -ne $null)
        {
            return @{ a = $null; b = $b }
        }
        if ($b -eq $null -and $a -ne $null)
        {
            return @{ b = $null; a = $a }
        }
        if ($a -eq $null -and $b -eq $null)
        {
            return
        }

        # compare data types
        if (Compare-Object $a.PSObject.TypeNames $b.PSObject.TypeNames)
        {
            return @{ _typeMismatch = "Data type mismatch"; a = $a.PSObject.TypeNames; b = $b.PSObject.TypeNames }
        }

        $differences = @{ } # accumulate differences here.
        if ($a -is [array])
        {
            # Recurse for each element of an array
            if ($a.count -ne $b.count)
            {
                $differences["_count"] = "Element count mismatch"
            }

            for($i = 0; $i -lt [math]::max($a.length, $b.length); $i++) {
                #recurse
                if ($d = Compare-DeepObject $a[$i] $b[$i])
                {
                    $differences["array element $i"] = $d
                }
            }
        }
        elseif($a -is [hashtable])
        {
            # Recurse for each element of a hashtable
            if ($a.count -ne $b.count)
            {
                $differences["_count"] = "Element count mismatch"
            }

            # walk both sets of keys with this cool get-unique magic.
            foreach ($k in @(@($a.keys) + @($b.keys) | get-unique))
            {
                #recurse
                if ($d = Compare-DeepObject $a[$k] $b[$k])
                {
                    $differences[$k] = $d
                }
            }
        }
        elseif($a -is [PSCustomObject])
        {
            # Recurse for each property of a PSCustomObject
            if ($a.PSObject.properties.name.count -ne $b.PSObject.properties.name.count)
            {
                $differences["_count"] = "Element count mismatch"
            }

            # walk both sets of keys^Wproperty names with this cool get-unique magic.
            foreach ($k in @(@($a.PSObject.properties.name) + @($b.PSObject.properties.name) | get-unique))
            {
                #recurse
                if ($d = Compare-DeepObject $a.$k $b.$k)
                {
                    $differences[$k] = $d
                }
            }
        }
        # If we are a complex object with differences, they should be accumulated and returned now.
        if ($differences.count)
        {
            return $differences
        }

        # We are not a complex object with differences.  actually compare what we have now.
        if (Compare-Object $a $b)
        {
            return @{ a = $a; b = $b }
        }

    } # End PROCESS
} # End function$
#endregion
#region updateDisk
function calculateDiskSize($vm)
{
    return [int][math]::Ceiling(((($vm.VirtualHardDisks.MaximumSize)  | Measure-Object -Sum).Sum) / 1000000000.0)
}
function compareDisks
{
    $newVMs = $getVMs
    writeDebugDate "fetching VM list from SCVMM: $newVMs"
    $oldVMs = getRestResults($urlVM)
    writeDebugDate "fetching VM list from Netbox (url: $urlVM):  $oldVMs"
    $differenceDisk = @()
    foreach ($vm in $newVMs)
    {
        if (-not$vm.VirtualHardDisks)
        {
            continue
        }
        $id = getVMIdByName ($vm.ID)
        $oldVM = $oldVMs | Where-Object { $_.id -eq $id }
        $newSize = calculateDiskSize($vm)
        $oldSize = $oldVM.disk
        if ($newSize -ne $oldSize)
        {
            $differenceDisk += @{
                "id" = $id
                "disk" = ($newSize)
            }
        }
    }
    writeDebugDate "build patching VM list: $differenceDisk"
    return $differenceDisk
}
function updateDisk
{
    writeDebugDate("About to update Disks")
    $VMs = compareDisks
    setCurrentStatus "update disks"
    $body = createBody $VMs {
        param($vm)
        return ($vm| ConvertTo-Json) + ","
    }
    patchBody $body $urlVM
}
#endregion
#region VM
function createVMList
{
    $VMs = $getVMs
    $vmList = @()
    writeDebugDate "fetching VM list from SCVMM: $VMs"

    foreach ($vm in $VMs)
    {
        $vmList += $vm
    }

    writeDebugDate "unique VMs: $vmList"
    return $vmList
}

function createVMFilter($vmList, $sideIndicator)
{
    if ($null -eq $vmList)
    {
        return $null
    }

    $nbVM = getRestResults $urlVM
    writeDebugDate "fetching VM list from Netbox (url: $urlVM):  $nbVM"
    if ($null -eq $nbVM)
    {
        return $vmList
    }

    $nbList = Compare-Object -ReferenceObject ($vmList.Id) -DifferenceObject ($nbVM.custom_fields.vmid)
    $nbList = $nbList | Where-Object { $_.SideIndicator -eq $sideIndicator }
    $nbList = ($nbList.InputObject)

    if ($sideIndicator -eq $Global:isOnlyinNB)
    {
        return $nbList
    }

    if ($null -eq $nbList)
    {
        return $null
    }

    if(@($nbList| Measure-Object).Count -eq 1)
    {
        $ret = $vmList | Where-Object {$nbList -eq $_.ID }
        return $ret
    }

    $ret = $vmList | Where-Object { $nbList.contains($_.Id) } #Nimmt alle objekte aus "vmList" die den gleichen namen haben wie die, die in "nbList" sind
    writeDebugDate "difference list VMs (netbox <=> Scvmm): $nbList"

    return $ret
}

function getClusterID([string]$nameStr, $clusterList)
{
    if ($nameStr -eq $null -or $nameStr -eq "")
    {
        Write-Warning "No Name provided"
        return $null
    }
    $id = ($clusterList | Where-Object{ $_.Name -eq $nameStr }).Id
    if ($null -eq $id)
    {
        Write-Warning "Cluster ($namestr) has no ID"
    }
    return $id
}

function createVMBody($vmList)
{
    $ret = [PSCustomObject]@{
        "body" = ""
        "clusterless" = @()
    }

    $body = "["
    $existingClusterList = getRestResults $urlCluster
    setCurrentStatus "create VMs"
    $counter = 0
    foreach ($vm in $vmList)
    {

        $name = $vm.Name
        $id = $vm.VMHost.HostCluster.ClusterName
        if ($null -eq $id)
        {
            $ret.clusterless += $vm
            continue
        }
        $counter += 1
        $step = linear $counter 0 ($vmList.count) 0 100
        stepChildProgressBar $step
        $clusterID = getClusterID $id $existingClusterList
        $body += (@{
            "name" = $name
            "cluster" = $clusterID
            "custom_fields" = @{
                "VMId" = ($vm.ID)
            }

        } | ConvertTo-Json) + ","
    }
    popChildProgressBar
    if ($body -eq "[")
    {
        $ret.body = ""
        return $ret
    }
    $body = $body.subString(0, $body.length - 1) + "]"
    $ret.body = $body
    writeDebugDate "Created list of SingleHost-VMs: $( $ret.clusterless )"
    return $ret
}

function createSingleCluster($potentialSingleCluster)
{
    $body = "["
    $tracking = @()
    $existingClusterNames = getNameList $urlCluster
    foreach ($clusterName in $existingClusterNames)
    {
        $tracking += $clusterName
    }

    $type = getHyperVTypeID
    $counter = 0
    setCurrentStatus "create SingleClusters"
    foreach ($vm in $potentialSingleCluster)
    {
        $indexOfSingleClu = $vm.HostName.IndexOf(".")
        $stringOFSingleClu = $vm.HostName.Substring(0, $indexOfSingleClu)
        if ( $tracking.Contains($stringOFSingleClu))
        {
            continue
        }
        $counter += 1
        $step = linear $counter 0 ($potentialSingleCluster.count) 0 100
        stepChildProgressBar $step
        $tracking += $stringOFSingleClu
        $body += (@{
            "name" = $stringOFSingleClu
            "type" = $type
        } | ConvertTo-Json) + ","
    }
    popChildProgressBar
    if ($body -eq "[")
    {
        return ""
    }
    $body = $body.subString(0, $body.length - 1) + "]"
    return $body
}

function createSingleVM($potentialSingleCluster)
{
    $body = "["
    $tracking = @()
    $existingVMNames = getNameList $urlVM
    writeDebugDate "fetching VM list from Netbox (url: $urlVM): $existingVMNames"
    $existingClusterList = getRestResults $urlCluster
    writeDebugDate "fetching Cluster list from Netbox: $existingClusterList"
    foreach ($vmName in $existingVMNames)
    {
        $tracking += $vmName
    }
    $counter = 0
    setCurrentStatus "create single VMs"
    foreach ($vm in $potentialSingleCluster)
    {
        $name = $vm.Name
        if ( $tracking.Contains($name))
        {
            continue
        }
        $counter += 1
        $step = linear $counter 0 ($potentialSingleCluster.count) 0 100
        stepChildProgressBar $step
        $tracking += $name
        $indexOfSingleClu = $vm.HostName.IndexOf(".")
        $id = $vm.HostName.Substring(0, $indexOfSingleClu)
        $clusterID = getClusterID $id $existingClusterList
        $body += (@{
            "name" = $name
            "cluster" = $clusterID
            "custom_fields" = @{
                "VMId" = ($vm.ID)
            }
        } | ConvertTo-Json) + ","
    }
    popChildProgressBar
    if ($body -eq "[")
    {
        return ""
    }
    $body = $body.subString(0, $body.length - 1) + "]"
    return $body
}

function fillSingleVMTracking()
{
    $tracking = @()

    $existingVMNames = getNameList $urlVM
    foreach ($vmName in $existingVMNames)
    {
        $tracking += $vmName
    }
    return $tracking
}

function createVMs
{
    writeDebugDate("About to create VMs")
    $list = createVMList
    $filtered = createVMFilter $list $Global:isNotinNB
    $combine = createVMBody $filtered
    $singleClusters = createSingleCluster $combine.clusterless
    writeDebugDate("posting single Clusters")
    postBody $singleClusters $urlCluster
    writeDebugDate("posting single VMs")
    postBody (createSingleVM $combine.clusterless) $urlVM
    writeDebugDate("posting VMs")
    postBody $combine.body $urlVM
}

function deleteVMs
{
    writeDebugDate("About to delete VMs")
    $list = createVMList
    $filter = createVMFilter $list $Global:isOnlyinNB
    setCurrentStatus "delete VMs"
    $body = createBody $filter { param($vm) return (@{ "id" = getVMIdByName $vm } | ConvertTo-Json) + "," }
    deleteBody $body $urlVM
}
#endregion
#region interface
function seedTrackingSet($uniqueTracking)
{
    foreach ($element in $existingInterfaces)
    {
        $uniqueTracking.Add($element.virtual_machine.Name + $element.Name) | out-null
    }
}

function createInterfaceBodyElement([string]$vmName, [string]$interfaceName, $uniqueTracking)
{
    if ($interfaceName -eq "" -or $vmName -eq "")
    {
        writeDebugDate "break interfaceName($interfaceName) or vmName($vmName) is empty"
        return
    }
    $combo = $vmName + $interfaceName
    if ( $uniqueTracking.Contains($combo))
    {
        writeDebugDate "$combo exists"
        return
    }
    $uniqueTracking.Add($combo) | out-null
    $newInterface = @{
        "virtual_machine" = getVMIdNetbox($vmName)
        "name" = $interfaceName
    }
    return ($newInterface | ConvertTo-Json) + ","
}

function isNetworkNullOrEmpty($nic)
{
    if ($null -eq $nic)
    {
        writeDebugDate "$nic is null"
        return $true
    }
    if ($null -eq $nic.VMNetwork)
    {
        writeDebugDate "$nic doesnt have VMNetwork"
        return $true
    }
    if ($null -eq $nic.VMNetwork.Name -or "" -eq ($nic.VMNetwork.Name))
    {
        writeDebugDate "$nic is missing a Name for VMNetwork"
        return $true
    }
    return $false
}

function processNic($nic, $vm, $body, $uniqueTracking)
{
    if (isNetworkNullOrEmpty $nic)
    {
        return $body
    }
    $vmNameResult = $vm.VirtualNetworkAdapters.VMNetwork.Name
    if ($vmNameResult -is [array])
    {
        foreach($vmName in $vmNameResult)
        {
            if(-not $vmName -is [string])
            {
                continue
            }

            $body += (createInterfaceBodyElement $name $vmName $uniqueTracking)

        }
    }
    else
    {
        $body +=    (createInterfaceBodyElement $name $vmNameResult $uniqueTracking)

    }
    return $body
}

function createInterfaceBody
{
    $VMs = $getVMs
    writeDebugDate "fetching VMs list from SCVMM: $VMs"
    $uniqueTracking = New-Object System.Collections.Generic.HashSet[string]
    seedTrackingSet $uniqueTracking
    $body = "["
    foreach ($vm in $VMs)
    {
        $name = $vm.Name
        $NICs = $vm.VirtualNetworkAdapters
        foreach ($nic in $NICs)
        {
            $body = processNic $nic $vm $body $uniqueTracking
        }

    }
    if($body -eq "[")
    {
        return ""
    }
    $body = $body.subString(0, $body.length - 1) + "]"
    return $body
}

function createInterface
{
    writeDebugDate("About to create Interfaces")
    postBody (createInterfaceBody) $urlInterface
}

function createInterfaceList
{
    $interfaceSCVMMArray = @()
    $VMs = $getVMs
    writeDebugDate "fetching VM list from SCVMM: $VMs"
    foreach ($vm in $VMs)
    {
        $name = $vm.Name
        $NICs = $vm.VirtualNetworkAdapters
        foreach ($nic in $NICs)
        {
            if (isNetworkNullOrEmpty $nic)
            {
                continue
            }
            $vmNameResult = $nic.VMNetwork.Name
            $comboScvmmName = $name + $vmNameResult
            $interfaceSCVMMArray += $comboScvmmName
        }
    }
    writeDebugDate "unique interfaceSCVMMArray: $interfaceSCVMMArray"
    return $interfaceSCVMMArray
}

function interfaceFilter($interfaceSCVMMArray)
{
    $nbInterface = $existingInterfaces
    writeDebugDate "fetching Interface list from Netbox: $nbInterface"
    if ($null -eq $nbInterface)
    {
        return $interfaceSCVMMArray
    }
    $nbInterface = $nbInterface | Where-Object{ $null -ne $_.virtual_machine -and $null -ne $_.virtual_machine.name -and $_.virtual_machine.name -ne "" -and $null -ne $_.Name -and $_.Name -ne "" }
    $comboName = @()
    foreach ($itf in $nbInterface)
    {
        $comboName += ($itf.virtual_machine.name + $itf.Name)
    }
    $nbList = Compare-Object -ReferenceObject $comboName  -DifferenceObject $interfaceSCVMMArray
    $nbList = $nbList | Where-Object { $_.SideIndicator -eq $Global:isNotinNB }
    writeDebugDate "difference list Interface (netbox <=> Scvmm): $nbList"
    return $nbList.InputObject
}

function deleteInterface
{
    writeDebugDate("About to delete Interface")
    $list = createInterfaceList
    $filter = interfaceFilter $list
    setCurrentStatus "delete interfaces"
    $body = createBody $filter { param($itf) (@{ "id" = getInterfaceIdByComboString $itf } | ConvertTo-Json) + "," }
    deleteBody $body $urlInterface
}
#endregion
#region createIP
function createOldIps{
    $nbIPs = getRestResults $urlIPAM
    $listIPs = @()
    foreach ($ips in $nbIPs)
    {
        $listIPs += $ips
    }
    return $listIPs
}

function deleteIPs
{
    $VMs = $getVMs
    $patchlist = @()
    $deleteIPs = @()
    $oldIPs = createOldIps

    foreach ($vm in $VMs.VirtualNetworkAdapters)
    {
        $ipAdresses = getCidrIPs $vm.IPv4Subnets.PrefixLength $vm.IPv4Addresses
        foreach( $ip in $ipAdresses)
        {
            $patchlist += $ip
        }
        $ipAdresses = getCidrIPs $vm.IPv6Subnets.PrefixLength $vm.IPv6Addresses
        foreach( $ip in $ipAdresses)
        {
            $patchlist += $ip
        }
    }
    foreach($ip in $oldIPs)
    {

        if(-not ($patchlist | Where-Object {$_ -eq $ip.Address}))
        {
            $deleteIPs += $ip.id
        }
    }
    $body = createBody $deleteIPs { param($id) (@{ "id" = $id } | ConvertTo-Json) + "," }
    deleteBody $body $urlIPAM
}

function getCidrIPs($prefix, $results)
{
    if (-not$prefix.length -eq $results.length)
    {
        return  @()
    }
    $ret = @()

    for($element = 0; $element -lt $prefix.length; $element++)
    {
        $ret += "" + $results[$element] + "/" + $prefix[$element]
    }
    return $ret
}

function getIpJsonChecked([string]$adresses, [string]$interfaceID)
{
    if ($nbIPAdresses | Where-Object{ $_.address -eq $adresses })
    {
        return ""
    }
    return(@{
        "address" = $adresses
        "assigned_object_type" = "virtualization.vminterface"
        "assigned_object_id" = getInterfaceIdByComboString $interfaceID
    }|ConvertTo-Json) + ","
}

function createIPBodyPart($nic, $prefix, $result)
{
    $vmName = $nic.Name
    $interfaceName = $nicName.nic.VMNetwork.Name
    $comboName = $vmName + $interfaceName
    $cidrList = getCidrIPs $prefix $result
    $body = ""
    if ($cidrList.length -eq 0)
    {
        Write-Warning "$vmName couldnt match IP-Adress and Subnet"
    }
    foreach ($ip in $cidrList)
    {
        $body += getIpJsonChecked $ip $comboName
    }
    return $body
}

function createIP
{
    writeDebugDate("About to create IPs")
    $VMs = $getVMs
    writeDebugDate "fetching VM list from Netbox (url: $urlVM): $VMs"
    $patchlist = @()

    foreach ($vm in $VMs)
    {
        $NICs = $vm.VirtualNetworkAdapters

        foreach ($nic in $NICs)
        {
            if (isNetworkNullOrEmpty $nic)
            {
                continue
            }
            $nicName = [PSCustomObject]@{
                "nic" = $nic
                "name" = ($vm.Name)
            }
            $patchlist += $nicName
        }
    }

    setCurrentStatus "create IP4s"
    $IPBody = createBody $patchlist {
        param($nicName)

        $ip4Prefix = $nicName.nic.IPv4Subnets.PrefixLength
        $ip4Results = $nicName.nic.IPv4Addresses
        $part += createIPBodyPart $nicName $ip4Prefix $ip4Results

        return $part
    }
    if ($IPBody -ne "")
    {
        $IPBody = $IPBody.substring(0, $IPBody.length - 1) + ","
    }
    setCurrentStatus "create IP6s"
    $IPv6Body = createBody $patchlist {
        param($nicName)

        $ip6Prefix = $nicName.nic.IPv6Subnets.PrefixLength
        $ip6Results = $nicName.nic.IPv6Addresses
        $part += createIPBodyPart $nicName $ip6Prefix $ip6Results

        return $part
    }

    if ($IPv6Body -ne "")
    {
        $IPv6Body = $IPv6Body.substring(1)
    }

    $IPBody += $IPv6Body

    if (($IPBody[0] -ne "[") -and ($IPBody -ne ""))
    {
        $IPBody = "[" + $IPBody
    }

    if ($IPBody[-1] -ne "]" -and $IPBody -ne "")
    {
        $IPBody = $IPBody.Substring(0, $IPBody.Length-1) + "]"
    }
    
    postBody $IPBody $urlIPAM
}
#endregion
#region main program
function run()
{
    stepMainProgressBar 0

    createTenant
    stepMainProgressBar 10
    $existingTenants = getRestResults $urlTenant

    createOS
    stepMainProgressBar 20
    $osLists = getRestResults $urlOS

    createCluster
    stepMainProgressBar 30

    $vmNBList = getRestResults $urlVM
    deleteVMs
    stepMainProgressBar 40

    $vmNBList = getRestResults $urlVM
    createVMs
    stepMainProgressBar 50
    $vmNBList = getRestResults $urlVM

    patchVM

    stepMainProgressBar 60
    $vmNBList = getRestResults $urlVM

    updateDisk
    stepMainProgressBar 70

    $existingInterfaces = getRestResults $urlInterface
    createInterface
    stepMainProgressBar 80
    $existingInterfaces = getRestResults $urlInterface

    deleteInterface
    stepMainProgressBar 90
    $existingInterfaces = getRestResults $urlInterface

    deleteIPs
    createIP
    stepMainProgressBar 100

}

run
writeDebugDate "Execution complete!"
#endregion
