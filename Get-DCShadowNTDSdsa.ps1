# comments to yossis@protonmail.com (v1.0.2) <added option to query other domains>
param (
    [string]$DomainDNSname
)

if ($DomainDNSname -eq "") {$DomainDNSname = $env:USERDNSDOMAIN}

$recycleBinEnabled = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"} -Server $DomainDNSname | Select-Object -ExpandProperty EnabledScopes

if ($recycleBinEnabled) {
    Write-Host "Active Directory Recycle Bin is enabled in the domain. continue to check for exploitation..."
} else {
    Write-Host "Active Directory Recycle Bin is not enabled in the domain. Quiting.";
    exit
}

$root = Get-ADRootDSE -Server $DomainDNSname;
$deletedFromCN = Get-ADObject -ResultPageSize 100000 -searchbase $root.configurationNamingContext -Server $DomainDNSname -filter {(IsDeleted -eq $true) -and (ObjectClass -ne "msExchActiveSyncDevice")} -IncludeDeletedObjects -properties *;
$nTDSDSAResult = $deletedFromCN | where-object {$_.ObjectClass -eq 'nTDSDSA'}

if ($nTDSDSAResult)
	{
        [int]$nTDSDSAEntriesCount = ($nTDSDSAResult | Measure-Object).count
        [int]$i = 1
		write-warning "Found $nTDSDSAEntriesCount Domain Controller(s) demotion <Potential Execution of DCShadow>:"
		
        $nTDSDSAResult | ForEach-Object {
            $nTDSDSA = $_;
            Write-Output "Entry $i of $nTDSDSAEntriesCount"
            if (($($nTDSDSA.whenCreated) -  $($nTDSDSA.whenChanged)).Hours -lt 1)
                {
                    Write-Host "HIGHLY SUSPICIOUS ENTRY -- Check Details Carefully!" -ForegroundColor Yellow
                }

            Write-Output "Full object distinguished name: $($nTDSDSA.DistinguishedName)"
        
            [int]$IndexofHostName = $($nTDSDSA.DistinguishedName.Substring(3)).IndexOf("CN=") + 3
            $DeletedObjectHostName = $nTDSDSA.DistinguishedName.Substring($IndexofHostName).ToString().Split("\")[0].Replace("CN=","")
        
            Write-Output "Deleted computer name: $DeletedObjectHostName"
            Write-Output "WhenCreated: $($nTDSDSA.whenCreated)"
            Write-Output "WhenChanged: $($nTDSDSA.whenChanged)"
            Write-Output "Domain Naming Context: $($nTDSDSA.'msDS-HasDomainNCs')"

            $nTDSDSACanonicalNameElements = ($nTDSDSA.CanonicalName).ToString().Split("/")

            Write-Output "Domain FQDN: $($nTDSDSACanonicalNameElements[0])`n"
            $i++
	    }
	else
	{
		"No suspicious entries found."
	}
    }
else
    {
        Write-Host "No relevant entries found (no direct evidence of exploitation)." -ForegroundColor Cyan
    }