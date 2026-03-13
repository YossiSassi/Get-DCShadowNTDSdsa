# comments to yossis@protonmail.com (v1.0.5) 
# v1.0.6 - Fixed a minor field output bug (first deleted entry came out empty)
# v1.0.5 - Added check for Forest DN rather than current domain + check for relevant deleted objects before moving on + ignore lack of tombstonelifetime value + some minor error handling
# v1.0.4 - minor addition to reflect the number of Days Since Recycle Bin was Enabled
# v1.0.3 - added checks for tombstoneLifetime & AD-RecycleBin enabled date + solved minor error in 'else' loop (not affecting the results but still)
# v1.0.2 - added option to query other domains
param (
    # If other trusted domain specified as a parameter - use it. Otherwise, use currently logged on *FOREST*
    [string]$DomainDNSname = (Get-ADRootDSE).rootDomainNamingContext.Replace("DC=","").Replace(",",".")
)

$recycleBinEnabled = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"} -Server $DomainDNSname -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnabledScopes
if (!$?)
{
    Write-Host "[!] The domain $DomainDNSname could not be contacted.`n$($Error[0].exception.message)`nQuiting." -ForegroundColor Yellow;
    break
}

if ($recycleBinEnabled) {
    Write-Host "[x] Active Directory Recycle Bin is enabled in the domain.`nContinuing to check for DC demotion / DC-Shadow exploitation..." -ForegroundColor Green
} else {
    Write-Host "[!] Active Directory Recycle Bin is not enabled in the domain. Quiting." -ForegroundColor Yellow;
    break
}

$root = Get-ADRootDSE -Server $DomainDNSname;
$deletedFromCN = Get-ADObject -ResultPageSize 100000 -searchbase $root.configurationNamingContext -Server $DomainDNSname -filter {(IsDeleted -eq $true) -and (ObjectClass -ne "msExchActiveSyncDevice")} -IncludeDeletedObjects -properties *;
$nTDSDSAResult = $deletedFromCN | where-object {$_.ObjectClass -eq 'nTDSDSA'}

# Ensure we got potentially relevant results from Deleted objects
if (!$nTDSDSAResult) {
    Write-Host "[!] No relevant entries found in the Recycle Bin. Quiting." -ForegroundColor Yellow;
}

# Check to see when AD recycle bin was enabled, and what is the tombstoneLifetime
# Get tombstoneLifetime value in days
#$DomainDN = (Get-ADDomain -Server $DomainDNSname).DistinguishedName;
$tombstoneLifetime = $((Get-ADObject -SearchBase "CN=Directory Service,CN=Windows NT,CN=Services,$($root.configurationNamingContext)" -Filter * -Property tombstoneLifetime).tombstoneLifetime | Out-String).Trim();
if ($tombstoneLifetime) {
    Write-Host "[x] Accessing $DomainDNSname <tombstoneLifetime = $tombstoneLifetime days>"
}

# Get the date when AD Recycle Bin was enabled
$configNCDN = (Get-ADRootDSE -Server $DomainDNSname).configurationNamingContext;
$directoryServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNCDN";

# Get the Directory Service object
$directoryService = Get-ADObject -Identity $directoryServiceDN -Server $DomainDNSname -Properties whenChanged;
$recycleBinEnabledDate = $directoryService.whenChanged;
$DaysSinceRecycleBinEnabled = $($(get-date) - $recycleBinEnabledDate).Days;
Write-Host "[x] Recycle Bin was enabled on $recycleBinEnabledDate ($DaysSinceRecycleBinEnabled days ago)";

if ($tombstoneLifetime) {
    $daysDiff = ($(Get-Date) - $recycleBinEnabledDate).Days;
    if ($daysDiff -lt $tombstoneLifetime) {$DaysBack = $tombstoneLifetime - $daysDiff} else {$DaysBack = $tombstoneLifetime}
    Write-Host "[x] Results reflecting the last $daysback days (according to tombstoneLifetime & recycleBin Enabled date)`n" -ForegroundColor Cyan
}

if ($nTDSDSAResult)
	{        
        [int]$nTDSDSAEntriesCount = ($nTDSDSAResult | Measure-Object).count
        [int]$i = 1
		write-warning "Found $nTDSDSAEntriesCount Domain Controller(s) demotion <Potential Execution of DCShadow>:"
		
        $nTDSDSAResult | ForEach-Object {
            $nTDSDSA = $_;
            Write-Output "Entry $i of $nTDSDSAEntriesCount";
            
            [int]$IndexofHostName = $($nTDSDSA.DistinguishedName.Substring(3)).IndexOf("CN=") + 3;
            $DeletedObjectHostName = $nTDSDSA.DistinguishedName.Substring($IndexofHostName).ToString().Split("\")[0].Replace("CN=","");
        
            if (($($nTDSDSA.whenCreated) -  $($nTDSDSA.whenChanged)).Hours -lt 1)
                {
                    Write-Host "[!] SUSPICIOUS ENTRY (" -ForegroundColor Yellow -NoNewline; Write-Host $DeletedObjectHostName -NoNewline -ForegroundColor Cyan; Write-Host ") -- Check Details Carefully!" -ForegroundColor Yellow
                }

            Write-Output "Full object distinguished name: $($nTDSDSA.DistinguishedName)";
            Write-Output "Deleted computer name: $DeletedObjectHostName";
            Write-Output "WhenCreated: $($nTDSDSA.whenCreated)";
            Write-Output "WhenChanged: $($nTDSDSA.whenChanged)";
            Write-Output "Domain Naming Context: $($nTDSDSA.'msDS-HasDomainNCs')";

            $nTDSDSACanonicalNameElements = ($nTDSDSA.CanonicalName).ToString().Split("/");

            Write-Output "Domain FQDN: $($nTDSDSACanonicalNameElements[0])`n";
            $i++
	    }
    }
else
    {
        Write-Host "[x] No relevant entries found (no direct evidence of exploitation)." -ForegroundColor Green;
    }