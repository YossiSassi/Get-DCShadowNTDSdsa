# comments to yossis@protonmail.com

$root = Get-ADRootDSE
$deletedFromCN = Get-ADObject -ResultPageSize 100000 -searchbase $root.configurationNamingContext  -filter {(IsDeleted -eq $true) -and (ObjectClass -ne "msExchActiveSyncDevice")} -IncludeDeletedObjects -properties *
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