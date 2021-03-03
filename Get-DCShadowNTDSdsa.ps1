$root = Get-ADRootDSE
$deletedFromCN = Get-ADObject -ResultPageSize 100000 -searchbase $root.configurationNamingContext  -filter {(IsDeleted -eq $true) -and (ObjectClass -ne "msExchActiveSyncDevice")} -IncludeDeletedObjects -properties *
$nTDSDSA = $deletedFromCN | where-object {$_.ObjectClass -eq 'nTDSDSA'}
if ($nTDSDSA)
	{
		write-warning "Found $($($nTDSDSA | Measure-Object).count) Domain Controller(s) demotion or use of DCShadow:"
		$nTDSDSA.DistinguishedName
	}
