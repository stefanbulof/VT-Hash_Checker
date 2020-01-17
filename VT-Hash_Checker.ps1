$Table = @()
$APIKey = '<APIKEYHERE>'

foreach ($Hash in Get-Content 'HashList.txt')
{
Write-Host $Hash
$Request = @{ resource = $Hash; apikey = $APIKey }
$VTRequest = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $Request
$VTRequest | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | where-object {$_ -eq 'total'} |ForEach-Object { $TableRow = [PSCustomObject]@{  'Hash' = $Hash; 'Detections' = $VTRequest.positives ; 'Report' = $VTRequest.permalink };
$Table += $TableRow 
}
Start-Sleep -s 20
}
$Table |ConvertTo-Csv | Out-File -FilePath hash_detection.csv 
