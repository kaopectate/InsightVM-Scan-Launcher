#Put your API Credentials here
$username = "user"
$password = "password"

#address to your Insight VM Instance
$base_url = "" 

#max number of concurrent scans
[Int16]$max_concurent_scans = 3

#sites to exclude 
$excluded_sites = @(
    'Rapid7 Insight Agents',
    'Sonar DNS Scan'
)
Function Get-InsightVMSites {
    $pair = "{0}:{1}" -f ($username, $password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $token = [System.Convert]::ToBase64String($bytes)
    $headers = @{
        Authorization = "Basic {0}" -f ($token)
    }
    $uri = "https://$base_url/api/3/sites?size=100"
    $get = Invoke-RestMethod -Uri $uri -Headers $headers 
    $get.resources | ForEach-Object{
        [pscustomobject]@{
            Name = $_.name
            riskScore = $_.riskScore
            scanEngine = $_.scanEngine
            scanTemplate = $_.scanTemplate
            type = $_.type
            vulnerabilities = $_.vulnerabilities
            assets = $_.assets         
            description = $_.description
            id = $_.id
            importance = $_.importance
            lastScanTime = $_.LastScanTime
            links = $_.links
        }
    }
}
Function Get-InsightvmScans {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $id
    )
    $pair = "{0}:{1}" -f ($username, $password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $token = [System.Convert]::ToBase64String($bytes)
    $headers = @{
        Authorization = "Basic {0}" -f ($token)
    }

    $uri = "https://$base_url/api/3/sites/$id/scans?active=true"
    $get = (Invoke-RestMethod -Uri $uri -Headers $headers).resources
    $get
}
Function Invoke-InsightVMSiteScan {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $id
    )
    $pair = "{0}:{1}" -f ($username, $password)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $token = [System.Convert]::ToBase64String($bytes)
    $headers = @{
        Authorization = "Basic {0}" -f ($token)
        'Content-Type' = 'application/json'
    }
    $body = @{
        name = "scan"
    }
    $body = $body | ConvertTo-Json
    $uri = "https://$base_url/api/3/sites/$id/scans"
    $post = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $body
    $post
}
$sites = Get-InsightVMSites | Where-Object -Property name -notin $excluded_sites
$results = $sites | % {
    $scans = Get-InsightvmScans -id $_.id
    [pscustomobject]@{
        Name = $_.Name
        id = $_.id
        lastScanTime = $_.lastScanTime
        status = $scans.status
    }
}
$scans_to_start = $max_concurent_scans - ($results | Where-Object -Property Status -EQ 'Running').count
$next_scans = $results | Sort-Object -Property lastScanTime | Where-Object -Property Status -NE 'Running' | Select-Object -First $scans_to_start
$next_scans | ForEach-Object{
    Invoke-InsightVMSiteScan -id $_.id
}
