Write-Host "Checking Elasticsearch cluster health..." -ForegroundColor Cyan
try {
    $es = Invoke-RestMethod -Uri "http://localhost:9200/_cluster/health" -Method Get
    Write-Host "Elasticsearch Status: $($es.status)" -ForegroundColor Green
    Write-Host "Number of Nodes: $($es.number_of_nodes)" -ForegroundColor Green
} catch {
    Write-Host "Elasticsearch is unreachable on port 9200!" -ForegroundColor Red
}

Write-Host "`nChecking Kibana status..." -ForegroundColor Cyan
try {
    $kibana = Invoke-WebRequest -Uri "http://localhost:5601/status" -Method Get -UseBasicParsing
    if ($kibana.StatusCode -eq 200) {
        Write-Host "Kibana is running on port 5601!" -ForegroundColor Green
    }
} catch {
    Write-Host "Kibana is unreachable on port 5601!" -ForegroundColor Red
}
