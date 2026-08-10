#requires -Version 5.1
<#
.SYNOPSIS
  Provision the public honeypot dashboard infrastructure (idempotent).

.DESCRIPTION
  Creates, in ap-southeast-3:
    - S3 bucket (private, Block Public Access) for the static site + JSON
    - IAM role + inline policy for the exporter Lambda
    - Lambda function cowrie-dashboard-exporter (python3.12)
    - SQS DLQ cowrie-exporter-dlq
    - EventBridge hourly schedule -> exporter Lambda (with DLQ)
    - CloudFront distribution with OAC fronting the bucket
    - Bucket policy granting the distribution read via OAC
  Uploads site/ static files. Safe to re-run; existing resources are reused.

.PARAMETER BucketName
  Globally-unique S3 bucket name. If omitted, one is generated.

.EXAMPLE
  .\infra.ps1 -BucketName cowrie-public-dashboard-abc123
#>
param(
    [string]$BucketName = "",
    [string]$Region = "ap-southeast-3"
)

$ErrorActionPreference = "Continue"   # AWS CLI writes to stderr on success; we gate on $LASTEXITCODE
$root = Split-Path -Parent $PSScriptRoot          # repo root (code/ -> repo)
$siteDir = Join-Path $root "site"
$exporterZip = Join-Path $env:TEMP "exporter.zip"

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

# --- 0. Auth + account ------------------------------------------------------
Info "Checking AWS identity..."
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
$AccountId = $identity.Account
Ok "Account: $AccountId  Region: $Region"

# --- 1. S3 bucket -----------------------------------------------------------
if (-not $BucketName) {
    $suffix = -join ((97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object {[char]$_})
    $BucketName = "cowrie-public-dashboard-$suffix"
}
Info "Ensuring S3 bucket: $BucketName"
$exists = aws s3api head-bucket --bucket $BucketName 2>$null; if ($LASTEXITCODE -eq 0) {
    Warn "Bucket already exists, reusing."
} else {
    aws s3api create-bucket --bucket $BucketName --region $Region `
        --create-bucket-configuration LocationConstraint=$Region | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "create-bucket failed for $BucketName" }
    Ok "Bucket created."
}
aws s3api put-public-access-block --bucket $BucketName --public-access-block-configuration `
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" | Out-Null
Ok "Block Public Access enabled."

# --- 2. IAM role for exporter Lambda ---------------------------------------
$RoleName = "cowrie-exporter-role"
$trust = @{
    Version = "2012-10-17"
    Statement = @(@{
        Effect = "Allow"
        Principal = @{ Service = "lambda.amazonaws.com" }
        Action = "sts:AssumeRole"
    })
} | ConvertTo-Json -Depth 6 -Compress

Info "Ensuring IAM role: $RoleName"
$roleArn = $null
$existing = aws iam get-role --role-name $RoleName 2>$null | ConvertFrom-Json
if ($existing) { $roleArn = $existing.Role.Arn; Warn "Role exists, reusing." }
else {
    $trustFile = Join-Path $env:TEMP "trust.json"; Set-Content -Path $trustFile -Value $trust
    $r = aws iam create-role --role-name $RoleName --assume-role-policy-document "file://$trustFile" | ConvertFrom-Json
    $roleArn = $r.Role.Arn
    aws iam attach-role-policy --role-name $RoleName `
        --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" | Out-Null
    Ok "Role created: $roleArn"
}

# Inline policy: Logs Insights on the log group + S3 RW on the bucket JSON
$policy = @{
    Version = "2012-10-17"
    Statement = @(
        @{ Effect = "Allow"; Action = @("logs:StartQuery","logs:GetQueryResults","logs:DescribeLogGroups");
           Resource = "arn:aws:logs:${Region}:${AccountId}:log-group:/honeypot/cowrie:*" },
        @{ Effect = "Allow"; Action = @("logs:StartQuery"); Resource = "arn:aws:logs:${Region}:${AccountId}:log-group:/honeypot/cowrie" },
        @{ Effect = "Allow"; Action = @("s3:PutObject","s3:GetObject");
           Resource = "arn:aws:s3:::$BucketName/*.json" }
    )
} | ConvertTo-Json -Depth 8 -Compress
$polFile = Join-Path $env:TEMP "exporter-policy.json"; Set-Content -Path $polFile -Value $policy
aws iam put-role-policy --role-name $RoleName --policy-name "cowrie-exporter-policy" --policy-document "file://$polFile" | Out-Null
Ok "Inline policy attached."
Start-Sleep -Seconds 8   # IAM propagation

# --- 3. Exporter Lambda -----------------------------------------------------
$FunctionName = "cowrie-dashboard-exporter"
Info "Packaging exporter..."
$exporterSrc = Join-Path $root "code\exporter.py"
if (Test-Path $exporterZip) { Remove-Item $exporterZip -Force }
Compress-Archive -Path $exporterSrc -DestinationPath $exporterZip -Force
Ok "Zipped exporter.py"

$env = "Variables={COWRIE_LOG_GROUP=/honeypot/cowrie,DASHBOARD_BUCKET=$BucketName,GEOIP_ENABLED=true}"
$fn = aws lambda get-function --function-name $FunctionName --region $Region 2>$null | ConvertFrom-Json
if ($fn) {
    Warn "Lambda exists, updating code + config."
    aws lambda update-function-code --function-name $FunctionName --zip-file "fileb://$exporterZip" --region $Region | Out-Null
    Start-Sleep -Seconds 3
    aws lambda update-function-configuration --function-name $FunctionName --region $Region `
        --timeout 60 --memory-size 256 --environment $env | Out-Null
} else {
    Info "Creating Lambda: $FunctionName"
    aws lambda create-function --function-name $FunctionName --region $Region `
        --runtime python3.12 --handler exporter.lambda_handler --role $roleArn `
        --zip-file "fileb://$exporterZip" --timeout 60 --memory-size 256 --environment $env | Out-Null
    Ok "Lambda created."
}
$fn = aws lambda get-function --function-name $FunctionName --region $Region | ConvertFrom-Json
$LambdaArn = $fn.Configuration.FunctionArn
Ok "Lambda ARN: $LambdaArn"

# --- 4. SQS DLQ -------------------------------------------------------------
$DlqName = "cowrie-exporter-dlq"
Info "Ensuring DLQ: $DlqName"
$dlqUrl = aws sqs get-queue-url --queue-name $DlqName --region $Region 2>$null | ConvertFrom-Json
if ($dlqUrl) { $DlqUrl = $dlqUrl.QueueUrl; Warn "DLQ exists, reusing." }
else {
    $q = aws sqs create-queue --queue-name $DlqName --region $Region | ConvertFrom-Json
    $DlqUrl = $q.QueueUrl
    Ok "DLQ created."
}
$DlqArn = (aws sqs get-queue-attributes --queue-url $DlqUrl --attribute-names QueueArn --region $Region | ConvertFrom-Json).Attributes.QueueArn
Ok "DLQ ARN: $DlqArn"

# --- 5. EventBridge hourly schedule ----------------------------------------
$RuleName = "cowrie-dashboard-exporter-hourly"
Info "Ensuring EventBridge rule: $RuleName"
aws events put-rule --name $RuleName --region $Region --schedule-expression "rate(1 hour)" `
    --state ENABLED --description "Hourly Cowrie dashboard export" | Out-Null
$RuleArn = (aws events describe-rule --name $RuleName --region $Region | ConvertFrom-Json).Arn

# Lambda permission for EventBridge to invoke
aws lambda remove-permission --function-name $FunctionName --region $Region --statement-id "AllowEventBridgeHourly" 2>$null | Out-Null
aws lambda add-permission --function-name $FunctionName --region $Region --statement-id "AllowEventBridgeHourly" `
    --action "lambda:InvokeFunction" --principal "events.amazonaws.com" --source-arn $RuleArn | Out-Null

# Target with DLQ
$target = @(@{
    Id = "exporter"
    Arn = $LambdaArn
    DeadLetterConfig = @{ Arn = $DlqArn }
}) | ConvertTo-Json -Depth 6 -Compress
$tgtFile = Join-Path $env:TEMP "targets.json"; Set-Content -Path $tgtFile -Value $target
aws events put-targets --rule $RuleName --region $Region --targets "file://$tgtFile" | Out-Null
Ok "Schedule -> Lambda (with DLQ) wired."

# --- 6. Upload static site --------------------------------------------------
Info "Uploading site files to s3://$BucketName ..."
Get-ChildItem $siteDir -File | ForEach-Object {
    $ct = switch ($_.Extension) {
        ".html" { "text/html" }
        ".js"   { "application/javascript" }
        ".json" { "application/json" }
        default { "application/octet-stream" }
    }
    aws s3 cp $_.FullName "s3://$BucketName/$($_.Name)" --content-type $ct --region $Region | Out-Null
    Ok "  uploaded $($_.Name)"
}

# --- 7. CloudFront OAC + distribution --------------------------------------
Info "Ensuring CloudFront Origin Access Control..."
$oacName = "cowrie-dashboard-oac"
$oacs = aws cloudfront list-origin-access-controls --output json | ConvertFrom-Json
$oac = $oacs.OriginAccessControlList.Items | Where-Object { $_.Name -eq $oacName } | Select-Object -First 1
if ($oac) { $OacId = $oac.Id; Warn "OAC exists, reusing ($OacId)." }
else {
    $oacConf = @{
        Name = $oacName; Description = "OAC for Cowrie dashboard"
        SigningProtocol = "sigv4"; SigningBehavior = "always"; OriginAccessControlOriginType = "s3"
    } | ConvertTo-Json -Compress
    $oacFile = Join-Path $env:TEMP "oac.json"; Set-Content -Path $oacFile -Value $oacConf
    $o = aws cloudfront create-origin-access-control --origin-access-control-config "file://$oacFile" | ConvertFrom-Json
    $OacId = $o.OriginAccessControl.Id
    Ok "OAC created: $OacId"
}

$originDomain = "$BucketName.s3.$Region.amazonaws.com"
Info "Ensuring CloudFront distribution..."
$distComment = "cowrie-public-dashboard"
$dists = aws cloudfront list-distributions --output json | ConvertFrom-Json
$dist = $dists.DistributionList.Items | Where-Object { $_.Comment -eq $distComment } | Select-Object -First 1

$distConfig = @{
    CallerReference = "cowrie-dashboard-$(Get-Date -Format yyyyMMddHHmmss)"
    Comment = $distComment
    Enabled = $true
    DefaultRootObject = "index.html"
    Origins = @{
        Quantity = 1
        Items = @(@{
            Id = "s3-dashboard"
            DomainName = $originDomain
            S3OriginConfig = @{ OriginAccessIdentity = "" }
            OriginAccessControlId = $OacId
        })
    }
    DefaultCacheBehavior = @{
        TargetOriginId = "s3-dashboard"
        ViewerProtocolPolicy = "redirect-to-https"
        AllowedMethods = @{ Quantity = 2; Items = @("GET","HEAD"); CachedMethods = @{ Quantity = 2; Items = @("GET","HEAD") } }
        Compress = $true
        CachePolicyId = "658327ea-f89d-4fab-a63d-7e88639e58f6"  # Managed-CachingOptimized
    }
    CacheBehaviors = @{
        Quantity = 1
        Items = @(@{
            PathPattern = "*.json"
            TargetOriginId = "s3-dashboard"
            ViewerProtocolPolicy = "redirect-to-https"
            AllowedMethods = @{ Quantity = 2; Items = @("GET","HEAD"); CachedMethods = @{ Quantity = 2; Items = @("GET","HEAD") } }
            Compress = $true
            CachePolicyId = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # Managed-CachingDisabled (fresh JSON)
        })
    }
    PriceClass = "PriceClass_100"
    ViewerCertificate = @{ CloudFrontDefaultCertificate = $true }
} | ConvertTo-Json -Depth 12 -Compress
$distFile = Join-Path $env:TEMP "dist.json"; Set-Content -Path $distFile -Value $distConfig

if ($dist) {
    $DistId = $dist.Id; $DistDomain = $dist.DomainName
    Warn "Distribution exists ($DistId). Leaving config as-is."
} else {
    $d = aws cloudfront create-distribution --distribution-config "file://$distFile" | ConvertFrom-Json
    $DistId = $d.Distribution.Id; $DistDomain = $d.Distribution.DomainName
    Ok "Distribution created: $DistId  ($DistDomain)"
}

# --- 8. Bucket policy granting the distribution read via OAC ---------------
Info "Applying bucket policy for OAC..."
$bucketPolicy = @{
    Version = "2012-10-17"
    Statement = @(@{
        Sid = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = @{ Service = "cloudfront.amazonaws.com" }
        Action = "s3:GetObject"
        Resource = "arn:aws:s3:::$BucketName/*"
        Condition = @{ StringEquals = @{ "AWS:SourceArn" = "arn:aws:cloudfront::${AccountId}:distribution/$DistId" } }
    })
} | ConvertTo-Json -Depth 10 -Compress
$bpFile = Join-Path $env:TEMP "bucket-policy.json"; Set-Content -Path $bpFile -Value $bucketPolicy
aws s3api put-bucket-policy --bucket $BucketName --policy "file://$bpFile" | Out-Null
Ok "Bucket policy applied."

# --- Summary ----------------------------------------------------------------
Write-Host ""
Write-Host "================ DEPLOY SUMMARY ================" -ForegroundColor Magenta
Write-Host "Bucket        : $BucketName"
Write-Host "Lambda        : $FunctionName  ($LambdaArn)"
Write-Host "DLQ           : $DlqName  ($DlqArn)"
Write-Host "Schedule      : $RuleName  (rate(1 hour))"
Write-Host "Distribution  : $DistId"
Write-Host "Dashboard URL : https://$DistDomain"
Write-Host "================================================"
Write-Host ""
Write-Host "NOTE: CloudFront takes ~5-10 min to deploy." -ForegroundColor Yellow
Write-Host "Next: test-invoke the exporter to generate JSON:" -ForegroundColor Yellow
Write-Host "  aws lambda invoke --function-name $FunctionName --region $Region --log-type Tail out.json; Get-Content out.json" -ForegroundColor Yellow
