Write-Host 'Connecting to exchange- Use Tenant admin credentials'
Connect-ExchangeOnline

# Define the IP addresses for Proofpoint Essentials and other authorized mail systems
$ProofpointIPs = @(
    "67.231.152.0/24", "67.231.153.0/24", "67.231.154.0/24", "67.231.155.0/24", "67.231.156.0/24",
    "67.231.144.0/24", "67.231.145.0/24", "67.231.146.0/24", "67.231.147.0/24", "67.231.148.0/24", "67.231.149.0/24",
    "148.163.128.0/24", "148.163.129.0/24", "148.163.130.0/24", "148.163.131.0/24", "148.163.132.0/24",
    "148.163.133.0/24", "148.163.134.0/24", "148.163.135.0/24", "148.163.136.0/24", "148.163.137.0/24",
    "148.163.138.0/24", "148.163.139.0/24", "148.163.140.0/24", "148.163.141.0/24", "148.163.142.0/24",
    "148.163.143.0/24", "148.163.144.0/24", "148.163.145.0/24", "148.163.146.0/24", "148.163.147.0/24",
    "148.163.148.0/24", "148.163.149.0/24", "148.163.150.0/24", "148.163.151.0/24", "148.163.152.0/24",
    "148.163.153.0/24", "148.163.154.0/24", "148.163.155.0/24", "148.163.156.0/24", "148.163.157.0/24",
    "148.163.158.0/24", "148.163.159.0/24"
)

Write-Host ''
Write-Host 'Configuring Outbound Connector'
$OutboundConnectorName = "Outbound connector for Proofpoint Essentials"
$ExistingOutboundConnector = Get-OutboundConnector -Identity $OutboundConnectorName -ErrorAction SilentlyContinue

if ($ExistingOutboundConnector) {
    Write-Host "Outbound Connector '$OutboundConnectorName' already exists. Updating its settings."
    $OutboundConnectorEnabledState = $ExistingOutboundConnector.Enabled
    Set-OutboundConnector -Identity $OutboundConnectorName `
        -TlsSettings certificatevalidation `
        -RecipientDomains * `
        -SmartHosts "outbound-us1.ppe-hosted.com" `
        -UseMXRecord $False `
        -Enabled $OutboundConnectorEnabledState
} else {
    Write-Host "Outbound Connector '$OutboundConnectorName' not found. Creating a new one."
    New-OutboundConnector -Name $OutboundConnectorName `
        -comment "Outbound connector for Proofpoint Essentials" `
        -TlsSettings certificatevalidation `
        -RecipientDomains * `
        -SmartHosts "outbound-us1.ppe-hosted.com" `
        -UseMXRecord $False `
        -Enabled $false
}

$VarTestEml = Read-Host -Prompt 'What Email would you like to use for validation? (Your BPT email will work here)'
Validate-OutboundConnector -Identity $OutboundConnectorName -Recipients "$VarTestEml"
Write-Host ''
Write-Host ''

Write-Host 'Configuring Inbound Connector'
# Using the connector name and SenderDomains value exactly as you provided
$InboundConnectorName = "Inbound connector for Proofpoint Essentials"
$ExistingInboundConnector = Get-InboundConnector -Identity $InboundConnectorName -ErrorAction SilentlyContinue

if ($ExistingInboundConnector) {
    Write-Host "Inbound Connector '$InboundConnectorName' already exists. Updating its settings."
    $InboundConnectorEnabledState = $ExistingInboundConnector.Enabled
    Set-InboundConnector -Identity $InboundConnectorName `
        -SenderDomains "smtp:*;1" `
        -RequireTls $true `
        -SenderIPAddresses $ProofpointIPs `
        -RestrictDomainsToIPAddresses $true `
        -Enabled $InboundConnectorEnabledState
} else {
    Write-Host "Inbound Connector '$InboundConnectorName' not found. Creating a new one."
    New-InboundConnector -Name $InboundConnectorName `
        -comment "Inbound connector for Proofpoint Essentials" `
        -SenderDomains "smtp:*;1" `
        -RequireTls $true `
        -SenderIPAddresses $ProofpointIPs `
        -RestrictDomainsToIPAddresses $true `
        -Enabled $false
}
Write-Host ''
Write-Host ''

Write-Host 'Configuring Spam Bypass rule'
$TransportRuleName = "Bypass Spam Filter (PPE)"
$ExistingTransportRule = Get-TransportRule -Identity $TransportRuleName -ErrorAction SilentlyContinue

if ($ExistingTransportRule) {
    Write-Host "Transport Rule '$TransportRuleName' already exists. Updating its settings."
																		 
    Set-TransportRule -Identity $TransportRuleName `
        -SenderIpRanges $ProofpointIPs `
        -SetSCL -1 
} else {
    Write-Host "Transport Rule '$TransportRuleName' not found. Creating a new one."
    New-TransportRule -Name $TransportRuleName `
        -Priority 0 `
        -SenderIpRanges $ProofpointIPs `
        -SetSCL -1 `
        -Enabled $false
}
Write-Host ''
Write-Host ''


$title    = 'Enable Now?'
$question = 'Are you ready to enable the Proofpoint connectors and rule? (This will enable them if they are currently disabled)'
$choices  = '&Yes', '&No'
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)

if ($decision -eq 0) {
    # Explicitly enable only the connectors and rule by their names
    Set-OutboundConnector -Identity $OutboundConnectorName -Enabled $true
    Set-InboundConnector -Identity $InboundConnectorName -Enabled $true
    # Enable-TransportRule is the correct cmdlet to enable a transport rule
    Enable-TransportRule -Identity $TransportRuleName
    Write-Host 'Proofpoint connectors and rule have been enabled.'
} else {
    Write-Host 'Proofpoint connectors and rule have not been enabled. Their previous states have been preserved for existing objects.'
}