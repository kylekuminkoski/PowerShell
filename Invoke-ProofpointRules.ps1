# Connect to Exchange Online
Write-Host 'Connecting to Exchange Online - Use Tenant admin credentials'
Connect-ExchangeOnline
# Setting up Connection Filter defaults for ProofPoint
Write-Host 'Setting up Connection Filter defaults for ProofPoint'
Set-HostedConnectionFilterPolicy "Default" -IPAllowList @{
    Add="67.231.152.0/24","67.231.153.0/24","67.231.154.0/24","67.231.155.0/24",
    "67.231.156.0/24","67.231.144.0/24","67.231.145.0/24","67.231.146.0/24",
    "67.231.147.0/24","67.231.148.0/24","67.231.149.0/24","148.163.128.0/24",
    "148.163.129.0/24","148.163.130.0/24","148.163.131.0/24","148.163.132.0/24",
    "148.163.133.0/24","148.163.134.0/24","148.163.135.0/24","148.163.136.0/24",
    "148.163.137.0/24","148.163.138.0/24","148.163.139.0/24","148.163.140.0/24",
    "148.163.141.0/24","148.163.142.0/24","148.163.143.0/24","148.163.144.0/24",
    "148.163.145.0/24","148.163.146.0/24","148.163.147.0/24","148.163.148.0/24",
    "148.163.149.0/24","148.163.150.0/24","148.163.151.0/24","148.163.152.0/24",
    "148.163.153.0/24","148.163.154.0/24","148.163.155.0/24","148.163.156.0/24",
    "148.163.157.0/24","148.163.158.0/24","148.163.159.0/24"
} -EnableSafeList $true
Write-Host 'If no error text is displayed, the Connection filter was set up successfully'
Write-Host ''
Write-Host ''
# Configuring Outbound Connector
Write-Host 'Configuring Outbound Connector'
New-OutboundConnector -Name "Outbound connector for Proofpoint Essentials" `
    -Comment "Outbound connector for Proofpoint Essentials" `
    -TlsSettings certificatevalidation `
    -RecipientDomains * `
    -SmartHosts "outbound-us1.ppe-hosted.com" `
    -UseMXRecord $False `
    -Enabled $False
# Validate Outbound Connector
$VarTestEml = Read-Host -Prompt 'What Email would you like to use for validation? (Your BPT email will work here)'
Validate-OutboundConnector -Identity 'Outbound connector for Proofpoint Essentials' -Recipients "$VarTestEml"
Write-Host ''
Write-Host ''
# Configuring Inbound Connector
Write-Host 'Configuring Inbound Connector'
New-InboundConnector -Name "Inbound connector for Proofpoint Essentials" `
    -Comment "Inbound connector for Proofpoint Essentials" `
    -SenderIPAddresses `
        67.231.152.0/24,67.231.153.0/24,67.231.154.0/24,67.231.155.0/24,67.231.156.0/24, `
        67.231.144.0/24,67.231.145.0/24,67.231.146.0/24,67.231.147.0/24,67.231.148.0/24, `
        67.231.149.0/24,148.163.128.0/24,148.163.129.0/24,148.163.130.0/24,148.163.131.0/24, `
        148.163.132.0/24,148.163.133.0/24,148.163.134.0/24,148.163.135.0/24,148.163.136.0/24, `
        148.163.137.0/24,148.163.138.0/24,148.163.139.0/24,148.163.140.0/24,148.163.141.0/24, `
        148.163.142.0/24,148.163.143.0/24,148.163.144.0/24,148.163.145.0/24,148.163.146.0/24, `
        148.163.147.0/24,148.163.148.0/24,148.163.149.0/24,148.163.150.0/24,148.163.151.0/24, `
        148.163.152.0/24,148.163.153.0/24,148.163.154.0/24,148.163.155.0/24,148.163.156.0/24, `
        148.163.157.0/24,148.163.158.0/24,148.163.159.0/24 `
    -SenderDomains * `
    -RequireTls $True `
    -Enabled $False
Write-Host ''
Write-Host ''
# Configuring Spam Bypass Rule
Write-Host 'Configuring Spam Bypass Rule'
New-TransportRule -Name "Bypass Spam Filter (PPE)" `
    -Priority 0 `
    -SenderIpRanges `
        67.231.152.0/24,67.231.153.0/24,67.231.154.0/24,67.231.155.0/24,67.231.156.0/24, `
        67.231.144.0/24,67.231.145.0/24,67.231.146.0/24,67.231.147.0/24,67.231.148.0/24, `
        67.231.149.0/24,148.163.128.0/24,148.163.129.0/24,148.163.130.0/24,148.163.131.0/24, `
        148.163.132.0/24,148.163.133.0/24,148.163.134.0/24,148.163.135.0/24,148.163.136.0/24, `
        148.163.137.0/24,148.163.138.0/24,148.163.139.0/24,148.163.140.0/24,148.163.141.0/24, `
        148.163.142.0/24,148.163.143.0/24,148.163.144.0/24,148.163.145.0/24,148.163.146.0/24, `
        148.163.147.0/24,148.163.148.0/24,148.163.149.0/24,148.163.150.0/24,148.163.151.0/24, `
        148.163.152.0/24,148.163.153.0/24,148.163.154.0/24,148.163.155.0/24,148.163.156.0/24, `
        148.163.157.0/24,148.163.158.0/24,148.163.159.0/24 `
    -SetSCL -1 `
    -Enabled $False
# Prompt to Enable Connectors and Rules
$title    = 'Enable Now?'
$question = 'Are you ready to enable all connectors and rules?'
$choices  = '&Yes', '&No'
$choice = $host.ui.PromptForChoice($title, $question, $choices, 0)
switch ($choice) {
    0 {
        # Enable Outbound Connector
        Enable-OutboundConnector -Identity 'Outbound connector for Proofpoint Essentials'
        Write-Host 'Outbound Connector has been enabled.'
        # Enable Inbound Connector
        Enable-InboundConnector -Identity 'Inbound connector for Proofpoint Essentials'
        Write-Host 'Inbound Connector has been enabled.'
        # Enable Transport Rule
        Enable-TransportRule -Identity 'Bypass Spam Filter (PPE)'
        Write-Host 'Transport Rule "Bypass Spam Filter (PPE)" has been enabled.'
    }
    1 {
        Write-Host 'Connectors and rules remain disabled. Please enable them manually when ready.'
    }
}