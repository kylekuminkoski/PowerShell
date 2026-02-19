# CMMC 2.0 Assessment Automation Guide
## NinjaRMM → Rewst → Drata Integration

This guide provides step-by-step instructions for automating CMMC 2.0 Level 2 compliance assessments across your fleet using NinjaRMM, processing data through Rewst, and sending results to Drata.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Phase 1: NinjaRMM Setup](#phase-1-ninjarmm-setup)
4. [Phase 2: Rewst Workflow Configuration](#phase-2-rewst-workflow-configuration)
5. [Phase 3: Drata Integration](#phase-3-drata-integration)
6. [Testing & Validation](#testing--validation)
7. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────┐
│  NinjaRMM       │
│  Scripted       │  Runs on each Windows workstation
│  Action         │  Generates JSON assessment data
└────────┬────────┘
         │
         │ HTTP POST (JSON)
         ▼
┌─────────────────┐
│  Rewst          │
│  Webhook        │  Receives and processes JSON
│  Workflow       │  Aggregates multi-device data
└────────┬────────┘
         │
         │ API Call (Transformed Data)
         ▼
┌─────────────────┐
│  Drata          │
│  Custom         │  Records compliance evidence
│  Integration    │  Tracks CMMC controls
└─────────────────┘
```

**Data Flow:**
1. NinjaRMM deploys `Deploy-CMMC2Assessment.ps1` to target devices
2. Script runs `Invoke-CMMC2Assessment.ps1` with `-ExportJSON` flag
3. JSON results posted to Rewst webhook
4. Rewst workflow validates, transforms, and aggregates data
5. Rewst sends formatted data to Drata custom integration
6. Drata records compliance evidence and updates control status

---

## Prerequisites

### Required Access & Credentials

- **NinjaRMM**: Organization administrator or scripting permission
- **Rewst**: Workflow creation permission, webhook access
- **Drata**: Custom integration setup permission, API access
- **Azure AD/Intune**: Read permissions (for device context)

### Required Files

- `Invoke-CMMC2Assessment.ps1` (main assessment script)
- `Deploy-CMMC2Assessment.ps1` (NinjaRMM wrapper)

### Software Requirements

- PowerShell 5.1+ on all target devices
- Windows 10/11 or Windows Server 2016+
- Administrator rights for assessment execution

---

## Phase 1: NinjaRMM Setup

### Step 1.1: Upload Assessment Scripts

1. Navigate to **Administration → Library → Automation**
2. Click **Add → Script**
3. Create two scripts:

**Script 1: CMMC2-Assessment-Main**
- Name: `CMMC2-Assessment-Main`
- Category: `Compliance`
- Description: `CMMC 2.0 Level 2 compliance assessment script`
- Script Type: `PowerShell`
- Upload or paste contents of `Invoke-CMMC2Assessment.ps1`

**Script 2: CMMC2-Deployment-Wrapper**
- Name: `CMMC2-Deployment-Wrapper`
- Category: `Compliance`
- Description: `NinjaRMM deployment wrapper for CMMC assessment`
- Script Type: `PowerShell`
- Upload or paste contents of `Deploy-CMMC2Assessment.ps1`

### Step 1.2: Create Scripted Action

1. Navigate to **Administration → Policies → Scripted Actions**
2. Click **Add Scripted Action**
3. Configure:
   - **Name**: `Run CMMC 2.0 Assessment`
   - **Category**: `Compliance / Security`
   - **Script**: Select `CMMC2-Deployment-Wrapper`
   - **Run As**: `System`
   - **Timeout**: `600 seconds` (10 minutes)

### Step 1.3: Configure Script Parameters

You have three deployment options. Choose based on your environment:

#### Option A: Rewst Webhook (Recommended)

```powershell
# Script Parameters in NinjaRMM
-WebhookURL "https://engine.rewst.io/webhooks/custom/YOUR-WEBHOOK-ID-HERE"
-ScriptSource "$env:ProgramData\NinjaRMMAgent\scripting\Invoke-CMMC2Assessment.ps1"
```

**Pros**: Real-time data delivery, no infrastructure needed
**Cons**: Requires outbound internet access from workstations

#### Option B: Network Share

```powershell
# Script Parameters in NinjaRMM
-UseNetworkShare -NetworkSharePath "\\fileserver\compliance\CMMC-Reports"
-ScriptSource "$env:ProgramData\NinjaRMMAgent\scripting\Invoke-CMMC2Assessment.ps1"
```

**Pros**: Works in air-gapped or restricted networks
**Cons**: Requires file share infrastructure, Rewst must poll share

#### Option C: Azure Blob Storage

```powershell
# Script Parameters in NinjaRMM
-UseAzureBlob -AzureBlobURL "https://yourstorageaccount.blob.core.windows.net/cmmc?sp=racw&st=2026-02-10..."
-ScriptSource "$env:ProgramData\NinjaRMMAgent\scripting\Invoke-CMMC2Assessment.ps1"
```

**Pros**: Scalable, secure, Azure-native
**Cons**: Requires Azure subscription, SAS token management

### Step 1.4: Deploy to Devices

1. Navigate to **Devices → All Devices**
2. Select target devices (Windows workstations)
3. Click **Actions → Run Script**
4. Select `Run CMMC 2.0 Assessment`
5. Choose schedule:
   - **One-time**: Immediate assessment
   - **Scheduled**: Weekly/monthly recurring (recommended)
   - **Triggered**: On device check-in or policy update

**Recommended Schedule**: Weekly on Sunday at 2:00 AM

### Step 1.5: Configure Script Deployment

To ensure the main assessment script is available on devices:

1. Navigate to **Administration → Policies → Software Deployment**
2. Create new software deployment:
   - **Name**: `Deploy CMMC2 Assessment Script`
   - **Type**: `File Copy`
   - **Source**: Upload `Invoke-CMMC2Assessment.ps1`
   - **Destination**: `C:\ProgramData\NinjaRMMAgent\scripting\`
   - **Condition**: Deploy to all Windows devices

---

## Phase 2: Rewst Workflow Configuration

### Step 2.1: Create Webhook Trigger

1. Log into **Rewst** (https://app.rewst.io)
2. Navigate to **Automations → Workflows**
3. Click **Create Workflow**
4. Configure:
   - **Name**: `CMMC 2.0 Assessment Processor`
   - **Description**: `Receives CMMC assessment data from NinjaRMM and forwards to Drata`
   - **Trigger Type**: `Webhook`

5. Copy the webhook URL (format: `https://engine.rewst.io/webhooks/custom/[id]`)
6. Use this URL in your NinjaRMM script parameters

### Step 2.2: Build Workflow Logic

#### Trigger Configuration

```yaml
Trigger: Webhook
  Method: POST
  Content-Type: application/json
  Authentication: None (or API Key if preferred)
```

#### Workflow Steps

**Step 1: Validate Incoming Data**

```python
# Jinja2 template for validation
{{ CTX.webhook.body.AssessmentMetadata }}
{{ CTX.webhook.body.ComplianceSummary }}
{{ CTX.webhook.body.ControlResults }}

# Validation checks
{% if CTX.webhook.body.AssessmentMetadata.ComputerName %}
  Valid
{% else %}
  Invalid - Missing ComputerName
{% endif %}
```

**Step 2: Extract Key Metrics**

Create data aliases for easier reference:

```python
computer_name: {{ CTX.webhook.body.AssessmentMetadata.ComputerName }}
assessment_date: {{ CTX.webhook.body.AssessmentMetadata.AssessmentDate }}
overall_score: {{ CTX.webhook.body.ComplianceSummary.OverallScore }}
compliant_count: {{ CTX.webhook.body.ComplianceSummary.CompliantCount }}
non_compliant_count: {{ CTX.webhook.body.ComplianceSummary.NonCompliantCount }}
control_results: {{ CTX.webhook.body.ControlResults }}
```

**Step 3: Store in Rewst Database (Optional)**

Add **Database Action** to store historical data:

```yaml
Action: Database Insert
  Table: cmmc_assessments
  Fields:
    - computer_name: {{ CTX.computer_name }}
    - assessment_date: {{ CTX.assessment_date }}
    - overall_score: {{ CTX.overall_score }}
    - compliant_count: {{ CTX.compliant_count }}
    - non_compliant_count: {{ CTX.non_compliant_count }}
    - raw_json: {{ CTX.webhook.body | tojson }}
```

**Step 4: Transform Data for Drata**

Add **Data Transform** action:

```python
# Transform CMMC control results to Drata format
{% set drata_controls = [] %}
{% for control in CTX.control_results %}
  {% set drata_control = {
    "control_id": control.Control,
    "control_name": control.Title,
    "status": "compliant" if control.Status == "Compliant" else "non_compliant",
    "evidence_date": CTX.assessment_date,
    "device_name": CTX.computer_name,
    "category": control.Category,
    "finding": control.Finding,
    "remediation": control.Remediation
  } %}
  {% set _ = drata_controls.append(drata_control) %}
{% endfor %}

{{ {"controls": drata_controls, "summary": {
  "device": CTX.computer_name,
  "score": CTX.overall_score,
  "total_controls": CTX.webhook.body.ComplianceSummary.TotalChecks,
  "compliant": CTX.compliant_count,
  "non_compliant": CTX.non_compliant_count
}} | tojson }}
```

**Step 5: Send to Drata**

Add **HTTP Request** action:

```yaml
Action: HTTP Request
  Method: POST
  URL: https://api.drata.com/public/v1/custom-integrations/YOUR-INTEGRATION-ID/results
  Headers:
    Authorization: Bearer YOUR-DRATA-API-TOKEN
    Content-Type: application/json
  Body: {{ CTX.drata_transform }}
```

**Step 6: Error Handling & Notifications**

Add **Conditional** action for error handling:

```yaml
Condition: {{ CTX.http_request.status_code != 200 }}
  True Actions:
    - Send notification (email/Slack)
    - Log error to database
    - Create ticket in PSA
```

### Step 2.3: Advanced Features (Optional)

#### Aggregation for Fleet-Wide Reporting

Add a scheduled workflow that runs daily:

```python
# Query all assessments from last 24 hours
{% set recent_assessments = DATABASE.query(
  "SELECT * FROM cmmc_assessments WHERE assessment_date > NOW() - INTERVAL 1 DAY"
) %}

# Calculate fleet-wide metrics
{% set fleet_avg_score = recent_assessments | avg('overall_score') %}
{% set fleet_total_devices = recent_assessments | length %}
{% set failing_devices = recent_assessments | selectattr('overall_score', '<', 80) | list %}

# Send summary to Drata
{
  "fleet_summary": {
    "total_devices_assessed": {{ fleet_total_devices }},
    "average_compliance_score": {{ fleet_avg_score }},
    "devices_below_threshold": {{ failing_devices | length }},
    "assessment_period": "last_24_hours"
  }
}
```

---

## Phase 3: Drata Integration

### Step 3.1: Create Custom Integration in Drata

1. Log into **Drata** (https://app.drata.com)
2. Navigate to **Integrations → Custom Integrations**
3. Click **Create Custom Integration**
4. Configure:
   - **Name**: `CMMC 2.0 Workstation Assessments`
   - **Description**: `Automated compliance assessments from NinjaRMM via Rewst`
   - **Type**: `API`
   - **Frequency**: `Real-time (webhook-driven)`

### Step 3.2: Map CMMC Controls to Drata Frameworks

Drata may not have CMMC 2.0 out-of-the-box. Map CMMC controls to relevant frameworks:

| CMMC Control | Maps to Drata Framework |
|--------------|-------------------------|
| AC.1.001 | SOC 2 - CC6.1 (Logical Access) |
| AC.1.002 | SOC 2 - CC6.2 (Authorization) |
| AU.1.001 | SOC 2 - CC7.2 (System Monitoring) |
| IA.1.001 | SOC 2 - CC6.1 (User Authentication) |
| SC.1.001 | SOC 2 - CC6.6 (Encryption in Transit) |
| SI.1.001 | SOC 2 - CC7.1 (Malware Protection) |
| CM.1.001 | SOC 2 - CC8.1 (Change Management) |

### Step 3.3: Configure API Endpoint

1. In Drata Custom Integration settings, locate **API Configuration**
2. Note the **Integration ID** (e.g., `custom_integration_abc123`)
3. Generate an **API Token**:
   - Navigate to **Settings → API Tokens**
   - Click **Generate Token**
   - Scope: `custom_integrations:write`
   - Copy token (starts with `drata_`)

4. Update Rewst workflow Step 5 with your Integration ID and API Token

### Step 3.4: Define Control Evidence Mapping

In Drata, create custom controls that match your CMMC assessment:

```json
{
  "custom_controls": [
    {
      "control_id": "CMMC-AC.1.001",
      "control_name": "Authorized Access Control",
      "framework": "CMMC 2.0 Level 2",
      "category": "Access Control",
      "evidence_type": "automated_scan",
      "passing_criteria": {
        "status": "compliant"
      }
    },
    {
      "control_id": "CMMC-AU.1.001",
      "control_name": "System Audit Logging",
      "framework": "CMMC 2.0 Level 2",
      "category": "Audit & Accountability",
      "evidence_type": "automated_scan",
      "passing_criteria": {
        "status": "compliant"
      }
    }
    // ... repeat for all 33 controls
  ]
}
```

### Step 3.5: Configure Drata Monitors

Set up monitors to alert on compliance drift:

1. Navigate to **Monitors → Create Monitor**
2. Configure:
   - **Name**: `CMMC Workstation Compliance < 80%`
   - **Type**: `Custom Integration Data`
   - **Source**: `CMMC 2.0 Workstation Assessments`
   - **Condition**: `overall_score < 80`
   - **Alert**: Email security team + create task

---

## Testing & Validation

### Test Phase 1: Single Device Test

1. Select a test workstation in NinjaRMM
2. Manually run the `Run CMMC 2.0 Assessment` scripted action
3. Monitor NinjaRMM activity log for execution
4. Verify in Rewst:
   - Check webhook received data (Automations → Workflow History)
   - Confirm data transformation successful
   - Verify HTTP POST to Drata returned 200 OK
5. Verify in Drata:
   - Navigate to custom integration page
   - Confirm new evidence record appears
   - Check control status updated

### Test Phase 2: Small Device Group

1. Create a test policy in NinjaRMM
2. Assign 5-10 test devices
3. Schedule assessment for immediate execution
4. Monitor Rewst for concurrent webhook processing
5. Verify all devices appear in Drata within 10 minutes

### Test Phase 3: Full Fleet Rollout

1. Create production policy in NinjaRMM
2. Assign to all Windows workstations
3. Schedule for weekly execution (e.g., Sunday 2 AM)
4. Monitor first week for:
   - Execution success rate > 95%
   - Data delivery to Drata within SLA
   - No performance impact on workstations

---

## Troubleshooting

### Issue: NinjaRMM Script Fails

**Symptoms**: Script timeout, error in activity log

**Diagnosis**:
```powershell
# Check log file on affected device
Get-Content "$env:TEMP\CMMC2Assessment\deployment.log"
```

**Common Causes**:
- Insufficient permissions (not running as admin)
- PowerShell execution policy restriction
- Assessment script missing from deployment location
- Network connectivity issues (webhook/share unreachable)

**Resolution**:
```powershell
# Fix execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Verify script exists
Test-Path "$env:ProgramData\NinjaRMMAgent\scripting\Invoke-CMMC2Assessment.ps1"

# Test webhook connectivity
Invoke-WebRequest -Uri "YOUR-WEBHOOK-URL" -Method Get
```

### Issue: Rewst Webhook Not Receiving Data

**Symptoms**: No workflow executions in Rewst history

**Diagnosis**:
- Check NinjaRMM script output for HTTP errors
- Verify webhook URL is correct (copy-paste from Rewst)
- Test webhook manually:

```powershell
$testPayload = @{
    AssessmentMetadata = @{
        ComputerName = "TEST-PC"
        AssessmentDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }
    ComplianceSummary = @{
        OverallScore = 85
        TotalChecks = 33
        CompliantCount = 28
        NonCompliantCount = 5
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "YOUR-WEBHOOK-URL" -Method Post -Body $testPayload -ContentType "application/json"
```

**Resolution**:
- Update webhook URL in NinjaRMM script parameters
- Check Rewst webhook authentication settings
- Verify webhook is enabled (not disabled/archived)

### Issue: Drata Not Receiving Data

**Symptoms**: Rewst workflow succeeds but no data in Drata

**Diagnosis**:
- Check Rewst workflow HTTP response from Drata
- Verify API token has correct scopes
- Check Drata integration status (active vs. paused)

**Resolution**:
```python
# In Rewst, add logging action after Drata HTTP request
Log Message: "Drata Response: {{ CTX.http_request.status_code }} - {{ CTX.http_request.body }}"
```

- If 401 Unauthorized: Regenerate API token
- If 400 Bad Request: Verify data transformation matches Drata schema
- If 404 Not Found: Verify custom integration ID is correct

### Issue: Data Mismatch Between Sources

**Symptoms**: Different compliance scores in HTML vs JSON vs Drata

**Diagnosis**:
- Compare HTML report (local) with JSON file
- Check Rewst data transformation logic
- Verify Drata received complete payload

**Resolution**:
- Ensure script version is consistent across all devices
- Review Rewst transformation for data loss
- Enable verbose logging in all components

---

## Maintenance & Best Practices

### Regular Maintenance Tasks

**Weekly**:
- Review Drata compliance trends
- Investigate devices with declining scores
- Address non-compliant controls

**Monthly**:
- Audit Rewst workflow execution success rate
- Review NinjaRMM scripted action logs
- Update CMMC control mappings if frameworks change

**Quarterly**:
- Update assessment script with new controls/checks
- Review and update remediation guidance
- Validate Drata evidence retention

### Performance Optimization

- **Stagger NinjaRMM execution**: Avoid running all devices simultaneously
- **Batch Rewst processing**: If using network share, poll every 15 minutes
- **Drata API rate limits**: Implement exponential backoff in Rewst
- **Archive old data**: Set retention policy for Rewst database (e.g., 90 days)

### Security Considerations

- **Protect webhook URLs**: Use Rewst webhook authentication
- **Secure API tokens**: Store Drata tokens in Rewst encrypted variables
- **Audit access**: Review who can modify NinjaRMM scripts/policies
- **Network security**: If using webhooks, consider IP whitelisting

---

## Appendix

### A. Example JSON Output Structure

```json
{
  "AssessmentMetadata": {
    "ComputerName": "WS-2024-001",
    "AssessmentDate": "2026-02-10T14:30:00Z",
    "ScriptVersion": "2.1",
    "Framework": "CMMC 2.0 Level 2 (NIST SP 800-171)"
  },
  "ComplianceSummary": {
    "OverallScore": 87.88,
    "TotalChecks": 33,
    "CompliantCount": 29,
    "NonCompliantCount": 3,
    "InformationalCount": 1
  },
  "ControlResults": [
    {
      "Control": "AC.1.001",
      "Title": "Authorized Access Control",
      "Category": "Access Control",
      "Status": "Compliant",
      "Finding": "Limited access enforced: BUILTIN\\Administrators, ...",
      "Remediation": "Compliant - No action needed"
    }
  ]
}
```

### B. Rewst Workflow Template (YAML)

Available upon request - contact your Rewst CSM for the official workflow template import.

### C. Drata Custom Integration Schema

Available upon request - contact Drata support for the latest custom integration API specification.

### D. Support Resources

- **NinjaRMM Documentation**: https://ninjarmm.zendesk.com
- **Rewst Documentation**: https://docs.rewst.help
- **Drata API Documentation**: https://docs.drata.com/api
- **CMMC Resources**: https://www.acq.osd.mil/cmmc/

---

## Version History

- **v1.0** (2026-02-10): Initial release
  - NinjaRMM deployment wrapper
  - Rewst workflow configuration
  - Drata integration setup

---

*For questions or support with this automation workflow, contact your IT administrator or MSP.*
