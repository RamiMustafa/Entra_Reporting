#Requires -Version 5.1

<#
.SYNOPSIS
Exports Microsoft Entra PIM assignments and activation history, including
assignment creator and approval details when available.

.REQUIREMENTS
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

Delegated Microsoft Graph permissions:
- RoleManagement.ReadWrite.Directory
- RoleAssignmentSchedule.ReadWrite.Directory
- RoleEligibilitySchedule.ReadWrite.Directory
- Directory.Read.All

.NOTES
Author:  Rami Mustafa, Sr. Cybersecurity Cloud Solutions Architect
Email:   Rami.Mustafa@microsoft.com
Org:     Microsoft
Created: 2026-09-28
Version: 1.0.0

Approval details use the Microsoft Graph beta roleAssignmentApprovals endpoint.
Beta APIs can change and are not supported for production applications.
#>

[CmdletBinding()]
param(
    [Parameter()][string]$TenantId,
    [Parameter()][ValidateNotNullOrEmpty()][string]$OutputFolder = "D:\Entra-PIM-Report",
    [Parameter()][switch]$IncludeRolesWithoutAssignments,
    [Parameter()][switch]$UseDeviceCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$GraphV1 = "https://graph.microsoft.com/v1.0"
$GraphBeta = "https://graph.microsoft.com/beta"
$PrincipalCache = @{}
$ApprovalCache = @{}

function Test-Blank {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $true }
    return ([string]$Value).Trim().Length -eq 0
}

function Write-Log {
    param(
        [Parameter(Mandatory)][ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ("[{0}] [{1}] {2}" -f $stamp,$Level,$Message)
}

function Get-Value {
    param([AllowNull()]$Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-UtcText {
    param([AllowNull()]$Value)
    if (Test-Blank $Value) { return $null }
    try { return ([datetimeoffset]$Value).UtcDateTime.ToString("o") }
    catch { return [string]$Value }
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri)

    $delays = @(2,4,8,16,32,60)
    for ($attempt = 0; $attempt -lt $delays.Count; $attempt++) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        }
        catch {
            $message = $_.Exception.Message
            $retryable = $message -match '429|502|503|504|Too Many Requests|timeout|temporar|connection reset'
            if ((-not $retryable) -or ($attempt -eq ($delays.Count - 1))) { throw }
            $delay = $delays[$attempt]
            Write-Log "WARN" ("Graph request failed. Retrying in {0} seconds. {1}" -f $delay,$message)
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri)

    $items = @()
    $nextLink = $Uri
    while (-not (Test-Blank $nextLink)) {
        $response = Invoke-GraphGet -Uri $nextLink
        $value = Get-Value $response "value"
        if ($null -ne $value) { $items += @($value) }
        $nextLink = Get-Value $response "@odata.nextLink"
    }
    return @($items)
}

function Get-Principal {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Id)

    if ($PrincipalCache.ContainsKey($Id)) { return $PrincipalCache[$Id] }
    try {
        $basic = Invoke-GraphGet -Uri ("{0}/directoryObjects/{1}" -f $GraphV1,$Id)
        $odataType = [string](Get-Value $basic "@odata.type")
        $detail = $basic
        $type = "DirectoryObject"

        if ($odataType -match 'user$') {
            $type = "User"
            $detail = Invoke-GraphGet -Uri ("{0}/users/{1}?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled" -f $GraphV1,$Id)
        }
        elseif ($odataType -match 'group$') {
            $type = "Group"
            $detail = Invoke-GraphGet -Uri ("{0}/groups/{1}?`$select=id,displayName,mail,isAssignableToRole" -f $GraphV1,$Id)
        }
        elseif ($odataType -match 'servicePrincipal$') {
            $type = "ServicePrincipal"
            $detail = Invoke-GraphGet -Uri ("{0}/servicePrincipals/{1}?`$select=id,displayName,appId,accountEnabled" -f $GraphV1,$Id)
        }

        $result = [pscustomobject]@{
            Id=$Id; Type=$type; DisplayName=Get-Value $detail "displayName"
            UserPrincipalName=Get-Value $detail "userPrincipalName"; Mail=Get-Value $detail "mail"
            UserType=Get-Value $detail "userType"; AccountEnabled=Get-Value $detail "accountEnabled"
            AppId=Get-Value $detail "appId"; IsAssignableToRole=Get-Value $detail "isAssignableToRole"
        }
    }
    catch {
        Write-Log "WARN" ("Could not resolve principal {0}. {1}" -f $Id,$_.Exception.Message)
        $result = [pscustomobject]@{
            Id=$Id; Type="Unresolved"; DisplayName=$null; UserPrincipalName=$null; Mail=$null
            UserType=$null; AccountEnabled=$null; AppId=$null; IsAssignableToRole=$null
        }
    }
    $PrincipalCache[$Id] = $result
    return $result
}

function Get-RequestCreator {
    param([AllowNull()]$Request)

    $empty = [pscustomobject]@{Id=$null;Type=$null;DisplayName=$null;UserPrincipalName=$null;AppId=$null}
    if ($null -eq $Request) { return $empty }
    $createdBy = Get-Value $Request "createdBy"
    if ($null -eq $createdBy) { return $empty }

    $user = Get-Value $createdBy "user"
    if ($null -ne $user) {
        $id = [string](Get-Value $user "id")
        if (-not (Test-Blank $id)) {
            $principal = Get-Principal -Id $id
            return [pscustomobject]@{
                Id=$principal.Id; Type=$principal.Type; DisplayName=$principal.DisplayName
                UserPrincipalName=$principal.UserPrincipalName; AppId=$null
            }
        }
    }

    $application = Get-Value $createdBy "application"
    if ($null -ne $application) {
        return [pscustomobject]@{
            Id=Get-Value $application "id"; Type="Application"
            DisplayName=Get-Value $application "displayName"; UserPrincipalName=$null
            AppId=Get-Value $application "appId"
        }
    }
    return $empty
}

function Get-ApprovalInfo {
    param([AllowNull()][string]$ApprovalId)

    $empty = [pscustomobject]@{
        ApprovalId=$ApprovalId; ApprovalStatus=$null; ApprovalStepCount=0
        ApprovalReviewResults=$null; ApprovalReviewedUtc=$null; ApprovalJustifications=$null
        ApprovedByDisplayName=$null; ApprovedByUPN=$null; ApprovedById=$null
    }
    if (Test-Blank $ApprovalId) { return $empty }
    if ($ApprovalCache.ContainsKey($ApprovalId)) { return $ApprovalCache[$ApprovalId] }

    try {
        $uri = "{0}/roleManagement/directory/roleAssignmentApprovals/{1}" -f $GraphBeta,$ApprovalId
        $approval = Invoke-GraphGet -Uri $uri
        $steps = @()
        $stepValue = Get-Value $approval "steps"
        if ($null -ne $stepValue) { $steps = @($stepValue) }

        $names=@(); $upns=@(); $ids=@(); $results=@(); $times=@(); $reasons=@()
        foreach ($step in $steps) {
            if (-not (Test-Blank $step.reviewResult)) { $results += [string]$step.reviewResult }
            if ($null -ne $step.reviewedDateTime) { $times += ConvertTo-UtcText $step.reviewedDateTime }
            if (-not (Test-Blank $step.justification)) { $reasons += [string]$step.justification }

            $reviewer = $step.reviewedBy
            if ($null -eq $reviewer) { continue }
            $id = [string](Get-Value $reviewer "id")
            $name = [string](Get-Value $reviewer "displayName")
            $upn = [string](Get-Value $reviewer "userPrincipalName")

            if (-not (Test-Blank $id)) {
                $resolved = Get-Principal -Id $id
                if (Test-Blank $name) { $name = [string]$resolved.DisplayName }
                if (Test-Blank $upn) { $upn = [string]$resolved.UserPrincipalName }
                $ids += $id
            }
            if (-not (Test-Blank $name)) { $names += $name }
            if (-not (Test-Blank $upn)) { $upns += $upn }
        }

        $result = [pscustomobject]@{
            ApprovalId=$ApprovalId; ApprovalStatus=Get-Value $approval "status"; ApprovalStepCount=$steps.Count
            ApprovalReviewResults=(($results|Select-Object -Unique)-join '; ')
            ApprovalReviewedUtc=(($times|Select-Object -Unique)-join '; ')
            ApprovalJustifications=(($reasons|Select-Object -Unique)-join '; ')
            ApprovedByDisplayName=(($names|Select-Object -Unique)-join '; ')
            ApprovedByUPN=(($upns|Select-Object -Unique)-join '; ')
            ApprovedById=(($ids|Select-Object -Unique)-join '; ')
        }
    }
    catch {
        Write-Log "WARN" ("Could not retrieve approval {0}. {1}" -f $ApprovalId,$_.Exception.Message)
        $result = $empty
    }
    $ApprovalCache[$ApprovalId] = $result
    return $result
}

function Get-CorrelationKey {
    param([string]$PrincipalId,[string]$RoleId,[string]$ScopeId)
    if (Test-Blank $ScopeId) { $ScopeId = "/" }
    return "{0}|{1}|{2}" -f $PrincipalId,$RoleId,$ScopeId
}

function Get-AssignmentStart {
    param($Instance,$Schedule)
    $created = Get-Value $Schedule "createdDateTime"
    if ($null -ne $created) {
        return [pscustomobject]@{Value=ConvertTo-UtcText $created;Source="Schedule.createdDateTime"}
    }
    return [pscustomobject]@{Value=ConvertTo-UtcText $Instance.startDateTime;Source="Instance.startDateTime"}
}

function Resolve-Origin {
    param($Schedule,[hashtable]$RequestById,[hashtable]$FallbackByKey,[string]$PrincipalId,[string]$RoleId,[string]$ScopeId)
    $request=$null; $method=$null
    if ($null -ne $Schedule) {
        $createdUsing=[string](Get-Value $Schedule "createdUsing")
        if ((-not (Test-Blank $createdUsing)) -and $RequestById.ContainsKey($createdUsing)) {
            $request=$RequestById[$createdUsing]; $method="Schedule.createdUsing"
        }
    }
    if ($null -eq $request) {
        $key=Get-CorrelationKey $PrincipalId $RoleId $ScopeId
        if ($FallbackByKey.ContainsKey($key)) {
            $request=$FallbackByKey[$key]; $method="FallbackLatestAdminAssignByPrincipalRoleScope"
        }
    }
    return [pscustomobject]@{Request=$request;Method=$method}
}

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Microsoft.Graph.Authentication is missing. Run Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item $OutputFolder -ItemType Directory -Force | Out-Null }

$scopes = @(
    "RoleManagement.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "Directory.Read.All"
)
$connect = @{Scopes=$scopes;ContextScope="Process";NoWelcome=$true}
if (-not (Test-Blank $TenantId)) { $connect.TenantId=$TenantId }
if ($UseDeviceCode) { $connect.UseDeviceCode=$true }

try {
    Connect-MgGraph @connect
    $context=Get-MgContext
    Write-Log "INFO" ("Connected to tenant {0} as {1}" -f $context.TenantId,$context.Account)

    $missingScopes=@($scopes|Where-Object{@($context.Scopes)-notcontains $_})
    if ($missingScopes.Count -gt 0) { throw "Missing Graph consent: $($missingScopes -join ', ')" }

    Write-Log "INFO" "Reading PIM data"
    $roles=@(Get-GraphCollection("$GraphV1/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn")|Sort-Object displayName)
    $roleById=@{}; foreach($item in $roles){$roleById[[string]$item.id]=$item}
    $active=Get-GraphCollection("$GraphV1/roleManagement/directory/roleAssignmentScheduleInstances?`$select=id,principalId,roleDefinitionId,directoryScopeId,assignmentType,memberType,startDateTime,endDateTime,roleAssignmentScheduleId")
    $eligible=Get-GraphCollection("$GraphV1/roleManagement/directory/roleEligibilityScheduleInstances?`$select=id,principalId,roleDefinitionId,directoryScopeId,memberType,startDateTime,endDateTime,roleEligibilityScheduleId")
    $activeSchedules=Get-GraphCollection("$GraphV1/roleManagement/directory/roleAssignmentSchedules?`$select=id,createdDateTime,createdUsing,principalId,roleDefinitionId,directoryScopeId,assignmentType")
    $eligibleSchedules=Get-GraphCollection("$GraphV1/roleManagement/directory/roleEligibilitySchedules?`$select=id,createdDateTime,createdUsing,principalId,roleDefinitionId,directoryScopeId,memberType")
    $assignmentRequests=Get-GraphCollection("$GraphV1/roleManagement/directory/roleAssignmentScheduleRequests?`$select=id,action,status,createdDateTime,completedDateTime,principalId,roleDefinitionId,directoryScopeId,justification,targetScheduleId,approvalId,createdBy")
    $eligibilityRequests=Get-GraphCollection("$GraphV1/roleManagement/directory/roleEligibilityScheduleRequests?`$select=id,action,status,createdDateTime,completedDateTime,principalId,roleDefinitionId,directoryScopeId,justification,targetScheduleId,createdBy")

    $activeScheduleById=@{};foreach($x in $activeSchedules){$activeScheduleById[[string]$x.id]=$x}
    $eligibleScheduleById=@{};foreach($x in $eligibleSchedules){$eligibleScheduleById[[string]$x.id]=$x}
    $assignmentRequestById=@{};foreach($x in $assignmentRequests){$assignmentRequestById[[string]$x.id]=$x}
    $eligibilityRequestById=@{};foreach($x in $eligibilityRequests){$eligibilityRequestById[[string]$x.id]=$x}
    $successful=@("Provisioned","Granted","ScheduleCreated")
    $activeFallback=@{};$eligibleFallback=@{}
    foreach($x in @($assignmentRequests|Where-Object{$_.action-eq"adminAssign"-and$successful-contains[string]$_.status}|Sort-Object createdDateTime -Descending)){$k=Get-CorrelationKey ([string]$x.principalId)([string]$x.roleDefinitionId)([string]$x.directoryScopeId);if(-not$activeFallback.ContainsKey($k)){$activeFallback[$k]=$x}}
    foreach($x in @($eligibilityRequests|Where-Object{$_.action-eq"adminAssign"-and$successful-contains[string]$_.status}|Sort-Object createdDateTime -Descending)){$k=Get-CorrelationKey ([string]$x.principalId)([string]$x.roleDefinitionId)([string]$x.directoryScopeId);if(-not$eligibleFallback.ContainsKey($k)){$eligibleFallback[$k]=$x}}

    $eligibleOriginByKey=@{}
    foreach($x in $eligibleSchedules){$k=Get-CorrelationKey([string]$x.principalId)([string]$x.roleDefinitionId)([string]$x.directoryScopeId);$o=Resolve-Origin $x $eligibilityRequestById $eligibleFallback ([string]$x.principalId)([string]$x.roleDefinitionId)([string]$x.directoryScopeId);if($o.Request-and-not$eligibleOriginByKey.ContainsKey($k)){$eligibleOriginByKey[$k]=$o}}

    Write-Log "INFO" "Building activation history and approval details"
    $activationRows=@()
    foreach($request in @($assignmentRequests|Where-Object{$_.action-eq"selfActivate"}|Sort-Object createdDateTime -Descending)){
        $role=$null;if($roleById.ContainsKey([string]$request.roleDefinitionId)){$role=$roleById[[string]$request.roleDefinitionId]}
        $principal=Get-Principal([string]$request.principalId);$creator=Get-RequestCreator $request;$approval=Get-ApprovalInfo([string]$request.approvalId)
        $activationRows += [pscustomobject]@{
            TenantId=$context.TenantId;RequestId=$request.id;RequestCreatedUtc=ConvertTo-UtcText $request.createdDateTime;RequestCompletedUtc=ConvertTo-UtcText $request.completedDateTime;Status=$request.status;Action=$request.action
            RoleName=if($role){$role.displayName}else{$null};RoleDefinitionId=$request.roleDefinitionId;PrincipalDisplayName=$principal.DisplayName;UserPrincipalName=$principal.UserPrincipalName;PrincipalId=$principal.Id;PrincipalType=$principal.Type
            DirectoryScopeId=$request.directoryScopeId;Justification=$request.justification;TargetScheduleId=$request.targetScheduleId;RequestedByDisplayName=$creator.DisplayName;RequestedByUPN=$creator.UserPrincipalName;RequestedById=$creator.Id;RequestedByType=$creator.Type;RequestedByAppId=$creator.AppId
            ApprovalId=$approval.ApprovalId;ApprovalStatus=$approval.ApprovalStatus;ApprovalStepCount=$approval.ApprovalStepCount;ApprovalReviewResults=$approval.ApprovalReviewResults;ApprovalReviewedUtc=$approval.ApprovalReviewedUtc;ApprovalJustifications=$approval.ApprovalJustifications;ApprovedByDisplayName=$approval.ApprovedByDisplayName;ApprovedByUPN=$approval.ApprovedByUPN;ApprovedById=$approval.ApprovedById
        }
    }
    $lastActivation=@{};foreach($x in $activationRows){if($successful-notcontains[string]$x.Status){continue};$k="{0}|{1}"-f$x.PrincipalId,$x.RoleDefinitionId;if(-not$lastActivation.ContainsKey($k)){$lastActivation[$k]=$x}}

    $assignmentRows=@();$rolesWithAssignments=@{}
    foreach($kind in @("Active","Eligible")){
        if($kind-eq"Active"){$instances=$active;$scheduleMap=$activeScheduleById;$requestMap=$assignmentRequestById;$fallback=$activeFallback}else{$instances=$eligible;$scheduleMap=$eligibleScheduleById;$requestMap=$eligibilityRequestById;$fallback=$eligibleFallback}
        foreach($instance in $instances){
            $roleId=[string]$instance.roleDefinitionId;if(-not$roleById.ContainsKey($roleId)){continue};$rolesWithAssignments[$roleId]=$true;$role=$roleById[$roleId];$principal=Get-Principal([string]$instance.principalId)
            $scheduleId=if($kind-eq"Active"){[string]$instance.roleAssignmentScheduleId}else{[string]$instance.roleEligibilityScheduleId};$schedule=$null;if((-not(Test-Blank $scheduleId))-and$scheduleMap.ContainsKey($scheduleId)){$schedule=$scheduleMap[$scheduleId]}
            $assigned=Get-AssignmentStart $instance $schedule
            if($kind-eq"Active"-and[string]$instance.assignmentType-eq"Activated"){$key=Get-CorrelationKey([string]$instance.principalId)$roleId([string]$instance.directoryScopeId);if($eligibleOriginByKey.ContainsKey($key)){$eo=$eligibleOriginByKey[$key];$origin=[pscustomobject]@{Request=$eo.Request;Method="Eligibility.$($eo.Method)"}}else{$origin=[pscustomobject]@{Request=$null;Method=$null}}}else{$origin=Resolve-Origin $schedule $requestMap $fallback ([string]$instance.principalId)$roleId([string]$instance.directoryScopeId)}
            $req=$origin.Request;$creator=Get-RequestCreator $req;$lastKey="{0}|{1}"-f$instance.principalId,$roleId;$last=$null;if($lastActivation.ContainsKey($lastKey)){$last=$lastActivation[$lastKey]}
            $assignmentRows += [pscustomobject]@{TenantId=$context.TenantId;RoleName=$role.displayName;RoleDefinitionId=$roleId;IsBuiltIn=$role.isBuiltIn;PrincipalDisplayName=$principal.DisplayName;UserPrincipalName=$principal.UserPrincipalName;PrincipalId=$principal.Id;PrincipalType=$principal.Type;UserType=$principal.UserType;AccountEnabled=$principal.AccountEnabled;AssignmentType=$kind;ActiveInstanceType=if($kind-eq"Active"){$instance.assignmentType}else{$null};MemberType=$instance.memberType;DirectoryScopeId=$instance.directoryScopeId;AssignmentStartUtc=ConvertTo-UtcText $instance.startDateTime;AssignmentEndUtc=ConvertTo-UtcText $instance.endDateTime;AssignedOnUtc=$assigned.Value;AssignedOnSource=$assigned.Source;AssignedByDisplayName=$creator.DisplayName;AssignedByUPN=$creator.UserPrincipalName;AssignedById=$creator.Id;AssignedByType=$creator.Type;AssignedByAppId=$creator.AppId;AssignmentCorrelationMethod=$origin.Method;AssignmentRequestId=if($req){$req.id}else{$null};AssignmentRequestAction=if($req){$req.action}else{$null};AssignmentRequestStatus=if($req){$req.status}else{$null};AssignmentRequestCreatedUtc=if($req){ConvertTo-UtcText $req.createdDateTime}else{$null};AssignmentJustification=if($req){$req.justification}else{$null};LastActivationRequestUtc=if($last){$last.RequestCreatedUtc}else{$null};LastActivationStatus=if($last){$last.Status}else{$null}}
        }
    }

    if($IncludeRolesWithoutAssignments){foreach($role in $roles){$roleId=[string]$role.id;if($rolesWithAssignments.ContainsKey($roleId)){continue};$assignmentRows += [pscustomobject]@{TenantId=$context.TenantId;RoleName=$role.displayName;RoleDefinitionId=$roleId;IsBuiltIn=$role.isBuiltIn;PrincipalDisplayName=$null;UserPrincipalName=$null;PrincipalId=$null;PrincipalType=$null;UserType=$null;AccountEnabled=$null;AssignmentType="None";ActiveInstanceType=$null;MemberType=$null;DirectoryScopeId="/";AssignmentStartUtc=$null;AssignmentEndUtc=$null;AssignedOnUtc=$null;AssignedOnSource=$null;AssignedByDisplayName=$null;AssignedByUPN=$null;AssignedById=$null;AssignedByType=$null;AssignedByAppId=$null;AssignmentCorrelationMethod=$null;AssignmentRequestId=$null;AssignmentRequestAction=$null;AssignmentRequestStatus=$null;AssignmentRequestCreatedUtc=$null;AssignmentJustification=$null;LastActivationRequestUtc=$null;LastActivationStatus=$null}}}

    $assignmentFile=Join-Path $OutputFolder "Entra-PrivilegedRoleAssignments.csv";$activationFile=Join-Path $OutputFolder "Entra-PIMActivationHistory.csv";$summaryFile=Join-Path $OutputFolder "Entra-PIMReport-Summary.json"
    $assignmentRows|Sort-Object RoleName,AssignmentType,PrincipalDisplayName|Export-Csv $assignmentFile -NoTypeInformation -Encoding UTF8
    $activationRows|Sort-Object RequestCreatedUtc -Descending|Export-Csv $activationFile -NoTypeInformation -Encoding UTF8
    [ordered]@{TenantId=$context.TenantId;GeneratedUtc=(Get-Date).ToUniversalTime().ToString("o");PrivilegedRoleDefinitions=$roles.Count;ActiveAssignments=@($assignmentRows|Where-Object{$_.AssignmentType-eq"Active"}).Count;EligibleAssignments=@($assignmentRows|Where-Object{$_.AssignmentType-eq"Eligible"}).Count;ActivationRequests=$activationRows.Count;ActivationRequestsWithApproval=@($activationRows|Where-Object{-not(Test-Blank $_.ApprovalId)}).Count;AssignmentReport=$assignmentFile;ActivationHistoryReport=$activationFile;ApprovalApiNote="Approval details use Microsoft Graph beta roleAssignmentApprovals."}|ConvertTo-Json -Depth 5|Set-Content $summaryFile -Encoding UTF8
    Write-Log "SUCCESS" "Report completed";Write-Host "Assignments: $assignmentFile";Write-Host "Activation history: $activationFile";Write-Host "Summary: $summaryFile"
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
