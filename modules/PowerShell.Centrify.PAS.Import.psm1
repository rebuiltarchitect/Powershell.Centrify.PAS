
$scriptRoot = $PSScriptRoot
Import-Module $PSScriptRoot\PowerShell.ConnectRestApi.psm1   3>$null 4>$null

<# 
 .Synopsis
  Import CPS entities from a CSV file. 

 .Description

  .Parameter Endpoint
  Required - The target host for the call (i.e. https://cloud.centrify.com)

  .Parameter Token
  Required - Login token returned by the Centrify-Enroll 

  .Parameter CSVFileName
  Required - CSV file to be imported

  .Outputs
  Result   - None. The command creates a folder (name: Timestamp) and creates the following files
             FailedRows.csv   - Includes all failed to import rows.
             FailedRows.txt   - Import result for failed rows. 
             WarningRows.txt  - Import result for rows that are imported with some errors.
             AllRows.txt      - Import result for all rows
  .Example
  Centrify-AddAccount -Endpoint 'https://cloud.centrify.com'  -Token $token  -CSVFile 'cpsimport.csv'

#>

function Centrify-CPS-Import {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $endpoint,
        [Parameter(Mandatory=$true)]
        [string] $token,
        [Parameter(Mandatory=$true)]
        [string] $csvFile
    )

    #define the number of entities to be added in each API. 
    $systemeBatchCount = 20             # 50
    $domainBatchCount = 20              # 50
    $databaseBatchCount = 20            # 50
    $accountBatchCount = 10             # 10
    $setupAdminstratorUsersBatchCount = 30  # 50
  
    Write-Verbose "Importing CSV file: $csvFile" 

    $operations = @(
        @{'Id' = 'Domain'; 'API' = '/ServerManage/SetAccountPermissions' ; 'ResultType' = 'AddResult';  'MaximumEntities'= $domainBatchCount }
        @{'Id' = 'System'; 'API' = '/ServerManage/SetAccountPermissions'; 'ResultType' = 'AddResult'; 'MaximumEntities'= $systemeBatchCount }
        @{'Id' = 'Database'; 'API' = '/ServerManage/SetAccountPermissions'; 'ResultType' = 'AddResult';  'MaximumEntities'= $databaseBatchCount }
        @{'Id' = 'Account'; 'API' = '/ServerManage/AddAccounts'; 'ResultType' = 'AddResult';  'MaximumEntities'= $accountBatchCount }) 
    
    #check version
    $versionInfo = Centrify-InvokeREST  -Endpoint $endpoint -Method "/sysinfo/version" -Token $token -Verbose:$enableVerbose     
    $major,$minor,$v3=$versionInfo.Result.Cloud.split(".",3)
    Write-Verbose "Current Version: $major.$minor "    
    if ( $major -lt 18 -or ( $major -eq 18 -and $minor -lt 4 ))
    {
        #Write-Error "Minimum required version is 18.4"
        #return
    }
            
    #import the file
    $file = Import-CSV $csvfile

    # Add index and result place holder for rows
    $rows = [System.Collections.ArrayList]@()
    $rowIndex  = 1;
    foreach ($obj in $file)
    {
        # remove empty properties
        $obj.PsObject.Properties | Where-Object { -not $_.value } |
        ForEach-Object {
            $obj.psobject.Properties.Remove($_.name)
        }
        $null = $rows.Add(@{ 'Row' = $obj; 'RowIndex' = $rowIndex; 'RowResult' = @{'AddResult' = $null; 'SetUpAdministrativeAccountsResult' = $null} })
        $rowIndex++
    }

    #Call RestAPI one by one
    Write-Verbose ("Total number of rows in file: " + $rows.Count)
    foreach ($operation in $operations)
    {
        Write-Verbose ("Importing: {0}, API: {1}, maxmium batch count: {2}"  -f $operation.Id, $operation.API, $operation.MaximumEntities)
        Centrify-InternalImportCSVRows $endpoint $token $rows $operation
    }
    
    # group the results based on the result type
    $failedrows = @($rows | Where-Object  {(($_.RowResult.AddResult -eq  $null) -or (($_.RowResult.AddResult -ne  $null) -And ($_.RowResult.AddResult.Output.Result -eq "Failed")))})
    $successrows = @($rows | Where-Object {($_.RowResult.AddResult -ne  $null) -And ($_.RowResult.AddResult.Output.Result -eq "Success") -And ($_.RowResult.SetUpAdministrativeAccountsResult.Output.Result -ne  "Failed")})
    $warningsrows = @($rows | where { ($successrows -notcontains $_ ) -And ($failedrows -notcontains $_ ) }) | Sort-Object { [int]$_.rowIndex }
  
    # start processing results.
    # create a folder with date and time
    $date = get-date -format "yyyyMMdd_HHmmss"
    $exampleRootDir = (Convert-Path (Split-Path $csvfile))

    $resultDir = "$exampleRootDir\$date"
    New-Item $resultDir -ItemType directory
   
    #create ouput files
    $summary = Centrify-InternalCreateImportSummary $csvfile $rows $failedrows $warningsrows $successrows
    Write-Verbose $summary
    try
    {
        #Create failed CSV file
        if ($failedrows -ne $null)
        {
            Get-Content $csvfile -First 1 | Out-File $resultDir\FailedRows.CSV
            $failedrows.Row | Export-Csv -Path $resultDir\FailedRows.CSV -Delimiter ',' -NoTypeInformation -Force -append
        }

        #Create failedrows.txt. This file list failed rows and the reason for failure
        New-Item $resultDir\FailedRows.txt -ItemType file -Value  $summary
        Add-Content $resultDir\FailedRows.txt   -Value "-----------Failed rows-----------"    
        $failedrows | ForEach-Object { Centrify-InternalImportResult($_) | Add-Content $resultDir\FailedRows.txt -Encoding UTF8 }
      
        #Create warningrows.txt. This file list all rows that are imported with some warnings         
        New-Item $resultDir\WarningRows.txt -ItemType file -Value  $summary
        Add-Content $resultDir\WarningRows.txt  -Value "-----------Rows added with some errors-----------"
        $warningsrows| ForEach-Object { Centrify-InternalImportResult($_) | Add-Content $resultDir\WarningRows.txt -Encoding UTF8 }

        #create allRows.txt. This file list all rows               
        New-Item $resultDir\AllRows.txt -ItemType file -Value  $summary
        Add-Content $resultDir\AllRows.txt  -Value "-----------All rows-----------"
        $rows |  ForEach-Object { Centrify-InternalImportResult($_) | Add-Content $resultDir\AllRows.txt  -Encoding UTF8}
    } 
    catch
    {
        Write-Warning ("Error : " + $_.Exception.Message)        
    } 

    Write-Verbose "CSV file $csvFile is imported and the result is saved in folder $resultDir"
}


function Centrify-FindAdminAccounts
{
    Param([Parameter(position=0)] [REF]$selectedadminrows)

    #find all admin account set entities
    $adminEntities = @($allrows | Where-Object {$_.Row.AdministrativeAccountUser -ne $null})
    #find all admin accounts
    $accountrows = @($allrows | Where-Object {($_.Row.EntityType -eq 'Account')} )
    Write-Verbose("Number accounts: {0}" -f  $accountrows.Count)
    $outItems = New-Object System.Collections.Generic.List[System.Object]
    $parentEntityType, $parenttobematched     
    foreach($adminEntity in $adminEntities) { 
        $user, $domain = $adminEntity.Row.AdministrativeAccountUser.split("@")
        if ($domain -ne $null) # administrative user is a domain account 
        {
            $parentEntityType = 'Domain'
            $parenttobematched = $domain
        }
        else
        {
            $parentEntityType = 'System'
            $parenttobematched = $adminEntity.Row.Name
        }
        foreach($account in $accountrows) {
            if ($user -eq $account.Row.User -and $parenttobematched -eq $account.Row.ParentEntityNameOfAccount -and $parentEntityType -eq  $account.Row.ParentEntityTypeOfAccount )
            {
                $outItems.Add($account)
                break;
            }
        }                    
    }
    Write-Verbose("# admin accounts : {0}" -f  $outItems.Count)
    $selectedadminrows.Value = @($outItems | Sort-Object -Property @{Expression={$_.RowIndex}} -Unique)
    Write-Verbose("# unique admin accounts : {0}" -f  $selectedadminrows.Value.Count)
}


#Internal function. Run specified operation on rows
function Centrify-InternalImportCSVRows
{
   Param(
        [Parameter(position=0)]
        [string] $endpoint,
        [Parameter(position=1)]
        [string] $token,
        [parameter(position=2)]
        $allrows,
        [parameter(position=3)]
        $operation 
    )

    Write-Verbose ("Operation {0}" -f  $operation.Id)

    #seperate rows based on its type
    $restArg = @{}
    switch ($operation.Id) 
    { 
        'System' { $selectedrows = @($allrows | Where-Object {$_.Row.EntityType -eq 'System'}) } 
        'Domain' { $selectedrows = @($allrows | Where-Object {$_.Row.EntityType -eq 'Domain'}) } 
        'Database' { $selectedrows = @($allrows | Where-Object {$_.Row.EntityType -eq 'Database'}) }
        'AdminAccount' { # Get all admin accounts
                $selectedrows  = @()     
                Centrify-FindAdminAccounts([REF]$selectedrows)
                Write-Verbose("Total # Admin accounts to be created: {0}" -f  $selectedrows.Count)
         }
        'Account' {  # get all non admin accounts
                $selectedrows = @($allrows | Where-Object {($_.Row.EntityType -eq 'Account')} ) 
                Write-Verbose("Total # accounts to be created: {0}" -f  $selectedrows.Count)
                $alreadyCreatedAccounts  = @()     
                Centrify-FindAdminAccounts([REF]$alreadyCreatedAccounts)
                Write-Verbose("# accounts already created: {0}" -f  $alreadyCreatedAccounts.Count) 
                foreach($addedaccount in $alreadyCreatedAccounts) {
                    $selectedrows = @($selectedrows | Where-Object { $addedaccount.RowIndex -notcontains $_.RowIndex })
                }
                Write-Verbose("# accounts to be created: {0}" -f  $selectedrows.Count)                           
         }
        'AdministrativeAccountUser' { $selectedrows = @($allrows | Where-Object {$_.Row.AdministrativeAccountUser -ne $null}) } 
         default {}
    }

    Write-Verbose("Number of rows to be processed: {0}" -f  $selectedrows.Count)

    #process the rows batch by batch
    $startIndex = 0;            
    while ($startIndex -lt $selectedrows.Count)
    {
        $stopIndex = $startIndex + ($operation.MaximumEntities - 1)
        if ($stopIndex -ge $selectedrows.Count) { $stopIndex = $selectedrows.Count -1 }
        Write-Host "Start index " $startIndex ", StopIndex  " $stopIndex ", TimeStamp  "  (Get-Date -format MM/dd/yy` hh:mm:ss)

        # create a batch of rows
        $batchrows = $selectedrows[$startIndex..$stopIndex]

        # filter only required param for the API
        switch ($operation.Id) 
        { 
            'System' { $restArg.Resources = @($batchrows.Row) } 
            'Domain' {  $restArg.Domains = @($batchrows.Row) } 
            'Database' { $restArg.Databases = @($batchrows.Row) } 
            'Account' {  $restArg.Accounts = @($batchrows.Row) }
            'AdminAccount' {  $restArg.Accounts = @($batchrows.Row) } 
            'AdministrativeAccountUser' {
                $restArg.AdministrativeAccounts = [System.Collections.ArrayList]@()
                ForEach ($rw in $batchrows.Row) {
                    $restArg.AdministrativeAccounts.Add([PSCustomObject]@{
                        TargetType = $rw.EntityType
                        Name = $rw.Name
                        AdministrativeAccount = $rw.AdministrativeAccountUser
                    })                    
                }
             } 
             default {}
        }

        $operationResult = @{Result = @{}}

        try
        { 
            # make the API call.                   
            $operationResult = Centrify-InvokeREST -Endpoint $endpoint -Method $operation.API -Token $token -ObjectContent $restArg -Verbose:$enableVerbose
        } 
        catch
        {
            # some unknown exception and the whole API call failed(none of input row is processed). Copy the exception as result for each row
            $tempresults = @()
            Write-Warning ("API: " + $operation.API  + " failed. Error: " + $_.Exception.Message)
            ForEach ($item In $batchrows)
            {
                $failedResult = [PSCustomObject]@{'Output' = [PSCustomObject]@{ Result = 'Failed'
                                                ID = ''
                                                ErrorMessages = @($_.Exception.Message)}}
                $tempresults += $failedResult
            } 
            $operationResult.Result = $tempresults               
        }
        
        if ($operationResult.success -ne $true)
        {
            Write-Error "Server error: $($operationResult.Message)"
        } 

        # update the Row result
        $counter = 0;
        ForEach ($result in $operationResult.Result)
        {
            if ($operation.Id -eq "AdministrativeAccountUser")
            { 
                $batchrows[$counter].RowResult.SetUpAdministrativeAccountsResult = $result
            }
            else
            {
                $batchrows[$counter].RowResult.AddResult = $result
            }
            $counter++;
        }
        # update index
        $startIndex = $stopIndex + 1
    }
    Write-Verbose ("Rows to be processed: {0}, Number of rows processed {1}" -f  $selectedrows.Count, ($StopIndex+1))
}

#Internal function. Creates import summary
function Centrify-InternalCreateImportSummary
{

   Param(
    [parameter(position=0)]
    $csvfile,
    [parameter(position=1)]
    $allRows, 
    [parameter(position=2)]
    $failedrows, 
    [parameter(position=3)]
    $warningsrows, 
    [parameter(position=4)]
    $successrows 
   )

    $NEWLINE = "`r`n"

    $summary =   "-----------SUMMARY-----------"  + $NEWLINE    
    $summary +=  "CSV file name: "  + $csvfile  + $NEWLINE
    $summary +=  "Number of entities in csv file: "  + $rows.Count + $NEWLINE
    $summary +=  "  Systems: "  + @($allRows | Where-Object {$_.Row.EntityType -eq 'System'}).Count + $NEWLINE
    $summary +=  "  Domains: "  + @($allRows | Where-Object {$_.Row.EntityType -eq 'Domain'}).Count + $NEWLINE
    $summary +=  "  Databases: "  + @($allRows | Where-Object {$_.Row.EntityType -eq 'Database'}).Count + $NEWLINE
    $summary +=  "  Accounts: "  + @($allRows | Where-Object {$_.Row.EntityType -eq 'Account'}).Count + $NEWLINE + $NEWLINE      

    $summary +=  "Total number of successfully imported entities: "  + $successrows.Count + $NEWLINE
    $summary +=  "  Systems: "  + @($successrows | Where-Object {$_.Row.EntityType -eq 'System'}).Count + $NEWLINE
    $summary +=  "  Domains: "  + @($successrows | Where-Object {$_.Row.EntityType -eq 'Domain'}).Count + $NEWLINE
    $summary +=  "  Databases: "  + @($successrows | Where-Object {$_.Row.EntityType -eq 'Database'}).Count + $NEWLINE
    $summary +=  "  Accounts: "  + @($successrows | Where-Object {$_.Row.EntityType -eq 'Account'}).Count + $NEWLINE + $NEWLINE

    $summary +=  "Total number of imported entities with warning: "  + $warningsrows.Count + $NEWLINE
    $summary +=  "  Systems: "  + @($warningsrows | Where-Object {$_.Row.EntityType -eq 'System'}).Count + $NEWLINE
    $summary +=  "  Domains: "  + @($warningsrows | Where-Object {$_.Row.EntityType -eq 'Domain'}).Count + $NEWLINE
    $summary +=  "  Databases: "  + @($warningsrows | Where-Object {$_.Row.EntityType -eq 'Database'}).Count + $NEWLINE
    $summary +=  "  Accounts: "  + @($warningsrows | Where-Object {$_.Row.EntityType -eq 'Account'}).Count + $NEWLINE + $NEWLINE
    
    $summary +=  "Total number of failed entities: "  + $failedrows.Count + $NEWLINE
    $summary +=  "  Systems: "  + @($failedrows | Where-Object {$_.Row.EntityType -eq 'System'}).Count  + $NEWLINE
    $summary +=  "  Domains: "  + @($failedrows | Where-Object {$_.Row.EntityType -eq 'Domain'}).Count + $NEWLINE
    $summary +=  "  Databases: "  + @($failedrows | Where-Object {$_.Row.EntityType -eq 'Database'}).Count + $NEWLINE
    $summary +=  "  Accounts: "  + @($failedrows | Where-Object {$_.Row.EntityType -eq 'Account'}).Count + $NEWLINE + $NEWLINE 

    return $summary
}

function Centrify-InternalImportResult
{
   Param(
        [parameter(position=0)]
        $row 
    )
    $NEWLINE = "`r`n"

    # Find identifying columns 
    if ($row.Row.EntityType -eq 'Account')
    { 
        $identifier = "User: " + $row.Row.User
    }
    else
    { 
        $identifier ="Name: "  + $row.Row.Name
    }

    # Append 'Add...' API result
    $rowString = "Row Index: " + $row.RowIndex + $NEWLINE
    $rowString += ("EntityType: {0}, {1}" -f  $row.Row.EntityType, $identifier + $NEWLINE)
    if ( $row.RowResult.AddResult -ne $null)
    {
        $entityid = ''
        if ( $row.RowResult.AddResult.Output.Result -ne 'Failed') 
        {
            $entityid = ", Entity Id: " + $row.RowResult.AddResult.Output.ID
        }
        $rowString +=   "Add Result: " + $row.RowResult.AddResult.Output.Result + $entityid +  $NEWLINE 
    }
     
    # Append setupadministrator API result 
    if ( $row.RowResult.SetUpAdministrativeAccountsResult -ne $null)
    {   
        $rowString +=   "SetupAdministrativeAccount Result: " + $row.RowResult.SetUpAdministrativeAccountsResult.Output.Result + $NEWLINE 
    } 

    #Add  errors 
    $rowString += "Errors : " + $NEWLINE

    $messages = [System.Collections.ArrayList]@()

    if ($row.RowResult.AddResult -ne $null) { $messages.AddRange($row.RowResult.AddResult.Output.ErrorMessages) }
    if ($row.RowResult.SetUpAdministrativeAccountsResult -ne $null) { $messages.AddRange($row.RowResult.SetUpAdministrativeAccountsResult.Output.ErrorMessages) }
    if ($messages.Count -gt  0) { $rowString += ($messages -join $NEWLINE);  $rowString += $NEWLINE }  
 
    return $rowString
}

Export-ModuleMember -function Centrify-CPS-Import
