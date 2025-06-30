Write-Host 'Starting CIS SQL Server Audit Checks (1-36)...' -ForegroundColor Cyan
$results = @()
$connectionString = 'Server=localhost;Database=master;Trusted_Connection=True;'
function Run-Check {
    param([string]$Id, [string]$Name, [string]$Remediation, [string]$Query)
    $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
    $command = $connection.CreateCommand()
    $command.CommandText = $Query
    try {
        $connection.Open()
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
        $table = New-Object System.Data.DataTable
        $adapter.Fill($table) | Out-Null
        $results += [PSCustomObject]@{
            ID = $Id; Check = $Name; Remediation = $Remediation; Result = ($table | Out-String).Trim()
        }
    } catch {
        $results += [PSCustomObject]@{
            ID = $Id; Check = $Name; Remediation = $Remediation; Result = 'ERROR: ' + $_.Exception.Message
        }
    } finally {
        $connection.Close()
    }
}
Run-Check -Id '1' -Name "Ensure Latest SQL Server Service Packs and Hotfixes" -Remediation "Install the latest SQL Server Service Pack and cumulative update." -Query "SELECT SERVERPROPERTY('ProductLevel') AS SP_installed, SERVERPROPERTY('ProductVersion') AS Version;"
Run-Check -Id '2' -Name "Ensure 'Ad Hoc Distributed Queries' is set to '0'" -Remediation "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"
Run-Check -Id '3' -Name "Ensure 'CLR Enabled' is set to '0'" -Remediation "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'clr enabled';"
Run-Check -Id '4' -Name "Ensure 'Cross DB Ownership Chaining' is set to '0'" -Remediation "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining';"
Run-Check -Id '5' -Name "Ensure 'Database Mail XPs' is set to '0'" -Remediation "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs';"
Run-Check -Id '6' -Name "Ensure 'Ole Automation Procedures' is set to '0'" -Remediation "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
Run-Check -Id '7' -Name "Ensure 'Remote Access' is set to '0'" -Remediation "EXEC sp_configure 'remote access', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'remote access';"
Run-Check -Id '8' -Name "Ensure 'Remote Admin Connections' is set to '0'" -Remediation "EXEC sp_configure 'remote admin connections', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'remote admin connections';"
Run-Check -Id '9' -Name "Ensure 'Scan for Startup Procs' is set to '0'" -Remediation "EXEC sp_configure 'scan for startup procs', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'scan for startup procs';"
Run-Check -Id '10' -Name "Ensure 'Trustworthy' bit is set to Off for All Databases" -Remediation "ALTER DATABASE <DatabaseName> SET TRUSTWORTHY OFF;" -Query "SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;"
Run-Check -Id '11' -Name "Ensure the Public Role in the msdb Database has the Default Permissions" -Remediation "REVOKE CONNECT FROM PUBLIC IN DATABASE msdb;" -Query "SELECT dp.class_desc, dp.permission_name, dp.state_desc FROM msdb.sys.database_permissions dp WHERE dp.grantee_principal_id = USER_ID('public');"
Run-Check -Id '12' -Name "Ensure the Public Role in the master Database has the Default Permissions" -Remediation "REVOKE CONNECT FROM PUBLIC IN DATABASE master;" -Query "SELECT dp.class_desc, dp.permission_name, dp.state_desc FROM master.sys.database_permissions dp WHERE dp.grantee_principal_id = USER_ID('public');"
Run-Check -Id '13' -Name "Ensure Windows Built-in Administrators Group is Not a SQL Server Login" -Remediation "DROP LOGIN [BUILTIN\Administrators];" -Query "SELECT name FROM sys.server_principals WHERE name LIKE '%BUILTIN\Administrators%';"
Run-Check -Id '14' -Name "Ensure SQL Authentication is Not Used" -Remediation "Use Windows Authentication or configure contained users as needed." -Query "SELECT name, type_desc FROM sys.server_principals WHERE type_desc = 'SQL_LOGIN';"
Run-Check -Id '15' -Name "Ensure Windows Groups are Used for SQL Server Access" -Remediation "Use Windows groups instead of individual users for SQL logins." -Query "SELECT name, type_desc FROM sys.server_principals WHERE type_desc = 'WINDOWS_GROUP';"
Run-Check -Id '16' -Name "Ensure Orphaned Users Are Reviewed and Removed" -Remediation "Use sp_change_users_login or ALTER USER with proper login." -Query "EXEC sp_change_users_login 'Report';"
Run-Check -Id '17' -Name "Ensure All SQL Server Authenticated Logins Have Been Assigned a Password Policy" -Remediation "ALTER LOGIN <login_name> WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;" -Query "SELECT name, is_policy_checked, is_expiration_checked FROM sys.sql_logins;"
Run-Check -Id '18' -Name "Ensure All Users are Assigned to a Server-Level Role" -Remediation "ALTER SERVER ROLE <role_name> ADD MEMBER <login>;" -Query "SELECT sp.name AS Login, slr.name AS Role FROM sys.server_role_members srm JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id JOIN sys.server_principals slr ON srm.role_principal_id = slr.principal_id;"
Run-Check -Id '19' -Name "Ensure the 'sa' Login Account is Disabled" -Remediation "ALTER LOGIN sa DISABLE;" -Query "SELECT name, is_disabled FROM sys.sql_logins WHERE name = 'sa';"
Run-Check -Id '20' -Name "Ensure SQL Server is Configured to Use Encrypted Connections" -Remediation "Enable Force Encryption in SQL Server Configuration Manager." -Query "EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', N'ForceEncryption';"
Run-Check -Id '21' -Name "Ensure Unnecessary SQL Server Protocols Are Disabled" -Remediation "Disable unused protocols via SQL Server Configuration Manager." -Query "EXEC xp_readerrorlog 0, 1, N'Server is listening on';"
Run-Check -Id '22' -Name "Ensure SQL Browser Service is Disabled if not Required" -Remediation "Disable SQL Server Browser in SQL Server Configuration Manager." -Query "EXEC xp_servicecontrol N'QUERYSTATE', N'SQLBrowser';"
Run-Check -Id '23' -Name "Ensure 'xp_cmdshell' is Disabled" -Remediation "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;" -Query "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
Run-Check -Id '24' -Name "Ensure Only Necessary SQL Server Services are Running" -Remediation "Use 'services.msc' to review and disable unneeded services." -Query "EXEC xp_servicecontrol 'QUERYSTATE', 'MSSQLServerOLAPService';"
Run-Check -Id '25' -Name "Ensure Database and Backup Files are Protected with Appropriate NTFS Permissions" -Remediation "Set NTFS permissions appropriately using icacls or Explorer." -Query "EXEC xp_cmdshell 'icacls "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Data"';"
Run-Check -Id '26' -Name "Ensure All SQL Server Logins are Reviewed Periodically" -Remediation "Review and disable/remove unused logins." -Query "SELECT name, type_desc, is_disabled FROM sys.server_principals;"
Run-Check -Id '27' -Name "Ensure Sensitive Data is Protected in Transit" -Remediation "Configure TLS and disable old protocols." -Query "SELECT protocol_desc FROM sys.dm_exec_connections;"
Run-Check -Id '28' -Name "Ensure Logging and Auditing are Enabled" -Remediation "Enable SQL Server Audit via SSMS or T-SQL." -Query "SELECT * FROM sys.server_audits;"
Run-Check -Id '29' -Name "Ensure Audit Logs are Protected from Tampering" -Remediation "Set file system permissions for audit file directory." -Query "SELECT audit_file_path FROM sys.dm_server_audit_status;"
Run-Check -Id '30' -Name "Ensure Backups are Encrypted" -Remediation "Use WITH ENCRYPTION option during backup." -Query "SELECT name, is_encrypted FROM msdb.dbo.backupset WHERE backup_finish_date > GETDATE()-30;"
Run-Check -Id '31' -Name "Ensure TLS 1.2 is Used and SSL/TLS is Configured Correctly" -Remediation "Update registry and force TLS 1.2 usage." -Query "EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server', 'Enabled';"
Run-Check -Id '32' -Name "Ensure Orphaned SQL Server Agent Jobs are Removed" -Remediation "Remove jobs without valid owners or purpose." -Query "SELECT name, owner_sid FROM msdb.dbo.sysjobs WHERE owner_sid NOT IN (SELECT sid FROM sys.syslogins);"
Run-Check -Id '33' -Name "Ensure SQL Server Agent is Monitored" -Remediation "Enable alerting and logging for agent activity." -Query "SELECT * FROM msdb.dbo.sysjobhistory WHERE run_status <> 1;"
Run-Check -Id '34' -Name "Ensure Transparent Data Encryption (TDE) is Enabled Where Appropriate" -Remediation "Enable TDE using CREATE DATABASE ENCRYPTION KEY, ALTER DATABASE ... SET ENCRYPTION ON." -Query "SELECT name, is_encrypted FROM sys.databases;"
Run-Check -Id '35' -Name "Ensure Separation of Duties Between DBA and Developers" -Remediation "Review and revise role assignments." -Query "SELECT sp.name, sp.type_desc FROM sys.server_principals sp WHERE sp.name NOT LIKE '##%';"
Run-Check -Id '36' -Name "Ensure SQL Server Error Logs are Retained and Reviewed" -Remediation "Configure log retention settings and review regularly." -Query "EXEC xp_readerrorlog;"
$results | Format-Table -AutoSize
$results | Export-Csv -Path './CIS_SQL_Audit_Report.csv' -NoTypeInformation
