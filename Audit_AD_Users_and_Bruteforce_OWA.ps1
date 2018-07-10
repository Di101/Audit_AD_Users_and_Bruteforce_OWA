
import-module activedirectory 
Import-Module ImportExcel
$domains = "you_domain.com"  , "sg.you_domain.com" ,"mx.you_domain.com"
$DaysInactive = 90
$DaysInactive_for_Created_users = 30
$time = (Get-Date).Adddays(-($DaysInactive))
$timefor_for_Created_users  = (Get-Date).Adddays(-($DaysInactive_for_Created_users))

$Users_need_attention = foreach ($domain in $domains)
    {
# Получаем всех включенных пользователей AD с lastLogonTimestamp меньше нашего времени.
$users_not_logon_90_days = Get-ADUser  -Server $domain -Filter {LastLogonTimeStamp -lt $time  -and enabled -eq $true} -Properties * `
| where {!($_.DistinguishedName -like "*CN=Microsoft Exchange System Objects,DC=8bitov,DC=com*") -and !($_.DistinguishedName -like '*OU=ServiceOU,DC=8bitov,DC=com*')}  `
| select  SamAccountName,CN,co,City , Department,Title, physicalDeliveryOfficeName,LastLogonDate,CanonicalName 
# Выгружаем включенных пользователей которые вообще не логинились. 
$users_never_logon = Get-ADUser  -Server $domain -Filter {LastLogonDate -notlike "*" -and enabled -eq $true -and whenCreated -lt $timefor_for_Created_users } -Properties * `
| where {!($_.DistinguishedName -like "*CN=Microsoft Exchange System Objects,DC=8bitov,DC=com*") -and !($_.DistinguishedName -like '*OU=ServiceOU,DC=8bitov,DC=com*')}  `
| select  SamAccountName,CN,co,City,Department,Title, physicalDeliveryOfficeName,LastLogonDate, whenCreated,CanonicalName 
#Выгружем включенных пользователей которые должны "изменить пароль при следующем входе" и когда-то логинились.
$users_need_chenge_pass = Get-ADUser  -Server $domain -Filter {pwdLastSet -eq "0" -and enabled -eq $true -and LastLogonDate -like "*" } -Properties *  `
| select   SamAccountName,CN,co,City , Department,Title, physicalDeliveryOfficeName,LastLogonDate, pwdLastSet

$users_for_brute_force =  $users_never_logon + $users_need_chenge_pass |  ForEach-Object {$_.SamAccountName } 
$Passwords = 'Qwerty123', 'Qwerty1234'

function Checkup_password_in_owa {

#Аuthor original function - Gowdhaman Karthikeyan (https://social.technet.microsoft.com/profile/Gowdhaman+Karthikeyan)

 $URL = 'https://post.you_domain.com/owa'
 $Username = $user_for_brute_force


#Initialize default values

$Result = $False
$StatusCode = 0
$Latency = 0

$Username_Full = $Domain + "\" + $Username

try{
#########################
#Work around to Trust All Certificates is is from this post

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
       }
   }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Initialize Stop Watch to calculate the latency.

$StopWatch = [system.diagnostics.stopwatch]::startNew()

#Invoke the login page
$Response = Invoke-WebRequest -Uri $URL -SessionVariable owa

#Login Page - Fill Logon Form

if ($Response.forms[0].id -eq "logonform") {
$Form = $Response.Forms[0]
$Form.fields.username= $Username_Full
$form.Fields.password= $Password
$authpath = "$URL/auth/owaauth.dll"
#Login to OWA
$Response = Invoke-WebRequest -Uri $authpath -WebSession $owa -Method POST -Body $Form.Fields
#SuccessfulLogin 
if ($Response.forms[0].id -eq "frm") {
  #Retrieve Status Code
  $StatusCode = $Response.StatusCode
  # Logoff Session
  $logoff = "$URL/auth/logoff.aspx?Cmd=logoff&src=exch"
  $Response = Invoke-WebRequest -Uri $logoff -WebSession $owa
  #Calculate Latency
  $StopWatch.stop()
  $Latency = $StopWatch.Elapsed.TotalSeconds
  $Result = $True
}
#Fill Out Language Form, if it is first login
elseif ($Response.forms[0].id -eq "lngfrm") {
  $Form = $Response.Forms[0]

  #Set Default Values
  $Form.Fields.add("lcid",$Response.ParsedHtml.getElementById("selLng").value)
  $Form.Fields.add("tzid",$Response.ParsedHtml.getElementById("selTZ").value)

  $langpath = "$URL/lang.owa"
  $Response = Invoke-WebRequest -Uri $langpath -WebSession $owa -Method $form.Method -Body $form.fields
  #Retrieve Status Code
  $StatusCode = $Response.StatusCode
  # Logoff Session
  $logoff = "$URL/auth/logoff.aspx?Cmd=logoff&src=exch"
  $Response = Invoke-WebRequest -Uri $logoff -WebSession $owa
  #Calculate Latency
  $StopWatch.stop()
  $Latency = $StopWatch.Elapsed.TotalSeconds
  $Result = $True
}
elseif ($Response.forms[0].id -eq "logonform") {
  #We are still in LogonPage
  #Retrieve Status Code
  $StatusCode = $Response.StatusCode
  #Calculate Latency
  $StopWatch.stop()
  $Latency = $StopWatch.Elapsed.TotalSeconds
  $Result = "Failed"
}
}

}

#Catch Exception, If any
catch
{
  #Retrieve Status Code
  $StatusCode = $Response.StatusCode
  if ($StatusCode -notmatch '\d\d\d') {$StatusCode = 0}
  #Calculate Latency
  $StopWatch.stop()
  $Latency = $StopWatch.Elapsed.TotalSeconds
  $Result = $_.Exception.Message
}

#Display Results
#Костыл с "1!" для корректного отображения контента в письме.

if ($StatusCode -eq '0'-and $Result -like 'False' ) {

$hacked_Users += "Получен парооль от УЗ $Username_Full $Password.1! " # Username: $Username_Full `nStatus Code: $StatusCode`nResult: $Result"
Write-Host "Получен парооль от УЗ $Username_Full $Password" -ForegroundColor red # Username: $Username_Full `nStatus Code: $StatusCode`nResult: $Result"
$hacked_Users


}
elseif ($StatusCode -eq '200'-and $Result -like 'False') {
$NOT_hacked_Users += "УЗ $Username_Full которым НЕ удалось подобрать пароль.1!"
Write-Host "$Username_Full $Password учетные данные не верны"
}
elseif ($StatusCode -eq '200'-and $Result -ne 'False') {
$NOT_hacked_Users += "УЗ $Username_Full которым НЕ удалось подобрать пароль $Password.1!"
$NOT_hacked_Users
Write-Host "$Username_Full $Password учетные данные не верны"
}

}

$BruteForce_result = foreach ($Password in $Passwords) {
foreach ($user_for_brute_force  in $users_for_brute_force) {

Checkup_password_in_owa }}

#Сохранить отчеты в директории с названием домена в html.

#Формируем HTML таблицу
$a = "<style>"
$a = $a + "BODY{background-color:peachpuff;}"
$a = $a + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$a = $a + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
$a = $a + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:PaleGoldenrod}"
$a = $a + "</style>"

#Выгружаем результат в HTML и xls файлы.

if (([string]::IsNullOrEmpty($users_not_logon_90_days)))
{
$users_not_logon_90_days = "" | Out-File C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_not_logon_90_days.html
}
else {
$users_not_logon_90_days | ConvertTo-Html -Head $a | Out-File C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_not_logon_90_days.html
$users_not_logon_90_days | Export-Excel C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\"$domain"_users_not_logon_90_days.xls
}


if (([string]::IsNullOrEmpty($users_never_logon)))
{
$users_never_logon = "" | Out-File C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_never_logon.html
}
else {

$users_never_logon | ConvertTo-Html -Head $a | Out-File C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_never_logon.html
$users_never_logon | Export-Excel C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\"$domain"_users_never_logon.xls
}

if (([string]::IsNullOrEmpty($users_need_chenge_pass)))
{
$users_need_chenge_pass = "" | Out-File C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_need_chenge_pass.html
}
else {

$users_need_chenge_pass | ConvertTo-Html -Head $a | Out-File C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_need_chenge_pass.html
$users_need_chenge_pass | Export-Excel C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\"$domain"_users_need_chenge_pass.xls
}

  #Обработка контента в письме.

  #Пользователи которые не логинилсь более 90 дней
 $users_not_logon_90_day_in_email = Get-Content C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_not_logon_90_days.html
 if (([string]::IsNullOrEmpty($users_not_logon_90_day_in_email)))
 {$users_not_logon_90_day_in_email = "Пользователи не обнаружены."
  
 }
 else {
 $users_not_logon_90_day_in_email_else = Get-Content C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_not_logon_90_days.html
 $users_not_logon_90_day_in_email = 'Пользователи которые не логились более 90 дней:
 '  +   $users_not_logon_90_day_in_email_else
 }

   #Пользователи никогда не логинились.
 $users_never_logon_in_email = Get-Content C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_never_logon.html
 if (([string]::IsNullOrEmpty($users_never_logon_in_email)))
 {$users_never_logon_in_email = "Пользователи которые никогда не логинились не обнаружены."
  
 }
 else {
 $users_never_logon_in_email_else = Get-Content C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_never_logon.html
 $users_never_logon_in_email = 'Пользователи которые никогда не логинились:
 '  +   $users_never_logon_in_email
 }

  #Пользователей которые должны "изменить пароль при следующем входе" и когда-то логинились.
$users_need_chenge_pass_in_email = Get-Content C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_need_chenge_pass.html
 if (([string]::IsNullOrEmpty($users_need_chenge_pass_in_email)))
 {$users_need_chenge_pass_email = "Пользователи которым нужно изменить пароль при следующем входе."
  
 }
 else {
 $users_need_chenge_pass_else = Get-Content C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\users_need_chenge_pass.html
 $users_need_chenge_pass_in_email = 'Пользователи которые должны изменить пароль при следующем входе:
 '  +   $users_need_chenge_pass_else
 }



#Отправляем письмо

$files = Get-ChildItem -Path "C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain" -File -Recurse -Include *.xls | Select -ExpandProperty FullName


$smtpServer = "mail1.you_domain.com"
$MailTo = 'you_email@you_domain.com'
$msg = new-object Net.Mail.MailMessage
$smtp = new-object Net.Mail.SmtpClient($smtpServer)
$gCont_1 =   $users_not_logon_90_day_in_email
$gCont_2 = $users_never_logon_in_email
$gCont_3 =  $users_need_chenge_pass_in_email
#Костыл с  <br> для корректного отображения контента в письме.
$gCont_4 = $BruteForce_result -replace '1!', " <br>" | Sort-Object -Property length | Out-String

$msg.From = "Users_need_attention@no-reply.com"
$msg.To.Add($MailTo)
foreach ($file in ($files))
{
        $Attachments = New-Object System.Net.Mail.Attachment ($file)
        $msg.Attachments.Add($Attachments)
     
}
   

$msg.Subject = $domain+" УЗ требующие внимания"
$msg.IsBodyHTML = $True
$msg.Body = $gCont_1  , '<br>' ,'<br>' , $gCont_2 , '<br>' ,'<br>' ,$gCont_3 ,   '<br>' , $gCont_4 

$smtp.Send($msg) 


$msg.Dispose()

Remove-Item -Path "C:\you_dir\scripts\audit_not_logon_users_and_users_default_pass\$domain\" -Filter *.xls  -recurse
#>
}
