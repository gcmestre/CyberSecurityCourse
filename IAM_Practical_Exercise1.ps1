# Recebe o nome do ficheiro csv como parâmetro
Param(
    [Parameter(Mandatory=$true)]
    [string]$csvFile
)

function Generate-SecurePassword {
    #múltiplos arrays de caracteres
    $uppercase = "ABCDEFGHKLMNOPRSTUVWXYZ".ToCharArray() 
    $lowercase = "abcdefghiklmnoprstuvwxyz".ToCharArray() 
    $number = "0123456789".ToCharArray() 
    $special = "$%&#!".ToCharArray() 

    #cria uma password base
    $password =($uppercase | Get-Random -count 2) -join ''
    $password +=($lowercase | Get-Random -count 4) -join ''
    $password +=($number | Get-Random -count 2) -join ''
    $password +=($special | Get-Random -count 2) -join ''

    $password_array=$password.ToCharArray() 
    $scrambled_password=($password_array | Get-Random -Count 10) -join ''

    return $scrambled_password
}

function Set-SAMAccountName {
    param (
        [string] $first_name,
        [string] $last_name
    )

    $lengh = 1
    $index = 0
    $samAccountName = ($first_name.Substring(0, 1) + $last_name).ToLower()
    while (Get-ADUser -Filter {SamAccountName -eq $samAccountName}) {
        # User with the same SamAccountName exists
        if ($index -gt 0) {
            $end = "$index"
        } else {
            $end = ""
        }
        if ($length -lt $first_name.length) {
            $length ++
        } else {
            $index ++
        }
        $samAccountName = ($first_name.Substring(0, $length) + $last_name).ToLower() + $end
    }

    return $samAccountName
}

# Importa o módulo Active Directory
Import-Module ActiveDirectory

# Lê o ficheiro csv e guarda os usersList numa variavel
$usersList = Import-Csv -Delimiter ';' $csvFile

# Percorre os usersList e cria os utilizadores na Active Directory
foreach ($user in $usersList) {
    $department = $user.department.replace(' ','_')
    $employeeType = $user.employee_type.replace(' ','_')
    $roleGroupName = $department + "_" + $employeeType

    $userTargetOU = "OU=$department,OU=User Accounts,DC=iam,DC=local"
    $roleTargetOU = "CN=$roleGroupName,OU=Roles,OU=Groups,DC=iam,DC=local"

    $parentUserOU = 'OU=User Accounts,DC=iam,DC=local'
    $parentRoleOU = 'OU=Roles,OU=Groups,DC=iam,DC=local'

    $userOU = Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $userTargetOU}
    if ($userOU -eq $null) {
        $userOU = New-ADOrganizationalUnit -Name $department -Path $parentUserOU

        # Remove a proteção de apagar acidentalmente apenas para testes pode-se apagar depois
        $userOU = Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $userTargetOU}
        $userOU.ProtectedFromAccidentalDeletion = $false
        Set-ADOrganizationalUnit -Instance $userOU
    } 

    $roleGroup = Get-ADGroup -Filter {DistinguishedName -eq $roleTargetOU} 
    if ($roleGroup -eq $null) {
        $roleGroup = New-ADGroup -Name $roleGroupName -Path $parentRoleOU -GroupScope Global

        
        # Remove a proteção de apagar acidentalmente apenas para testes pode-se apagar depois
        Set-ADObject -DistinguishedName $roleTargetOU -ProtectedFromAccidentalDeletion $false
    } 

    # Define user Paramenters

    $GivenName = $user.first_name
    $Surname = $user.last_name
    $DisplayName = $user.first_name + ' ' + $user.last_name

    $Title = $user.employee_type
    $Department = $user.department
    $Company = 'iam.local'

    $EmployeeID = $user.ID
    $EmployeeNumber = $user.indentification_number
    $EmployeeType = $user.employee_type

    $Mail = $UserPrincipalName
    $OtherMailbox = $user.personal_email

    $AccountExpirationDate = (Get-Date).AddDays(365)

    $Password =  ConvertTo-SecureString Generate-SecurePassword -AsPlainText -Force

    $ADUser = Get-ADUser -Filter {EmployeeID -eq $EmployeeID}
    if ($ADUser -eq $null) {
        $SAMAccountName = Set-SAMAccountName -first_name $user.first_name -last_name $user.last_name
        $UserPrincipalName = $SAMAccountName + "@" + "iam.local"
        
        # Create User
        New-ADUser -name $SAMAccountName -SamAccountName $SAMAccountName -UserPrincipalName $UserPrincipalName -AccountPassword $Password -Enabled $true `
                -ChangePasswordAtLogon $true -GivenName $GivenName -Surname $Surname -DisplayName $DisplayName `
                -Title $Title -Department $Department -Company $Company `
                -employeeID $EmployeeID -EmployeeNumber $EmployeeNumber `
                -EmailAddress $Mail -AccountExpirationDate $AccountExpirationDate `
                -path $userTargetOU  `
                -OtherAttributes @{
                    'EmployeeType'=$EmployeeType
                    'OtherMailbox'=$OtherMailbox
                }
        Add-ADGroupMember -identity $roleGroup -Members $SAMAccountName
    } else {
        $attributesToReplace = @{
                    'EmployeeType'=$EmployeeType
                    'OtherMailbox'=$OtherMailbox
        }
        
        $userParams = @{
            Identity                = $ADUser.DistinguishedName
            Enabled                 = $true
            ChangePasswordAtLogon   = $true
            GivenName               = $GivenName
            Surname                 = $Surname
            DisplayName             = $DisplayName
            Title                   = $Title
            Department              = $Department
            Company                 = $Company
            EmployeeNumber          = $EmployeeNumber
            EmailAddress            = $Mail
            AccountExpirationDate   = $AccountExpirationDate
            Replace                 = $attributesToReplace
        }
        Set-ADUser @userParams

        # Get the current group memberships of the user
        $currentGroups = Get-ADUser -Identity $ADUser.DistinguishedName -Properties MemberOf | Select-Object -ExpandProperty MemberOf
        
        # Remove the user from all groups except the target group
        foreach ($group in $currentGroups) {
            if ($group -ne $roleGroup) {
                Remove-ADGroupMember -Identity $group -Members $ADUser.DistinguishedName -Confirm:$false
                Write-Host "User removed from group: $group."
            }
        }

        # Add the user to the target group
        if (-not ($currentGroups -contains $roleGroup)) {
            Add-ADGroupMember -Identity $roleGroup -Members $ADUser.DistinguishedName
            Write-Host "User added to $roleGroup."
        }
    }


    # Remove otherMailbox EmployeeType


}

