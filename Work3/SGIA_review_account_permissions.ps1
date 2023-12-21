# Recebe o nome do ficheiro csv como parâmetro
Param(
    [Parameter(Mandatory = $true)]
    [string]$csvFile
)

# Importa o módulo Active Directory
Import-Module ActiveDirectory

# Lê o ficheiro csv e guarda os usersList numa variável
$usersList = Import-Csv -Delimiter ';' $csvFile

# Percorre os usersList e cria os utilizadores na Active Directory
foreach ($user_csv in $usersList)
{
    #     $groups = Get-ADGroup -Filter * | Where-Object { $_.Name -notlike "*Domain Users*" -and $_.Name -notlike "*Domain Admins*" }

    # Get user based on UID from the csv
    $user = Get-ADUser -Filter "EmployeeID -eq $( $user_csv.ID )" -Properties *

    # If user doesnt exists continoue to next user
    if ($user -eq $Null)
    {
        echo "User id $( $user_csv.ID ) doesn't  exist"
        continue
    }

    # Build expected user OU
    $department = $user_csv.department.replace(' ', '_')
    $employeeType = $user_csv.employee_type.replace(' ', '_')
    $roleGroup = $department + "_" + $employeeType

    #expected user OU
    $roleTargetOU = "CN=$roleGroup,OU=Roles,OU=Groups,DC=iam,DC=local"
    echo ("Expected target OU for user " +  $user.SAMAccountName + " - " + $roleTargetOU)

    $users_member_of =  (Get-ADUser -Identity $user.SAMAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf)

    # Iterate over all members OU
    foreach ($user_group in $users_member_of) {
        # Check is the OU is expcted for this user
        # If not remove it
        if ($user_group -ne $roleTargetOU) {
            Remove-ADGroupMember -Identity $user_group -Members $user.SAMAccountName -Confirm:$false
            echo ("Removed user " +  $user.SAMAccountName + " from " + $user_group)
        }

    }
    # Add to OU if not yet
    if (-not ($users_member_of -contains $roleTargetOU)) {
        Add-ADGroupMember -Identity $roleGroup -Members $user.SAMAccountName
        echo ("User " +  $user.SAMAccountName + " Added to role group " + $user_group)
    }
}

