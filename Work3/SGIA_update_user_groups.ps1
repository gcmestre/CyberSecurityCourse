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

    $department = $user_csv.department.replace(' ', '_')
    $employeeType = $user_csv.employee_type.replace(' ', '_')

    if ($user.department -eq $user_csv.department -and $user.Title -eq $user_csv.employee_type)
    {
        # The user is still in the same department
        # Move to next user
        continue
    }

    echo ("User " + $user.SAMAccountName + " Changed department")

    # Remove user from old department group
    $department = $user.department.replace(' ', '_')
    $employeeType = $user.Title.replace(' ', '_')
    $roleGroup = $department + "_" + $employeeType

    $roleTargetOU = "CN=$roleGroup,OU=Roles,OU=Groups,DC=iam,DC=local"

    # Remove user from OU
    Remove-ADGroupMember -Identity $roleTargetOU -Members $user.SAMAccountName -Confirm:$false
    echo ("Removed user " + $user.SAMAccountName + " from " + $roleTargetOU)


    # From excel info set the new group OU the user should be in
    # This was the same logic of the first work to create the user OU
    $department = $user_csv.department.replace(' ', '_')
    $employeeType = $user_csv.employee_type.replace(' ', '_')
    $roleGroup = $department + "_" + $employeeType

    $roleTargetOU = "CN=$roleGroup,OU=Roles,OU=Groups,DC=iam,DC=local"
    # Add user to OU
    $roleOU = Get-ADGroup -Filter { DistinguishedName -eq $roleTargetOU }

    # The groups the user should be from excel
    # Add user to new group
    Add-ADGroupMember -identity $roleOU -Members $user.SAMAccountName
    echo ("Add user " + $user.SAMAccountName + " to " + $roleOU)

    # Update user department and title
    Set-ADUser -Identity $user.SAMAccountName -Title $user_csv.employee_type -Department $user_csv.department

    # Move user to new OU
    $userTargetOU = "OU=$department,OU=User Accounts,DC=iam,DC=local"
    Get-ADUser -Identity $user.SAMAccountName | Move-ADObject -TargetPath $userTargetOU


}

