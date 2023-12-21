# Recebe o nome do ficheiro csv como parâmetro
Param(
    [Parameter(Mandatory = $true)]
    [string]$csvFile
)

# Importa o módulo Active Directory
Import-Module ActiveDirectory

# Lê o ficheiro csv e guarda os usersList numa variável
$usersList = Import-Csv -Delimiter ';' $csvFile

$today = Get-Date

# Percorre os usersList e cria os utilizadores na Active Directory
foreach ($user_csv in $usersList)
{
    #     $groups = Get-ADGroup -Filter * | Where-Object { $_.Name -notlike "*Domain Users*" -and $_.Name -notlike "*Domain Admins*" }

    # Get user based on UID from the csv
    $user = Get-ADUser -Filter "EmployeeID -eq $( $user_csv.ID )"

    # If user doesnt exists continoue to next user
    if ($user -eq $Null)
    {
        echo "User id $( $user_csv.ID ) doesn't  exist"
        continue
    }

    # Get contract end date from excel
    $contract_end_date = Get-Date -Date $user_csv.end_contract_date

    if ($contract_end_date -lt $today)
    {
        echo ($user.SAMAccountName + " contract is over")
        # Get user groups
        $user_groups = Get-ADUser -Identity $user.SAMAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf | Get-ADGroup
#        $user_groups = Get-ADUser $user.SAMAccountName -Properties MemberOf

        foreach ($user_group in $user_groups) {
            Remove-ADGroupMember -Identity $user_group -Members $user.SAMAccountName -Confirm:$false
            echo ("Removed user " +  $user.SAMAccountName + " from " + $user_group)
        }

        # Disable user account
        Disable-ADAccount -Identity $user.SAMAccountName
        echo ( $user.SAMAccountName + " account disabled")

    }

}

