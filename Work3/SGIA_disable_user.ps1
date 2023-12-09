Param(
    [Parameter(Mandatory = $true)]
    [string]$userSAMAccountName
)

# Importa o módulo Active Directory
Import-Module ActiveDirectory

$user = Get-ADUser -Identity $userSAMAccountName

# If user doesnt exists continoue to next user
if ($user -eq $Null)
{
    echo "User id $( $user_csv.ID ) doesn't  exist"
    continue
}

$user_groups = Get-ADUser -Identity $user.SAMAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf | Get-ADGroup
#        $user_groups = Get-ADUser $user.SAMAccountName -Properties MemberOf

foreach ($user_group in $user_groups)
{
    Remove-ADGroupMember -Identity $user_group -Members $user.SAMAccountName -Confirm:$false
    echo ("Removed user " + ${$user.SAMAccountName} + "from " + $user_group)
}

# Disable user account
Disable-ADAccount -Identity $user.SAMAccountName
echo ($user.SAMAccountName + " Account disabled")