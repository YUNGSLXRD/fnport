# Sends Fortnite traffic (AWS in Europe) from this PC through the fnport virtual machine;
# everything else goes as before. Run in PowerShell as administrator:
#   .\fnport-routes.ps1             add the routes until the PC restarts
#   .\fnport-routes.ps1 -Persist    add them for good
#   .\fnport-routes.ps1 -Remove     take them away
param(
	[switch]$Persist,
	[switch]$Remove,
	[string]$Gateway = '192.168.56.2'
)

$prefixes = '3.0.0.0/8', '13.32.0.0/11', '15.0.0.0/8', '18.0.0.0/8', '35.156.0.0/14', '35.176.0.0/13'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
	[Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
	Write-Host 'Run PowerShell as administrator.' -ForegroundColor Red
	exit 1
}

# old routes through the machine, in both stores, go first: no duplicates, and -Remove is just this
foreach ($store in 'ActiveStore', 'PersistentStore') {
	Get-NetRoute -AddressFamily IPv4 -PolicyStore $store -ErrorAction SilentlyContinue |
		Where-Object { $_.NextHop -eq $Gateway -and $prefixes -contains $_.DestinationPrefix } |
		Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}
if ($Remove) {
	Write-Host 'Routes through the fnport machine removed.'
	exit 0
}

# the PC's adapter on the machine's network (VirtualBox host-only or Hyper-V internal switch)
$net = $Gateway -replace '\.\d+$', '.'
$if = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
	Where-Object { $_.IPAddress.StartsWith($net) -and $_.IPAddress -ne $Gateway } | Select-Object -First 1
if (-not $if) {
	Write-Host "No adapter in ${net}0/24: is the virtual machine running?" -ForegroundColor Red
	exit 1
}

# routes to a machine that is off would cut the game off: the adapter alone proves nothing,
# VirtualBox keeps its host-only adapter up with the machine stopped
if (-not (Test-Connection -ComputerName $Gateway -Count 2 -Quiet)) {
	Write-Host "The fnport machine ($Gateway) does not answer: start it first. No routes were added." -ForegroundColor Red
	exit 1
}

foreach ($p in $prefixes) {
	# without -PolicyStore a route goes into both stores: in use now and after a restart
	if ($Persist) {
		New-NetRoute -DestinationPrefix $p -InterfaceIndex $if.InterfaceIndex -NextHop $Gateway | Out-Null
	} else {
		New-NetRoute -DestinationPrefix $p -InterfaceIndex $if.InterfaceIndex -NextHop $Gateway -PolicyStore ActiveStore | Out-Null
	}
}
Write-Host ("Fortnite traffic now goes through the fnport machine ({0}){1}." -f $Gateway,
	$(if ($Persist) { ', also after a restart' } else { ' until the PC restarts' }))
