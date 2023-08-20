

$BaseUri='https://f-cyberark-pvwa.presidium.com/PasswordVault'
$URI = "$BaseURI/API/Safes?includeAccounts=false&offset=0&limit=4"
#send request to web service
		$result = Invoke-PASRestMethod -Uri $URI -Method GET -WebSession $Global:NewSessionObject 

$URL = $BaseUri +'/'+ $result.nextLink

$result = Invoke-PASRestMethod -Uri $URL -Method GET -WebSession $Global:NewSessionObject 
