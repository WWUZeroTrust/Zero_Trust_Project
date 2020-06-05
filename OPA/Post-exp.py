import requests


url = 'http://natas15.natas.labs.overthewire.org/index.php'
usr = 'natas15'
pas = 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'
payload = ""

req = request.post(url, data={'username':payload}, auth=(usr, pas))
