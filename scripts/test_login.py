import requests

url = 'http://127.0.0.1:5000/api/login'
cred = {'username':'admin','password':'123456','user_type':'admin'}
resp = requests.post(url,json=cred)
print('login', resp.status_code, resp.text)
if resp.ok:
    token = resp.json().get('token')
    headers = {'Authorization':f'Bearer {token}'}
    r = requests.get('http://127.0.0.1:5000/api/monitor/status', headers=headers)
    print('/api/monitor/status', r.status_code, r.text)
    r2 = requests.post('http://127.0.0.1:5000/api/monitor/start', headers=headers)
    print('/api/monitor/start', r2.status_code, r2.text)
