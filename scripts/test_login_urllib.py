import json
import urllib.request

base='http://127.0.0.1:5000'
login_url=base+'/api/login'
cred={'username':'admin','password':'123456','user_type':'admin'}
req=urllib.request.Request(login_url, data=json.dumps(cred).encode(), headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print('login', r.status)
        body=r.read().decode()
        print(body)
        data=json.loads(body)
        token=data.get('token')
        if token:
            req2=urllib.request.Request(base+'/api/monitor/status', headers={'Authorization':f'Bearer {token}'})
            with urllib.request.urlopen(req2, timeout=10) as r2:
                print('/api/monitor/status', r2.status)
                print(r2.read().decode())
except urllib.error.HTTPError as e:
    print('HTTPError', e.code)
    try:
        print(e.read().decode())
    except:
        pass
except Exception as e:
    print('Error', e)
