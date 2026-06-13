import urllib.request
import urllib.error

urls = [
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:5000/api/monitor/status",
    "http://127.0.0.1:5000/api/logs",
]

for u in urls:
    print("---", u)
    try:
        req = urllib.request.Request(u)
        with urllib.request.urlopen(req, timeout=5) as r:
            status = getattr(r, 'status', None) or r.getcode()
            print("status:", status)
            body = r.read(800).decode(errors='replace')
            print(body[:800])
    except urllib.error.HTTPError as e:
        print("HTTPError:", e.code)
        try:
            print(e.read(800).decode(errors='replace'))
        except Exception:
            pass
    except Exception as e:
        print("Error:", repr(e))
