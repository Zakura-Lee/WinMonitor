import urllib.request
u='http://127.0.0.1:5000/dashboard'
with urllib.request.urlopen(u, timeout=5) as r:
    html=r.read().decode(errors='replace')
    print('len', len(html))
    print('has adminLink', 'id="adminLink"' in html)
    print(html.splitlines()[:60])
