import urllib.request

for path in ['/dashboard', '/admin']:
    url = f'http://127.0.0.1:5000{path}'
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            html = r.read().decode(errors='replace')
            print(path, r.status, 'adminLink' in html)
            if path == '/dashboard':
                print('snippet:', html[html.index('id="adminLink"')-40:html.index('id="adminLink"')+80] if 'id="adminLink"' in html else 'none')
    except Exception as e:
        print(path, 'ERROR', e)
