import urllib.request

for path in ['/favicon.ico', '/hybridaction/zybTrackerStatisticsAction?data={}&__callback__=x']:
    url = f'http://127.0.0.1:5000{path}'
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            print(path, r.getcode())
    except Exception as e:
        print(path, 'ERROR', e)
