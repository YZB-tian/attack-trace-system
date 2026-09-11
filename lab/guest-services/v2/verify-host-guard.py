import json
import socket
import subprocess

results = []
for host, port, expected in [('192.168.56.1',23453,False),('192.168.56.40',8080,True)]:
    try:
        with socket.create_connection((host,port),timeout=3):
            connected=True
    except OSError:
        connected=False
    results.append(dict(host=host,port=port,connected=connected,expected=expected))
print(json.dumps(dict(results=results,routes=subprocess.check_output(['ip','route'],text=True))))
assert all(r['connected']==r['expected'] for r in results)
