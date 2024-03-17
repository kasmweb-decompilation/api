# api
Kasm API decompiled from 1.15.0 docker image.

## Info so far:
* Container is based off of Ubuntu Focal.
* Startup Command:
```json
"Created": "2024-03-05T22:18:50.063048571Z",
"Path": "/bin/sh",
"Args": [
"-c",
"/usr/bin/startup.sh -s /usr/bin/kasm_server.so -c /opt/kasm/current/conf/app/api.app.config.yaml -p \"--enable-admin-api --enable-client-api --enable-public-api\""],
```
* `kasmweb/api` container just runs `kasm_server.so`
* `kasm_server.so` is a PyInstaller binary
