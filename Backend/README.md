# MITS Backend Server with Web Socket support  

MITS Backend Server is a Flask server wrapped inside a docker container.  
This version supports Websockets and communication with client is possible.  

## Usage
```bash
 docker-compose build
 docker-compose up 
```

This server can run with TLS.

__To run with TLS:__
Replace dummy certificate (__cert.crt__) and key (__key.key__) (keep names) in ./nginx

## Login/Credentials
The Login page can be accessed at https://<your-url>/api/ui/frontend/login. Currently the server only has a single user (`User: admin, Password: au.cds@25.1_DmI`)
The login process requires Two-factor authentication using TOTP. A new device for TOTP can be added at https://<your-url>/api/ui/frontend/twofac.

## Commands
Return progress of all scans:
```bash
 get_progress
```
Return all scanranges:
```bash
 get_ips
```
Return all ipranges to exclude:
```bash
 get_exclude
```
Delete all scanranges:
```bash
 clean_ips
```
Delete all ipranges to exclude:
```bash
 clean_exclude
```
Start the scan:
```bash
 start_scan
```
Return all running processes:
```bash
 get_proc
```

## License
For License info, see the [GPL v3.0](GPL-3.0.md) license.