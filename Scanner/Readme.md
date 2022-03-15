# MITS - OpenVAS Scanner 20.08

This is the Docker-based OpenVas scanner. The Docker image is used by https://hub.docker.com/r/immauss/openvas and is subject to the __GNU Affero__ license.

The components developed for this purpose in the __docker/mits_service__ directory and the OpenVAS plugins in __docker/openvas_plugins__ are subject to the GNU v3 (https://www.gnu.org/licenses/gpl-3.0.html) license.

## Change/Update
Update the `token.txt` file by generating a new token for the scanner in the backend service and copying it into the file.

## Configuration
The configuration can be modified in the file `config.py` which is located at `./docker/mits_service/scan_service`. After a change the container must be rebuilt.

## Install/Use
```
docker-compose build
docker-compose up -d
```

After all the components have been downloaded and OpenVas has been initialized, the web interface can be accessed via the link `http://localhost:8080` with the default credentials __admin/admin__.

## License
### Files in ./docker/mits_service && ./docker/openvas_plugins
For License info, see the [GPL v3.0](GPL-3.0.md) license.

### OpenVAS Scanner from immauss/openvas
This is the Docker-based OpenVAS scanner. The Docker image is used by https://hub.docker.com/r/immauss/openvas and is subject to the [GNU Affero](https://github.com/immauss/openvas/blob/master/LICENSE) license.