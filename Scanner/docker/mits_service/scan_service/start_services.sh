#!/bin/bash

nameko run --config /opt/mits/scanfiles/nameko_config.yaml network_disc_service &
nameko run --config /opt/mits/scanfiles/nameko_config.yaml scan_service &
nameko run --config /opt/mits/scanfiles/nameko_config.yaml server_communicator_service &
nameko run --config /opt/mits/scanfiles/nameko_config.yaml tls_scan_service &

sleep 10

python3 scan_controler.py &

cd