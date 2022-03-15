FROM immauss/openvas:21.4.4-06

EXPOSE 9392

RUN mkdir -p /usr/local/var/lib/openvas/plugins/private
COPY openvas_plugins/* /usr/local/var/lib/openvas/plugins/private/

############################################
# ADD DICOM SCRIPTS TO NMAP ################
############################################

ADD nmap-files-dicom/dicom.lua /usr/share/nmap/nselib/dicom.lua
ADD nmap-files-dicom/dicom-ping.nse /usr/share/nmap/scripts/dicom-ping.nse
ADD nmap-files-dicom/dicom-brute.nse /usr/share/nmap/scripts/dicom-brute.nse

############################################
# ADD DICOM TOOLKIT ########################
############################################
RUN apt update
RUN apt install -y dcmtk

############################################
# INSTALL PIP + DEPS #######################
############################################

RUN apt update
RUN apt install -y python3-dev python3-setuptools gcc default-jre

RUN pip3 install nameko requests xmltodict python-gvm eventlet python-nmap netifaces peewee

RUN export PYTHONPATH="${PYTHONPATH}:/opt/mits/scan_service/"

############################################
# COPY MITS Service Files ##################
############################################

ADD mits_service /opt/mits
