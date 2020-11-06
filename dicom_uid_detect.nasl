#To integrate the plugin into GVM System:
#1. Save the plugin in /opt/gvm/var/lib/openvas/plugins
#2. Increment "PLUGIN_FEED" counter in /opt/gvm/var/lib/openvas/plugins/plugin_feed_info.inc
#3. psql -q --pset pager=off gvmd -c "DELETE FROM meta where name = 'nvts_feed_version' OR name = 'nvts_check_time';" 
#4. openvas --update-vt-info
#5. The update of the plugin can take 2-5 minutes
# Status and errors can be found in :
# /opt/gvm/var/log/gvm/gvmd.log and /opt/gvm/var/log/gvm/openvas.log

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.308080"); 
  script_version("2020-05-20T07:50:38+0000");
  script_tag(name:"last_modification", value:"2020-05-20 07:50:38 +0000 (Wed, 20 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 03:57:07 +0000 (Wed, 20 May 2020)"); 
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");            

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DICOM Detection"); 

  script_tag(name:"summary", value:"Detection of Dicom Web Server.

  The script sends a connection request to the server and attempts to detect Dicom Web Server and to extract
  its version.");

  script_category(ACT_GATHER_INFO); 

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH"); 
  script_family("Product detection");  

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


portlist=make_list(104, 1112, 2761, 2762, 4242, 11112); #Ports which are scanned

foreach port (portlist){
	
	soc = open_sock_tcp(port);
	if(soc) {
		data = recv(soc:socket, length:1024); #Socket on a Port is opened


		send( socket:soc, data:'GET / HTTP/1.0\r\n\r\n' ); # A DICOM Server is indentified over a GET Request
		r = recv( socket:soc, length:4096 );
		close( soc );

		r_len = strlen( r );
		if( r_len == 0 ) {
			debug_print( 'Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n' );
			exit( 0 );
		}
		rhexstr = hexstr( r );
		if( rhexstr =~ "^(07000000000400000[0-2]0[0-6]){1,}$" ) {
			register_service( port:port, proto:"dicom", message:"A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
			log_message( port:port, data:"A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
					
			soc = open_sock_tcp(port);
			
			# If a DICOM server is identified, an A-ASSOCIATE-RQ is sent to the server to receive a A-ASSOCIATE-AC which includes the UID
	
			send( socket:soc, data:raw_string(0x01, 0x00, 0x00, 0x00, 0x00, 0xcd, 0x00, 0x01, 0x00, 0x00, 0x41, 0x4e, 0x59, 0x2d, 0x53, 0x43, 0x50, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x45, 0x43, 0x48, 0x4f, 0x53, 0x43, 0x55, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x15, 0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x33, 0x2e, 0x31, 0x2e, 0x31, 0x2e, 0x31, 0x20, 0x00, 0x00, 0x2e, 0x01, 0x00, 0xff, 0x00, 0x30, 0x00, 0x00, 0x11, 0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x31, 0x40, 0x00, 0x00, 0x11, 0x31, 0x2e, 0x32, 0x2e, 0x38, 0x34, 0x30, 0x2e, 0x31, 0x30, 0x30, 0x30, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x50, 0x00, 0x00, 0x3a, 0x51, 0x00, 0x00, 0x04, 0x00, 0x00, 0x40, 0x00, 0x52, 0x00, 0x00, 0x1b, 0x31, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x36, 0x2e, 0x30, 0x2e, 0x37, 0x32, 0x33, 0x30, 0x30, 0x31, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x32, 0x55, 0x00, 0x00, 0x0f, 0x4f, 0x46, 0x46, 0x49, 0x53, 0x5f, 0x44, 0x43, 0x4d, 0x54, 0x4b, 0x5f, 0x33, 0x36, 0x32));

			r = recv( socket:soc, length:4096 );
			close( soc );
			
			# Extraction of the UID:			
			
			rhexstr = hexstr( r );

			uid_ind = stridx( rhexstr, "520000", 0);
			sub_str = substr( rhexstr, uid_ind+6);
			len = sub_str[0] + sub_str[1];
			sub_str = substr(sub_str, 2);

			split_string=split(sub_str ,sep:"550000");


			rawstr = raw_string(r);

			rawstr=str_replace(string: rawstr, find: raw_string(0x00), replace: raw_string(0x20));

			for(i = 0;i<3;i++){
				uid = eregmatch(pattern: "(([0-9]+)\.)+([0-9]+)", string:rawstr);
				rawstr=str_replace(string: rawstr, find: uid[0], replace: raw_string(0x20));
			}

			# if(uid[0] == "1.2.826.0.1.3680043.1.2.100.8.40.120.0"){
			#	report = "Bad Version !";  
			#	security_message(port: 104, data: report);
			#        exit(0);
			#}

			vers = "unknown";
			if( ! isnull( uid[0] ) ) {
				    vers = uid[0];
				  }

			# DICOM service is registered
			cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:dicom:dicom:" );
				if( !cpe )
				  cpe = "cpe:/a:dicom:dicom";

				install = port + "/tcp";
				register_product( cpe:cpe, location:install, port:port, service:"dicom" );

				log_message( data:build_detection_report( app:"dicom",
									  version:vers,
									  install:install,
									  cpe:cpe
									  ),
					port:port );
			}
	}

}

exit( 0 );
