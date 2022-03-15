if(description)
{   
    script_name("TI-Connector Detection"); 
    script_oid("1.3.6.1.4.1.25623.1.0.552074"); 
    script_version("1.2.6");
    script_tag(name:"last_modification", value:"2020-12-26 15:38:14 +0000 (Sat, 26 Dec 2020)");
    script_tag(name:"creation_date", value:"2020-12-11 13:09:34 +0000 (Fri, 11 Dec 2020)"); 
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N"); 

    script_tag(name:"qod_type", value:"remote_banner");
    script_tag(name:"impact", value:"TLSMandatory: If the value is set to 'false', communication between the client and the TI connector may take place in plain text. This enables man-in-the-middle attacks on the connector communication.
    
    ClientAutMandatory: If the value is set to 'false', every reachable client can communicate with the connector without authentication. An attacker in the same network could pose as a legitimate connector client.");
    
    script_tag(name:"solution_type", value:"VendorFix");
    script_tag(name:"solution", value:"TLSMandatory: The TI connector should be configured for mandatory TLS use. The clients must be configured accordingly for TLS communication.
    
    ClientAutMandatory: The TI connector should be configured for mandatory authentication. The clients must be configured accordingly with the assigned access data or certificates.");

    script_tag(name:"summary", value:"TI-Connector detection and settings validation.

    The script sends an HTTP-Request to ports 80 and 443 of the target and attempts to identify a TI-Connector by requesting the connector.sds file.
    The TLSMandatory and ClientAutMandatory tags in the file will be checked for their attributes.");

    script_category(ACT_GATHER_INFO);
    
    script_copyright("Copyright (C) 2020 Greenbone Networks GmbH"); 
    script_family("Product detection");  

    exit(0);
}

include("http_func.inc");

portlist = make_list(80, 443); # Ports to scan

tlsm_pattern = "<ns2:TLSMandatory>(.*)<\/ns2:TLSMandatory>";
cam_pattern = "<ns2:ClientAutMandatory>(.*)<\/ns2:ClientAutMandatory>";
http_status_pattern = "^HTTP\/1.[0-1] 200 OK";

# extracts ProductVendorID, ProductType, ProductTypeVersion and returns a string
function get_info(r){
    vendorid_pattern = "<ProductVendorID>(.*)<\/ProductVendorID>";
    vendor_array = eregmatch(pattern:vendorid_pattern, string:r, icase:TRUE, multiline:TRUE);

    if(vendor_array){
        vendor = vendor_array[1];
    }else{
        vendor = "NOT FOUND";
    }

    producttype_pattern = "<ProductType>(.*)<\/ProductType>";
    producttype_array = eregmatch(pattern:producttype_pattern, string:r, icase:TRUE, multiline:TRUE);
    
    if(producttype_array){
        producttype = producttype_array[1];
    }else{
        producttype = "NOT FOUND";
    }

    producttypeversion_pattern = "<ProductTypeVersion>(.*)<\/ProductTypeVersion>";
    producttypeversion_array = eregmatch(pattern:producttypeversion_pattern, string:r, icase:TRUE, multiline:TRUE);

    if(producttypeversion_array){
        producttypeversion = producttypeversion_array[1];
    }else{
        producttypeversion = "NOT FOUND";
    }

    msg = string("ProductVendorID: ",vendor,"\nProductType: ",producttype,"\nProductTypeVersion: ",producttypeversion);

    return msg;
}

foreach port (portlist){

    soc = open_sock_tcp(port, transport:0); # 0: auto-detect encaps
    if(!soc){ # check whether the connection to the target was successful
        display("Error: Cannot connect to port: ", port);
        continue;
    }

    display("Port ", port, " is reachable");
    req = http_get(item:"/connector.sds", port:port);
    r = http_send_recv(data:req, port:port); # send http request and wait for response

    close(soc);
    #display("Data: \n", r);

    # check http status code
    if(!ereg(pattern:http_status_pattern, string:r, icase:TRUE, multiline:FALSE)){ # icase:TRUE = case-insensitive, multiline:FALSE = stop reading after new line
        display("No connector.sds received. Probably no TI-Connector.");
        continue;
    }
    
    info = get_info(r);
    
    # check TLSMandatory attribute
    tlsm_array = eregmatch(pattern:tlsm_pattern, string:r, icase:TRUE, multiline:TRUE);
    if(tlsm_array){
        if(tolower(tlsm_array[1]) == "false"){
            smsg_data = string("TI-Connector detected!\nTLSMandatory attribute is set to: false","\n\n",info);
            security_message(port:port, data:smsg_data);
        }
        else if(tolower(tlsm_array[1]) == "true"){
            lmsg_data = string("TI-Connector detected!\nTLSMandatory attribute is set to: true","\n\n",info);
            log_message(port:port, data:lmsg_data);
        }
        else{
            lmsg_data = string("TI-Connector detected!\nAttribute neither true nor false\nTLSMandatory attribute is set to: ",tlsm_array[1],"\n\n",info);
            log_message(port:port, data:lmsg_data);
        }
    }
    else{ # if tlsmandatory is not found, the target is probably not a ti-connector
        display("TLSMandatory not found. Probably no TI-Connector");
        continue;
    }
    
    # Check ClientAutMandatory attribute
    cam_array = eregmatch(pattern:cam_pattern, string:r, icase:TRUE, multiline:TRUE);
    if(cam_array){
        if(tolower(cam_array[1]) == "false"){
            smsg_data = string("TI-Connector detected!\nClientAutMandatory attribute is set to: false","\n\n",info);
            security_message(port:port, data:smsg_data);
        }
        else if(tolower(cam_array[1]) == "true"){
            lmsg_data = string("TI-Connector detected!\nClientAutMandatory attribute is set to: true","\n\n",info);
            log_message(port:port, data:lmsg_data);
        }
        else{
            lmsg_data = string("TI-Connector detected!\nAttribute neither true nor false\nClientAutMandatory attribute is set to: ",cam_array[1],"\n\n",info);
            log_message(port:port, data:lmsg_data);
        }
    }
    else{
        lmsg_data = string("TI-Connector detected!\nClientAutMandatory not found","\n\n",info);
        log_message(port:port, data:lmsg_data);
    }
}    

exit(0);
