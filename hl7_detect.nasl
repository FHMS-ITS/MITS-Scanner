

if(description)
{
    script_name("HL7 Detection");
    script_oid("1.3.6.1.4.1.25623.1.0.552075"); 
    script_version("1.1");
    script_tag(name:"last_modification", value:"2021-03-05 02:30:56 +0000 (Fri, 05 Mar 2021)");
    script_tag(name:"creation_date", value:"2021-01-15 04:17:27 +0000 (Wed, 20 May 2020)"); 
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");            

    script_tag(name:"qod_type", value:"remote_banner"); # https://docs.greenbone.net/GSM-Manual/gos-6/en/glossary.html

    script_tag(name:"impact", value:"If an ACK message is received the HL7-Interface is available for everyone in the same network. An attacker can cause damage by manuplating sensitive data if no further authentication is required.");
    
    script_tag(name:"solution_type", value:"VendorFix");
    script_tag(name:"solution", value:"The HL7-Interface should be configured for mandatory TLS use and for mandatory authentication. The clients must be configured accordingly for TLS communication and authentication.");

    script_tag(name:"summary", value:"HL7-Interface detection.
    The script sends a HL7 ADT message wrapped in MLLP to ports 6661, 6667, 22222 of the target and attempts to identify a HL7-Interface by triggering an HL7 ACK message.
    The Sending Application, Sending Facility and Version ID fields will be checked for their attributes.");
    

    script_category(ACT_GATHER_INFO); # http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-1-SECT-11.html

    script_copyright("Copyright (C) 2021 Greenbone Networks GmbH"); 
    script_family("Product detection");  

    exit(0);
}

# default ports of tools:
# 6661 mirth connect, 
# 21110 7edit,
# 2007, 9001, 10200 blackhat demo
# 6667 ukm mirth connect default
# 22222 hl7-soup

portlist = make_list(6661, 6667, 22222); # Ports to scan

# msg from hl7 scanner github repo. Without dreceiving facility
msg = raw_string(0x0b)+"MSH|^~\&|Openvas|Testsuite|||200911021022|SECURITY|ADT^A01|MSG00001-|P|2.3"+raw_string(0x1c, 0x0d);

ack_pattern = "MSH\|(.*)\|ACK";

msh_pattern = "MSH\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(ACK[^|]*)\|([^|]*)\|([^|]*)\|(([0-9]*\.?[0-9])*)(.*)";


foreach port (portlist){

    soc = open_sock_tcp(port); # transport:0: auto-detect encaps
    if(!soc){ # check whether the connection to the target was successful
        display("Error: Cannot connect to port: ", port);
        continue;
    }
    
    display("Port ", port, " is reachable");
    send(socket:soc, data:msg);

    r = recv(socket:soc, length:4096);
    close(soc);
    display("Data: \n", r);

    # check response. pattern ...MSH...ACK...
    if(!ereg(pattern:ack_pattern, string:r, icase:TRUE, multiline:TRUE)){ # icase:TRUE = case-insensitive, multiline:FALSE = stop reading after new line
        display("No ACK message received. Probably no HL7-Interface.");
        continue;
    }
    
    # extract values from message header
    msh_fields = eregmatch(pattern:msh_pattern, string:r, icase:TRUE, multiline:TRUE);
        if(msh_fields){
            for(i = 0; i < 14; i++){
                display("res[", i, "]: ", msh_fields[i]);
            }

            msh3 = string("MSH.3 Sending Application: ", msh_fields[2], "\r\n");
            msh4 = string("MSH.4 Sending Facility: ", msh_fields[3], "\r\n");
            msh12 = string("MSH.12 Version: ", msh_fields[11], "\r\n");
            smsg = string(msh3, msh4, msh12);

            security_message(port:port, data:smsg);
        }
        else{ # response does not match with specification
            lmsg = string("Could not parse Message Header.");
            log_message(port:port, data:lmsg);
            continue;
        }  
}    

exit(0);
