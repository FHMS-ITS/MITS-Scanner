class Config(object):
    class Server(object):
        URL_STATUS = "https://<backend-url>/api/ext/process-status"
        URL_REPORT = "https://<backend-url>/api/ext/process-report"

    class Gvm(object):
        PATH_GVM_SOCKET = "/usr/local/var/run/gvmd.sock"
        AUTH_USER = "admin"
        AUTH_PASS = "admin" 
        LIMIT_FOR_TARGET = 4000
        MAX_PARALLEL = 5

        # Scan Config
        ID_PORT_LIST = "730ef368-57e2-11e1-a90f-406186ea4fc5"
        ID_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
        ID_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
        ID_XML_REPORT_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        ID_TIMESTAMP_REPORT_FORMAT = "5057e5cc-b825-11e4-9d0e-28d24461215b"

    class Local(object):
        PATH_TOKEN = "/opt/mits/scanfiles/creds/token.txt"
        PATH_SCANRANGES = "/opt/mits/scanfiles/scanranges.txt"
        PATH_EXCLUDE = "/opt/mits/scanfiles/exclude.txt"
        PATH_JSONREPORT = "/opt/mits/scanfiles/output/report.json"
        PATH_PREV_IPS = "/opt/mits/scanfiles/output/prev_ips.txt"
        PATH_FULL_REPORT = "/opt/mits/scanfiles/output/full_report.json"
        TAKE_PREV_IPS = False
        REPORT_PULL_TIME = 300  # seconds
        PROGRESS_PULL_TIME = 180  # seconds
        DELETE_ALL_GVM_TASKS = False

    class TLS(object):
        TLS_SCAN = True
        PATH_DATABASE = "/opt/mits/scanfiles/output/tls_report.txt"



