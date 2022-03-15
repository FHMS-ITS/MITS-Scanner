import io
import json

import requests
import urllib3
from config import Config as conf
from nameko.rpc import rpc

from tls_report_models import db, Report

urllib3.disable_warnings()


class ServerCommunicator:
    name = "server_service"

    def get_auth_payload(self):
        f = open(conf.Local.PATH_TOKEN, "r")
        token = f.read()
        f.close()

        token = token.rstrip()

        auth_payload = {
            'Authorization': 'Bearer ' + token,

        }
        return auth_payload

    @rpc
    def send_status_message(self, status, is_progress):
        if is_progress:
            payload = {
                'status_msg': status,
                'msg_type': "process"
            }
        else:
            payload = {
                'status_msg': status,
                'msg_type': "other"
            }

        r = requests.post(conf.Server.URL_STATUS, data=payload, headers=self.get_auth_payload(), verify=False)
        return r.status_code

    # @rpc
    # def send_json_report(self, report, name):
    #     json_file = io.StringIO(report)
    #     report_file = {'report-json': ('{}.json'.format(name), json_file, 'application/json')}
    #     response = requests.post(conf.Server.URL_REPORT, files=report_file, headers=self.get_auth_payload(), verify=False)
    #     return response.status_code

    @rpc
    def send_json_report(self, report, name):
        try:
            f = open(conf.Local.PATH_JSONREPORT, 'r')
            openvas_report = f.read()
            f.close()
        except FileNotFoundError:
            return "Report no found"

        full_report = {}
        full_report.update({"openvas_report": json.loads(openvas_report)})

        if conf.TLS.TLS_SCAN:
            tls_reps = []
            for rep in Report.select():
                if rep.json_rep:
                    tls_reps.append(json.loads(rep.json_rep))

            full_report.update({"tls_report": tls_reps})

        f = open(conf.Local.PATH_FULL_REPORT, 'w+')
        json.dump(full_report, f)
        f.close()

        json_file = io.StringIO(json.dumps(full_report))

        report_file = {'report-json': ('{}.json'.format(name), json_file, 'application/json')}
        response = requests.post(conf.Server.URL_REPORT, files=report_file, headers=self.get_auth_payload())
        return response.status_code
