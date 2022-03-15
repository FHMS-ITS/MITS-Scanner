import json
import pprint
import re
import string
import subprocess
import threading

from config import Config as conf
from nameko.rpc import rpc
from peewee import *

pp = pprint.PrettyPrinter(indent=4)

db = SqliteDatabase('report.db')


class BaseModel(Model):
    class Meta:
        database = db


class Report(BaseModel):
    text = CharField()
    json_rep = CharField()


db.connect()
db.create_tables([Report])


class Scan:
    name = "tls_scan_service"

    @rpc
    def initiate_scan(self, ips):
        print(ips)
        report_generation_thread = threading.Thread(target=self.start_scan, args=(ips,))
        report_generation_thread.start()
        print("started")
        return "Scan was started"

    def start_scan(self, ips):
        query = Report.delete()
        query.execute()

        rep_strings = [
            "[32m+++",
            "[32m",
            "[m",
            "[1A",
            "[2K",
            "[0m",
            "[0;1m[34m",
            "[33m",
            "[31m",
            "--|[0;1m[35m[4m"
        ]

        for ip in ips:
            print(ip)
            result = subprocess.check_output("java -jar /opt/mits/scan_service/TLS-Server-Scanner.jar -connect {}".format(ip), shell=True, timeout=144000)

            result = filter(lambda x: x in string.printable, result.decode('ascii'))
            final_result = []
            for i in result:
                final_result.append(i)

            result = ''.join(final_result)

            for rep in rep_strings:
                result = result.replace(rep, '')
            f = open(conf.TLS.PATH_REPORT, 'w+')

            f.write(result)
            f.close()

            new_report = Report.create(text=result, json_rep="")
            new_report.save()

            json_report = self.create_json_report(result)

            if json_report:
                res = (Report
                       .update({Report.json_rep: json_report})
                       .where(Report.text == result)
                       .execute())

    def create_json_report(self, report):
        DIVISION_STRING = "------------------------------------------------------------"
        OFFLINE_STRING = "Cannot reach the Server. Is it online?"
        IP_STRING = "Report for"
        USELESS_INFO_STRING = "INFO : Main - Performing Scan, this may take some time..."

        ip = "0"
        json_report = {}
        content = []
        offline = False
        header = ""
        full_report = {}
        for line in report.splitlines():
            if json_report and not header:
                header = line
            elif IP_STRING in line:
                ip = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line).group(0)
            elif line == OFFLINE_STRING:
                offline = True
                break
            elif line == DIVISION_STRING:
                if not header:
                    json_report.update({"general_info": content})
                else:
                    json_report.update({header: content})
                content = []
                header = ""
            elif not line or line == USELESS_INFO_STRING:
                continue
            else:
                clean_line = re.sub('\s+', '', line)
                content.append(clean_line)

        print(ip)
        if offline:
            return None
        else:
            full_report.update({ip: json_report})
            pp.pprint(full_report)
            return json.dumps(full_report)