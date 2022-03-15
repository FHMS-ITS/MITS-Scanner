import base64
import io
import json
import os
import threading
from math import ceil

import xmltodict
from config import Config as conf
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
from lxml import etree
from nameko.rpc import rpc


class Scan:
    name = "scanner_service"

    @rpc
    def scanner_up(self):
        openvassd_stat = os.popen('ps aux | grep -E "gvmd" | grep -v grep').read()
        return 'Initializing' not in openvassd_stat

    def connect_to_gvm(self):
        connection = UnixSocketConnection(path=conf.Gvm.PATH_GVM_SOCKET)
        transform = EtreeTransform()
        return Gmp(connection, transform=transform)

    @rpc
    def start_scan(self, name, ips=[]):
        '''Starts scan for list of ips'''
        if not self.scanner_up():
            return json.dumps({'Error': 'Scanner has not started yet'})
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)

        LIMIT_FOR_TARGET = conf.Gvm.LIMIT_FOR_TARGET
        targets_num = ceil(len(ips) / LIMIT_FOR_TARGET)
        online_ips_limit = [[] for i in range(targets_num)]

        for i in range(len(online_ips_limit)):
            lower_bound = i * LIMIT_FOR_TARGET
            upper_bound = i * LIMIT_FOR_TARGET + LIMIT_FOR_TARGET
            if upper_bound > len(ips):
                upper_bound = len(ips)
            online_ips_limit[i] = ips[lower_bound:upper_bound]

        for i, ip in enumerate(online_ips_limit):
            gmp.create_target(name + "_" + str(i), hosts=ip, port_list_id=conf.Gvm.ID_PORT_LIST)
        targets = gmp.get_targets()
        target_ids = [targets.xpath("//target[name='{}']/@id".format(name + "_" + str(i))) for i in range(len(online_ips_limit))]
        for i in target_ids:
            pretty_print(gmp.create_task(name, config_id=conf.Gvm.ID_SCAN_CONFIG, scanner_id=conf.Gvm.ID_SCANNER, target_id=i[0]))
        tasks = gmp.get_tasks()
        tasks_ids = tasks.xpath("//task[name='{}']/@id".format(name))
        for task in tasks_ids:
            gmp.start_task(task)

        scan = {
            "target_ids": target_ids,
            "task_ids": tasks_ids,
            "ips": ips
        }
        return json.dumps(scan)

    @rpc
    def delete_all(self):
        '''Deletes all tasks, targets and reports'''
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)
        tasks = gmp.get_tasks()
        task_ids = tasks.xpath("//task/@id")

        for task_id in task_ids:
            gmp.delete_task(task_id)

        targets = gmp.get_targets()
        target_ids = targets.xpath("//target/@id")

        for tar_id in target_ids:
            gmp.delete_target(tar_id)

        gmp.empty_trashcan()
        deleted = {
            "task_ids": task_ids,
            "target_ids": target_ids
        }
        return json.dumps(deleted)

    @rpc
    def delete_tasks(self):
        '''Deletes all tasks'''
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)
        tasks = gmp.get_tasks()
        task_ids = tasks.xpath("//task/@id")

        deleted = {
            "task_ids": task_ids,
        }

        for task_id in task_ids:
            gmp.delete_task(task_id)
        return json.dumps(deleted)

    @rpc
    def get_task_progress(self, taskname):
        '''Returns scan progress for tasks with given taskname'''
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)
        tasks = gmp.get_tasks()
        task_progresses = tasks.xpath("//task/progress")
        progresses = []
        for progress in task_progresses:
            progresses.append(progress.text)
        return progresses

    def get_report_ids(self):
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)
        reports_raw = gmp.get_reports()

        reports = reports_raw.xpath("//report")
        report_ids = reports[0].xpath("//report/@id")
        report_ids = list(dict.fromkeys(report_ids))
        return report_ids

    @rpc
    def get_xml_reports(self):
        '''Returns xml reports for all tasks'''
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)

        report_id = self.get_report_ids()
        reports_an = []
        for rep_id in report_id:
            reports_an.append(gmp.get_report(rep_id, ignore_pagination=True, details=True, report_format_id=conf.Gvm.ID_XML_REPORT_FORMAT))

        xml_reports = []

        x_parser = etree.XMLParser(huge_tree=True)
        for rep in reports_an:
            base = rep.xpath("//report/text()")
            if base:
                xml_report = base64.decodestring(str.encode(base[0]))
                xml_report = io.StringIO(xml_report.decode('utf8'))
                xml_reports.append(etree.parse(xml_report, parser=x_parser))

        return xml_reports

    def get_timestamps(self):
        '''Return Timestamps from Text Report'''
        gmp = self.connect_to_gvm()
        if not gmp:
            return json.dumps({'Error': 'Connection to Scanner failed'})
        gmp.authenticate(conf.Gvm.AUTH_USER, conf.Gvm.AUTH_PASS)

        report_id = self.get_report_ids()

        txt_base_reports = []
        for rep_id in report_id:
            txt_base_reports.append(gmp.get_report(rep_id, ignore_pagination=True, details=True, report_format_id=conf.Gvm.ID_TIMESTAMP_REPORT_FORMAT))

        timestamps = ""
        for rep in txt_base_reports:
            # Decode report from base64
            base = rep.xpath("//report/text()")
            if base:
                txt_report = base64.decodestring(str.encode(base[0]))
                txt_report = txt_report.decode('utf8')
                for line in txt_report.splitlines():
                    if line.startswith('timestamps'):
                        timestamps += line + "\n"
        return timestamps

    def generate_json_report(self):
        '''Generates JSON Report and saves in PATH_JSONREPORT'''
        results = {}
        xml_reports = self.get_xml_reports()
        timestamps = self.get_timestamps()

        for report in xml_reports:
            ips = report.xpath('//host')
            ips_text = []
            for ip in ips:
                ips_text.append(ip.text)
            ips_text = list(dict.fromkeys(ips_text))
            ips_text = [i for i in ips_text if i]

            for ip in ips_text:
                if not ip[0].isnumeric():
                    ips_text.remove(ip)

            for ip in ips_text:
                res = []
                for resu in report.iter('result'):
                    for host in resu.iter('host'):
                        if ip in host.text:
                            res.append(resu)

                start = "0"
                end = "0"

                for line in timestamps.splitlines():
                    if line.startswith("timestamps||" + ip + "|host_start"):
                        start = line.split("|")[-2]
                    elif line.startswith("timestamps||" + ip + "|host_end"):
                        end = line.split("|")[-2]

                dict_elements = [{"start": start}, {"end": end}]

                for result in res:
                    finding = xmltodict.parse(etree.tostring(result))
                    unness_elem = ["@xmlns:gvm", "@xmlns", "@xmlns:ai", "@xmlns:core", "@xmlns:cpe-name", "@xmlns:arf"]
                    for el in unness_elem:
                        if el in finding["result"]: del finding["result"][el]
                    dict_elements.append(finding)

                results.update({ip: dict_elements})
        f = open(conf.Local.PATH_JSONREPORT, 'w+')
        f.write(json.dumps(results))
        f.close()

    @rpc
    def initiate_json_report_generation(self):
        report_generation_thread = threading.Thread(target=self.generate_json_report)
        report_generation_thread.start()

        return "Report is generated"
