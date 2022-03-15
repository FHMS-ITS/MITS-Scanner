import pathlib

from app import Config

from pylatex import Document, Section,  MiniPage, StandAloneGraphic, LineBreak,  Tabular, LongTable
from pylatex.package import Package
from pylatex.base_classes import Environment
from pylatex.utils import italic, NoEscape, bold
import os, json


def generate_pdf(file_name, rep_id, sev_filter="low"):
    """
    Generate PDF wit latex and saves it in PDF report folder
    Args:
        file_name: Filename of JSON report -> str
        rep_id: Id of target to whom report belongs -> str/int
        sev_filter: Lowest severity of findings in report (log, low, medium, high) -> string

    """
    severity = {
        "log": 0,
        "low": 0.1,
        "medium": 4.0,
        "high": 7.0
    }

    os.environ["running_job"] = file_name+sev_filter
    report = open(os.path.join(Config.REPORT_FOLDER, str(rep_id), file_name), "r")
    json_report = json.load(report)
    json_report = json_report["openvas_report"]
    pdf_file_name = os.path.join(Config.PDF_REPORT_FOLDER, str(rep_id), sev_filter, file_name[:-5])
    pathlib.Path(os.path.join(Config.PDF_REPORT_FOLDER, str(rep_id))).mkdir(exist_ok=True)
    pathlib.Path(os.path.join(Config.PDF_REPORT_FOLDER, str(rep_id), sev_filter)).mkdir(exist_ok=True)


    new_json_report = {}
    for ip in json_report:
        new_findings = []
        for i, finding in enumerate(json_report[ip]):
            if i > 1:
                if float(json_report[ip][i]["result"]["severity"]) < severity[sev_filter]:
                    continue
            new_findings.append(finding)
        new_json_report[ip] = new_findings

    json_report = new_json_report

    def filter_txt(text):
        text = text.replace('"', "''")
        return text

    def divide(text):
        text = text.split("|")
        ret_dict = {}
        for cat in text:
            parts = cat.split("=")
            ret_dict[parts[0]] = parts[1]

        return ret_dict

    class TitlePageEnvironment(Environment):
        _latex_name = 'titlepage'

    class Center(Environment):
        _latex_name = 'center'


    doc = Document(documentclass="report", font_size="small")
    doc.preamble.append(Package("colortbl"))
    doc.preamble.append(NoEscape(r"\usepackage[a4paper, total={6.5in, 9.5in}]{geometry}"))
    doc.preamble.append(NoEscape(r"\usepackage{seqsplit}"))

    doc.add_color("Log", "RGB", "95, 178, 225")
    doc.add_color("Low", "RGB", "40, 225, 40")
    doc.add_color("Medium", "RGB", "225, 220, 20")
    doc.add_color("High", "RGB", "225, 40, 40")

    with doc.create(TitlePageEnvironment()) as title:
        with doc.create(Center()) as center:
            center.append(bold('G Data Advanced Analytics Report'))
            center.append(LineBreak())
            with center.create(MiniPage(width=NoEscape(r"0.46\textwidth"),
                                        pos='c')) as logo_wrapper:
                logo_file = os.path.join("..", "..", "..", Config.IMAGES, 'logo.png')
                logo_wrapper.append(StandAloneGraphic(image_options="width=220px",
                                                      filename=logo_file))

    doc.append(NoEscape(r"\tableofcontents"))

    doc.append(NoEscape(r"\newpage"))


    not_scanned = []
    for ip in list(json_report):
        if not len(json_report[ip]) > 2:
            not_scanned.append(ip)
            json_report.pop(ip)

    for item in json_report:
        json_report[item][2:] = sorted(json_report[item][2:], key = lambda x: float(x["result"]["severity"]), reverse=True)

    sorted_json_report = sorted(json_report.items(), key=lambda x: float(x[1][2]["result"]["severity"]),
                                reverse=True)

    sorted_ips = []
    for i in sorted_json_report:
        sorted_ips.append(i[0])

    for ip in sorted_ips:

        if len(json_report[ip]) > 3:
            with doc.create(Section(ip)):
                start = json_report[ip][0]["start"]
                end = json_report[ip][1]["end"]
                if start == None:
                    start = "--"
                if end == None:
                    end = "--"

                table_time = Tabular('|c|c|')
                table_time.add_hline()
                table_time.add_row([italic("Start"), start])
                table_time.add_hline()
                table_time.add_row([italic("End"), end])
                table_time.add_hline()
                doc.append(table_time)

                #rep_results = json_report[ip][2:]


                for i in range(2, len(json_report[ip])):
                    table1 = LongTable("|p{16cm}|")
                    table1.add_hline()
                    table1.append(NoEscape(r"\rowcolor{"+json_report[ip][i]["result"]["threat"]+"}"))
                    table1.add_row([NoEscape(bold(json_report[ip][i]["result"]["threat"]) #,))
                                             + " CVSS: " + json_report[ip][i]["result"]["severity"])])
                    table1.add_hline()
                    table1.append(NoEscape(r"\rowcolor{"+json_report[ip][i]["result"]["threat"]+"}"))
                    table1.add_row([json_report[ip][i]["result"]["name"]])
                    table1.add_hline()
                    table1.add_row([bold("Port: ")])
                    table1.add_row([json_report[ip][i]["result"]["port"]])
                    if json_report[ip][i]["result"]["description"]:
                        table1.add_hline()
                        table1.add_row((bold("Description"),))
                        table1.add_row((filter_txt(json_report[ip][i]["result"]["description"]),))
                    tags = divide(json_report[ip][i]["result"]["nvt"]["tags"])
                    for tag in tags:
                        if tags[tag]:
                            table1.add_hline()
                            table1.add_row([bold(tag)])
                            table1.add_row([tags[tag]])
                    table1.add_hline()
                    doc.append(table1)

    doc.generate_pdf(pdf_file_name, clean_tex=True, compiler="pdflatex")
    doc.generate_pdf(pdf_file_name, clean_tex=True, compiler="pdflatex")

    del os.environ['running_job']
