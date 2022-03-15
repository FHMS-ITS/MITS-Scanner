import glob
import json
import math
import os
import pyqrcode
from datetime import date
from datetime import datetime
from io import BytesIO

from flask import request, url_for, render_template, flash, redirect, send_from_directory
from flask_login import login_user, login_required, logout_user
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

from app import db, Config
from app.errors import error_response
from app.ext_api.api import emit_message, clients
from app.forms import LoginForm, CommunicationForm, TokenForm, TargetForm, IpsForm, ExIpsForm, LogPfdReportForm, \
    LowPfdReportForm, \
    MediumPfdReportForm, HighPfdReportForm
from app.gen_pdf import generate_pdf
from app.models import Target, Admin
from app.ui_api import bp
import rq
from redis import Redis

@bp.route('/frontend/login', methods=['GET', 'POST'])
def login_front():
    """
    Login View
    Returns:
        Login HTML template or Targets HTML template if user logged in successfully
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = Admin.query.filter_by().first()
        if user is None or not user.check_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token')
            return redirect(url_for('ui_api.login_front'))
        login_user(user, remember=True)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('ui_api.get_targets_front')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout_front():
    """
    Logout view

    User is logged out
    Returns:
        Logout HTML template
    """
    logout_user()
    return redirect(url_for('ui_api.login_front'))


@bp.route('/frontend/targets', methods=['GET'])
@login_required
def get_targets_front():
    """
    View which shows a list of all targets
    Returns:
        Targets HTML template
    """
    targets = Target.to_collection_dict_raw(Target.query)
    return render_template('targets.html', targets=targets)


@bp.route('/frontend/target/<int:id>', methods=['GET'])
@login_required
def get_target_front(id):
    """
    View which shows information about a single target
    Args:
        id: Id of target -> int
    Returns:
        Target HTML template
    """
    target = Target.query.get_or_404(id)
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    num_msg = len(Target.to_collection_dict_raw(target.status))
    page = request.args.get('page', math.ceil(num_msg/per_page), type=int)
    data = Target.to_collection_dict_paginated(target.status, page, per_page, 'ui_api.get_target_front', id=id)
    prev_url = data["_links"]["prev"]
    next_url = data["_links"]["next"]

    online = id in clients
    return render_template('target.html', target=target.to_dict(), status=data["items"], prev_url=prev_url,
                           next_url=next_url, online=online)


@bp.route('/frontend/target/<int:id>/communicate', methods=['GET', 'POST'])
@login_required
def send_message_front(id):
    """
    View to send messages to Client via Websocket
    Args:
        id: Id of target -> int
    Returns:
        Target Communication HTML template
    """
    form = CommunicationForm()
    ip_upload_form = IpsForm()
    ip_ex_upload_form = ExIpsForm()
    if form.message.data and form.validate_on_submit():
        #Validate message form
        msg = form.message.data
        if not emit_message(msg, id):
            return error_response(401, "Target not online")

    if ip_upload_form.validate_on_submit():
        #Validate IP form
        f = ip_upload_form.file.data
        filename = secure_filename(f.filename)
        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in Config.UPLOAD_EXTENSIONS:
                return error_response(401, "Wrong extension")
            ips = f.readlines()
            if ips:
                ips = [ip.strip().decode() for ip in ips]
                msg = {"ips": ips}
                if not emit_message(json.dumps(msg), id):
                    return error_response(401, "Target not online")

    if ip_ex_upload_form.validate_on_submit():
        #Validate Excluded IPs form
        f = ip_ex_upload_form.fileex.data
        filename = secure_filename(f.filename)
        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in Config.UPLOAD_EXTENSIONS:
                return error_response(401, "Wrong extension")
            ips = f.readlines()
            if ips:
                ips = [ip.strip().decode() for ip in ips]
                msg = {"exips": ips}
                if not emit_message(json.dumps(msg), id):
                    return error_response(401, "Target not online")

    target = Target.query.get_or_404(id)

    #Pagination
    num_msg = len(Target.to_collection_dict_raw(target.message))
    per_page = min(request.args.get('per_page', 10, type=int), 100)
    page = request.args.get('page', math.ceil(num_msg/per_page), type=int)
    data = Target.to_collection_dict_paginated(target.message, page, per_page, 'ui_api.send_message_front', id=id)

    prev_url = data["_links"]["prev"]
    next_url = data["_links"]["next"]
    messages = data["items"]
    messages.reverse()
    online = id in clients

    return render_template('target-communication.html', target=target.to_dict(), messages=messages, prev_url=prev_url,
                           next_url=next_url, online=online, form=form,
                           ip_upload_form=ip_upload_form, ip_ex_upload_form=ip_ex_upload_form)


@bp.route('/frontend/target/<int:id>/token', methods=['GET', 'POST'])
@login_required
def get_token_front(id):
    """
    View to generate and update token
    Args:
        id: Id of target -> int
    Returns:
        Token Generation HTML template
    """
    form = TokenForm()
    token = None
    target = Target.query.get_or_404(id)
    online = id in clients
    if form.validate_on_submit():
        time = form.expiration.data
        sec = (time-date.today()).total_seconds()
        sec = 0 if sec < 0 else sec
        token = target.generate_token(int(sec))

    if form.update.data:
        if not emit_message(token, id):
            return error_response(401, "Target not online")
        token = "Token updated to: " + token



    return render_template('token-gen.html', target=target.to_dict(), token=token, form=form, online=online)


@bp.route('/frontend/target/delete/<int:id>', methods=['GET'])
@login_required
def delete_front(id):
    """
    View to delete target
    Args:
        id: Id of target -> int
    Returns:
        Redirect to targets view
    """
    target = Target.query.get_or_404(id)
    db.session.delete(target)
    db.session.commit()
    return redirect(url_for('ui_api.get_targets_front'))


@bp.route('/frontend/target', methods=['GET', 'POST'])
@login_required
def set_target_front():
    """
    View to create target
     Returns:
        Target creation HTML template or redirect to targets view if target was created
    """
    form = TargetForm()
    if form.validate_on_submit():
        name = form.name.data
        target = Target(name=name)
        db.session.add(target)
        db.session.commit()
        return redirect(url_for('ui_api.get_targets_front'))
    return render_template('target-create.html', form=form)


@bp.route('/frontend/target/report/<int:id>', methods=['GET'])
@login_required
def report_front(id):
    """
    View which shows report overview
    Args:
        id: Id of target -> int
    Returns:
        Report overview HTML template
    """
    target = Target.query.get_or_404(id)
    report = sorted(glob.glob(os.path.join(Config.REPORT_FOLDER, str(id), "*.json")), key=os.path.getmtime,
                    reverse=True)
    next_url = None
    prev_url = None
    tls_report = []
    if len(report) > 0:
        f = open(report[0])
        report = json.load(f)
        f.close()
        for ip in report["openvas_report"]:
            report["openvas_report"][ip][2:] = sorted(report["openvas_report"][ip][2:],
                                                      key=lambda x: float(x["result"]["severity"]),  reverse=True)

        sorted_findings = sorted(report["openvas_report"].items(), key=lambda x: float(x[1][2]["result"]["severity"]),
                                 reverse=True)

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)

        has_next = False
        if page * per_page < len(sorted_findings):
            sorted_findings = sorted_findings[page * per_page-per_page:page * per_page]
            has_next = True
        else:
            sorted_findings = sorted_findings[page * per_page-per_page:]

        d = {}
        for k, v in sorted_findings:
            d.setdefault(k, v)
        report["openvas_report"] = d

        tls_report = report.get("tls_report")
        next_url = url_for('ui_api.report_front', page=page + 1, per_page=per_page, id=id) if has_next else None
        prev_url = url_for('ui_api.report_front', page=page - 1, per_page=per_page, id=id) if page > 1 else None

    else:
        report = json.dumps({})

    return render_template('report.html', report=report, target=target.to_dict(), prev_url=prev_url, next_url=next_url, tls_report=tls_report)

redis_conn = Config.REDIS #'redis://127.0.0.1:6379' #'redis://redisq:6379'
queue = rq.Queue('pdf-gen', connection=Redis.from_url(redis_conn))

rj = []
@bp.route('/frontend/target/reports/<int:id>', methods=['GET', 'POST'])
@login_required
def reports_front(id):
    """
    View which shows all JSON reports and allows to generate and to download PDF reports
    Args:
        id: Id of target -> int
    Returns:
        Report download HTML template
    """
    log_form = LogPfdReportForm()
    low_form = LowPfdReportForm()
    medium_form = MediumPfdReportForm()
    high_form = HighPfdReportForm()
    Target.query.get_or_404(id)
    times = []
    reports = []
    status_log = []
    status_low = []
    status_medium = []
    status_high = []
    threads = []

    pdf_report_names_log = [os.path.basename(x) for x in glob.glob(os.path.join(Config.PDF_REPORT_FOLDER, str(id), "log", "*.pdf"))]
    pdf_report_names_low = [os.path.basename(x) for x in glob.glob(os.path.join(Config.PDF_REPORT_FOLDER, str(id), "low", "*.pdf"))]
    pdf_report_names_medium = [os.path.basename(x) for x in glob.glob(os.path.join(Config.PDF_REPORT_FOLDER, str(id), "medium", "*.pdf"))]
    pdf_report_names_high = [os.path.basename(x) for x in glob.glob(os.path.join(Config.PDF_REPORT_FOLDER, str(id), "high", "*.pdf"))]
    report_generating = False

    if log_form.report_name_log.data and log_form.validate_on_submit():
        if (log_form.report_name_log.data[:-4] + "pdf") in pdf_report_names_log:
            return send_from_directory(directory=os.path.join('..', Config.PDF_REPORT_FOLDER,  str(id), "log"), filename=log_form.report_name_log.data[:-4] + "pdf")

        job = queue.enqueue('app.gen_pdf.generate_pdf', log_form.report_name_log.data, id, "log", job_id=log_form.report_name_log.data+"log")
        rj.append(job.get_id())

    if low_form.report_name_low.data and low_form.validate_on_submit():
        if (low_form.report_name_low.data[:-4] + "pdf") in pdf_report_names_low:
            return send_from_directory(directory=os.path.join('..', Config.PDF_REPORT_FOLDER,  str(id), "low"), filename=low_form.report_name_low.data[:-4] + "pdf")
        job = queue.enqueue('app.gen_pdf.generate_pdf', low_form.report_name_low.data, id, "low", job_id=low_form.report_name_low.data+"low")
        rj.append(job.get_id())

    if medium_form.report_name_medium.data and medium_form.validate_on_submit():
        if (medium_form.report_name_medium.data[:-4] + "pdf") in pdf_report_names_medium:
            return send_from_directory(directory=os.path.join('..', Config.PDF_REPORT_FOLDER,  str(id), "medium"), filename=medium_form.report_name_medium.data[:-4] + "pdf")
        job = queue.enqueue('app.gen_pdf.generate_pdf', medium_form.report_name_medium.data, id, "medium", job_id=medium_form.report_name_medium.data+"medium")
        rj.append(job.get_id())

    if high_form.report_name_high.data and high_form.validate_on_submit():
        if (high_form.report_name_high.data[:-4] + "pdf") in pdf_report_names_high:
            return send_from_directory(directory=os.path.join('..', Config.PDF_REPORT_FOLDER,  str(id), "high"), filename=high_form.report_name_high.data[:-4] + "pdf")
        job = queue.enqueue('app.gen_pdf.generate_pdf', high_form.report_name_high.data, id, "high", job_id=high_form.report_name_high.data+"high")
        rj.append(job.get_id())

    jobs = queue.job_ids
    for j in jobs:
        threads.append(j)

    for rep in sorted(glob.glob(os.path.join(Config.REPORT_FOLDER, str(id), "*.json")), key=os.path.getmtime, reverse=True):
        rep_name = os.path.basename(rep)
        reports.append(rep_name)
        times.append(datetime.fromtimestamp(os.path.getmtime(rep)))

        if (rep_name[:-4] + "pdf") in pdf_report_names_log:
            status_log.append("avail")
            if (rep_name+"log") in rj:
                rj.remove(rep_name+"log")
        elif rep_name+"log" in threads or (rep_name+"log") in rj:
            status_log.append("gen")
            report_generating = True
        else:
            status_log.append("none")

        if (rep_name[:-4] + "pdf") in pdf_report_names_low:
            status_low.append("avail")
            if (rep_name+"low") in rj:
                rj.remove(rep_name+"low")
        elif rep_name+"low" in threads or (rep_name+"low") in rj:
            status_low.append("gen")
            report_generating = True
        else:
            status_low.append("none")

        if (rep_name[:-4] + "pdf") in pdf_report_names_medium:
            status_medium.append("avail")
            if (rep_name+"medium") in rj:
                rj.remove(rep_name+"medium")
        elif rep_name+"medium" in threads or (rep_name+"medium") in rj:
            status_medium.append("gen")
            report_generating = True
        else:
            status_medium.append("none")

        if (rep_name[:-4] + "pdf") in pdf_report_names_high:
            status_high.append("avail")
            if (rep_name+"high") in rj:
                rj.remove(rep_name+"high")
        elif rep_name+"high" in threads or (rep_name+"high") in rj:
            status_high.append("gen")
            report_generating = True
        else:
            status_high.append("none")

    return render_template('reports.html', reports=zip(reports, times, status_log, status_low, status_medium, status_high),
                           target_id=id, log_form=log_form, low_form=low_form, medium_form=medium_form, high_form=high_form,
                           report_generating=report_generating)


@bp.route('/frontend/target/report/<int:id>/<path:name>', methods=['GET'])
@login_required
def download_report(id, name):
    """
    Args:
        id: Id of target -> int
        name: Name of report in directory to download -> str
    Returns:
         JSON report to download
    """
    return send_from_directory(directory=os.path.join('..', Config.REPORT_FOLDER, str(id)), filename=name)


@bp.route('/frontend/twofac', methods=['GET'])
@login_required
def two_factor_setup():
    """
    View which shows QR code for 2Factor authentication
    Returns:
         HTML template with QR code
    """
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@bp.route('/qrcode')
@login_required
def qrcode():
    """
    Returns:
         QRCode for 2Factor authentication View -> bytes
    """
    user = Admin.query.filter_by().first()
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

