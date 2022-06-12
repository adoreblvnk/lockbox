import json
import os
from pathlib import Path
import shelve

from dotenv import load_dotenv
from flask import (abort, flash, jsonify, redirect, render_template, request,
                   send_file, session, url_for, send_from_directory)

import file_handler
from exceptions import CommitNotFound, CurrentCommitExistsError
from jx_api import FileMetadata, VersionControl, AnonymousSharing
import forms
from main import app

from Mark_AFC import * #For AFC logging and controls

# set environment variables
load_dotenv()
DB_PATH = os.getenv("DB_PATH")


def user_logged_in():
    return 'username' in session


@app.route("/versioncontrol/<filename>", methods=["GET", "POST"])
def version_control(filename):
    if not user_logged_in():
        return redirect("/")
    if request.method == "POST":
        fileid = FileMetadata.get_file_id(filename, session["username"])
        file_path = f"files/{session['username']}/{filename}"
        user_path = f"files/{session['username']}"
        # josef: version control → create repo
        if request.form.get("version_control") == "create":
            if VersionControl.is_under_10_mb(file_path) and VersionControl.is_img_or_text(file_path):
                VersionControl.vc_init(session["username"], user_path)
                # TODO: add commit message
                commit = VersionControl.create_commit_dict(
                    session["username"], filename)
                VersionControl.vc_commit(
                    session["username"], user_path, fileid, filename, commit)
                flash(
                    f"{filename} successfully committed with Commit ID {next(iter(commit))}", "success")
            else:
                flash(
                    f"{filename} exceeded file size or is of invalid type for version control", "warning")
        if request.form.get("vc_checkout"):
            try:
                commit_id = request.form.get("vc_checkout")
                VersionControl.vc_checkout(
                    session["username"], user_path, fileid, filename, commit_id)
                flash("successful checkout", "success")
            except FileNotFoundError:
                flash(f"{filename} not found!", "error")
        if request.form.get("vc_delete"):
            commit_id = request.form.get("vc_delete")
            try:
                VersionControl.vc_del(
                    session["username"], user_path, fileid, commit_id)
            except CurrentCommitExistsError:
                flash("Cannot delete current commit!", "warning")
            except CommitNotFound:
                flash(f"{commit_id} not found in repository", "warning")
            except FileNotFoundError:
                flash("This file does not exist.", "error")
    try:
        with open(Path(f"files/{session['username']}/.repo/repo.json"), "r") as repo:
            data = json.load(repo)
            try:
                commit_data = data[FileMetadata.get_file_id(
                    filename, session["username"])]
                commit_current = next(iter(commit_data["current"]))
                return render_template("jx_versioncontrol.html", commit_data=commit_data, commit_current=commit_current)
            except KeyError:
                return render_template("jx_versioncontrol.html", commit_data=None)
    except FileNotFoundError:
        return render_template("jx_versioncontrol.html", commit_data=None)
    return render_template("jx_versioncontrol.html", commit_data=None)


@app.route("/download_image/<path:filename>", methods=["GET"])
def download_image(filename):
    if not user_logged_in():
        return redirect('/')
    return send_from_directory(f"files/{session['username']}", filename)


@app.route("/files/<path:filename>/imageviewer", methods=["GET"])
def image_viewer(filename):
    if not user_logged_in():
        return redirect('/')
        # ADDED BY MARK
    path1 = str(Path(f"files/{session['username']}/{filename}"))
    with open(path1, "rb") as img_file:
        path1 = str(Path(f"files/{session['username']}/{filename}"))
        import base64
        from Mark_AFC import HandleWatermark
        result = img_file.read()
        b64_string = base64.b64encode(result)
        text=str(b64_string)[2:-1]
        text=HandleWatermark(filename,path1,text)

    return render_template("image_viewer.html", filename=filename,b64image=text)
        #END EDIT

@app.route("/sharing/<filename>", methods=["GET", "POST"])
def sharing(filename):
    if not user_logged_in():
        return redirect('/')
    if request.method == "POST":
        fileid = FileMetadata.get_file_id(filename, session["username"])
        with shelve.open(DB_PATH, writeback=True) as db:
            try:
                if request.form.get("share") and db["file"][fileid]["sharing"] != True:
                    db["file"][fileid]["sharing"] = True
                    return render_template("sharing.html", filename=filename, fileid=fileid)
            except KeyError:
                # this means sharing is not created
                db["file"][fileid]["sharing"] = True
                flash("sharing value has been created, the file was created before LockBox v11! tarded kid", "danger")
                return render_template("sharing.html", filename=filename, fileid=fileid)
        return render_template("sharing.html", filename=filename, fileid=fileid)
    try:
        with shelve.open(DB_PATH, writeback=True) as db:
            fileid = FileMetadata.get_file_id(filename, session["username"])
            if str(db["file"][fileid]["sharing"]) == "True":
                return render_template("sharing.html", filename=filename, fileid=fileid)
    except KeyError:
        return render_template("sharing.html", filename=filename)
    except Exception as e:
        print(e)
        return render_template("sharing.html", filename=filename)
    return render_template("sharing.html", filename=filename)


@app.route("/anon_image/<path:fileid>", methods=["GET"])
def anon_image(fileid):
    with shelve.open(DB_PATH, "r") as db:
        username = db["file"][fileid]["creator"]
        file_name = db["file"][fileid]["file_name"]
    return send_from_directory(f"files/{username}", file_name)


@app.route("/anonymous/<fileid>", methods=["GET", "POST"])
def anonymous_sharing(fileid):
    if request.method == "POST":
        with shelve.open(DB_PATH) as db:
            username = db["file"][fileid]["creator"]
            file_name = db["file"][fileid]["file_name"]
            path = Path(f"files/{username}/{file_name}")
            file_obj = file_handler.File(file_name, path)
            new_file_name = str(file_obj.name)
            if new_file_name in file_handler.files_in_dir(Path(f"files/{username}")):
                return send_file(Path(path), as_attachment=True)
    try:
        with shelve.open(DB_PATH) as db:
            username = db["file"][fileid]["creator"]
            file_name = db["file"][fileid]["file_name"]
            if db["file"][fileid]["sharing"] == True:

                # sharing is enabled
                file_path, file_type = AnonymousSharing.get_file_type(fileid)
                if check_AFC_permission(file_path.split('/')[-1]) == False: abort(404) #Mark
                from Mark_AFC import tempLogs
                logMe(file_path.split('/')[-1],request.remote_addr,tempLogs) # Mark
                #MARK EDIT
                newcode = AFCnewcode(file_path.split('/')[-1],0) #Mark
                if file_type == "text":
                    with open(file_path, "r") as data:
                        text = data.read()
                        if (text[:3]) == 'AES':
                            text = text[3:]
                        return render_template("anonymous_sharing.html", text=text,newcode=newcode)
                    #END EDIT
                elif file_type == "image":
                    # ADDED BY MARK
                    with open(file_path, "rb") as img_file:
                                import base64
                                from Mark_AFC import HandleWatermark
                                result = img_file.read()
                                b64_string = base64.b64encode(result)
                                text=str(b64_string)[2:-1]
                                text=HandleWatermark(file_path.split('/')[-1],file_path,text)

                    return render_template("anonymous_sharing.html", image=fileid,b64image=text,newcode=newcode)
                #END EDIT#
                elif file_type == "binary":
                    # josef: remove file password
                    form = forms.File()
                    return render_template("anonymous_sharing.html", file_name=file_name, form=form, binary="binary",newcode=newcode)
    except KeyError:
        abort(404)
    abort(404)
