import binascii
import datetime as dt
import json
import mimetypes
import os
import shelve
import shutil
from pathlib import Path

from dotenv import load_dotenv
from flask import (abort, flash, jsonify, redirect, render_template, request,
                   send_file, session)
from flask_jwt import JWT, current_identity, jwt_required
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)
from werkzeug.utils import secure_filename

import file_handler
import forms
from exceptions import CommitNotFound, CurrentCommitExistsError
from main import app

# prod by josef.

# set environment variables
load_dotenv()
DB_PATH = os.getenv("DB_PATH")


class FileMetadata():
    def metadata_create(file_name: str, username: str) -> None:
        """creates metadata for file. should only be run once per file.

        Args:
            file_name (str): file name 
            username (str): username
        """
        with shelve.open(DB_PATH, writeback=True) as db:
            db["file"][binascii.hexlify(os.urandom(8)).decode()] = {
                "file_name": file_name,
                "creator": username,
                "c_time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sharing": False
            }

    def get_file_id(file_name: str, username: str) -> str:
        """get file id, file must exist beforehand.

        Args:
            file_name (str): file name
            username (str): username

        Returns:
            str: file id
        """
        with shelve.open(DB_PATH, "r") as db:
            try:
                fileid = "".join([key for key, val in db["file"].items(
                ) if val["file_name"] == file_name and val["creator"] == username])
                return None if fileid == "" else fileid
            except KeyError as e:
                print(e)

    def metadata_del(file_name: str, username: str) -> None:
        """deletes file meta upon file deletion.

        Args:
            file_name (str): file name
            username (str): username
        """
        with shelve.open(DB_PATH, writeback=True) as db:
            try:
                # get fileid from username & file name
                fileid = "".join([key for key, val in db["file"].items(
                ) if val["file_name"] == file_name and val["creator"] == username])
                del db["file"][fileid]
            except KeyError as e:
                print(e)


class VersionControl():
    def is_under_10_mb(file_path: str) -> bool:
        """is under 10 mb

        Args:
            file_path (str):

        Returns:
            bool:
        """
        return True if os.path.getsize(file_path) <= 10 * 1024 ** 2 else False

    def is_img_or_text(file_path: str) -> bool:
        """is image or text based.

        Args:
            file_path (str):

        Returns:
            bool: 
        """
        return True if mimetypes.guess_type(file_path)[0].split("/")[0] in ["image", "text"] else False

    def create_commit_dict(username: str, file_name: str, commit_message: str = "") -> dict:
        """creates commit text. returns commit id & dictionary of commit.

        Args:
            modifier (str): username of modifier
            file_name (str): file name
            commit_message (str): commit message

        Returns:
            dict: commit
        """
        with shelve.open(DB_PATH) as db:
            fileid = "".join([key for key, val in db["file"].items(
            ) if val["file_name"] == file_name and val["creator"] == username])
        commit_id = binascii.hexlify(os.urandom(8)).decode()
        commit = {
            commit_id: {
                "fileid": fileid,
                "modifier": username,
                "mod_date": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "commit_message": commit_message
            }
        }
        return commit

    def vc_init(username: str, user_path: str) -> None:
        """creates repo"""
        # create repo folder
        os.makedirs(Path(f"{user_path}/.repo"), exist_ok=True)
        if not os.path.exists(Path(f"{user_path}/.repo/repo.json")):
            with open(Path(f"{user_path}/.repo/repo.json"), "w+") as f:
                json.dump({}, f, indent=2)

    def vc_commit(username: str, user_path: str, fileid: str, file_name: str, commit: dict) -> None:
        """creates a commit.

        Args:
            username (str): 
            user_path (str): 
            fileid (str): 
            file_name (str): 
            commit (dict): 
        """
        with open(Path(f"{user_path}/.repo/repo.json"), "r+") as repo:
            data = json.load(repo)
            if fileid in data:
                data[fileid]["current"] = commit
                data[fileid]["commit"].update(commit)
            else:
                data[fileid] = {"current": commit, "commit": commit}
            repo.seek(0)
            json.dump(data, repo, indent=2)
        os.makedirs(
            Path(f"{user_path}/.repo/{next(iter(commit))}"), exist_ok=True)
        shutil.copy(Path(f"{user_path}/{file_name}"),
                    Path(f"{user_path}/.repo/{next(iter(commit))}/{file_name}"))

    def vc_checkout(username: str, user_path: str, fileid: str, file_name: str, commit_id: str) -> None:
        """checkout commit.

        Args:
            username (str): 
            user_path (str): 
            fileid (str): 
            file_name (str): 
            commit_id (str): 

        Raises:
            FileNotFoundError: If commit does not exist.
        """
        # delete current file
        Path.unlink(Path(f"{user_path}/{file_name}"), missing_ok=True)
        # move file from commit to user dir
        try:
            shutil.copy2(
                f"{user_path}/.repo/{commit_id}/{file_name}", f"{user_path}")
        except FileNotFoundError:
            raise FileNotFoundError
        # changes current to match desired commit
        with open(Path(f"{user_path}/.repo/repo.json"), "r+") as repo:
            data = json.load(repo)
            data[fileid]["current"] = {
                commit_id: data[fileid]["commit"][commit_id]}
            repo.seek(0)
            json.dump(data, repo, indent=2)

    def vc_del(username: str, user_path: str, fileid: str, commit_id: str) -> None:
        """deletes commit id & commit files from repo.

        Args:
            username (str): 
            user_path (str): 
            fileid (str): 
            commit_id (str): 

        Raises:
            CurrentCommitExistsError: raised when trying to delete current commit
            CommitNotFound: raised when trying to delete commit that does not exist.
            FileNotFoundError: raised when commit file is not found.
        """
        with open(Path(f"{user_path}/.repo/repo.json"), "r") as repo:
            data = json.load(repo)
            if commit_id in data[fileid]["current"]:
                raise CurrentCommitExistsError
            try:
                del data[fileid]["commit"][commit_id]
                repo.seek(0)
            except KeyError:
                raise CommitNotFound
        with open(Path(f"{user_path}/.repo/repo.json"), "w+") as repo:
            json.dump(data, repo, indent=2)
        try:
            shutil.rmtree(Path(f"{user_path}/.repo/{commit_id}"))
        except FileNotFoundError:
            raise FileNotFoundError


class AnonymousSharing():
    def get_file_type(fileid: str):
        """[summary]

        Args:
            fileid (str): [description]

        Returns:
            [type]: file path, file type
        """
        # get filename & user
        with shelve.open(DB_PATH, "r") as db:
            username = db["file"][fileid]["creator"]
            file_name = db["file"][fileid]["file_name"]
        file_path = f"files/{username}/{file_name}"
        file_type = mimetypes.guess_type(file_path)[0].split("/")[0]
        if file_type in ["image", "text"]:
            return file_path, file_type
        else:
            file_type = "binary"
            return file_path, file_type


if __name__ == "__main__":
    # is_img_or_text("we do not care.png")
    # VersionControl.vc_init("student", "files/student")

    # FileMetadata.metadata_create("slumber_party.mp3", "student")

    # co = VersionControl.create_commit_dict("student", "files/student")
    # VersionControl.vc_commit("student", "files/student",
    #                          "8a97ff545f7cb898", "random.txt", co)
    # input("Enter: ")
    # VersionControl.vc_del("student", "files/student",
    #                       "8a97ff545f7cb898", "ac19f6c4768b38a3")
    print(AnonymousSharing.get_file_type("9d0b2aa195334bd8"))
    # pass