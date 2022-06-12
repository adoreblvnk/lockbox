import dbm
import json
import os
import shelve

from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DB_PATH")


def list_shelve_contents():
    print("\nPrinting contents of Shelve file.\n")
    with shelve.open(DB_PATH) as db:
        print(json.dumps(list(db.items()), indent=2))


def insert_test_data():
    try:
        with shelve.open(r"database/lockbox.db", "c") as db:
            db.clear()

            # login
            db["login"] = {
                "aquaman": {
                    "password": "191bd1a59650d560ee6d1aedd1bd3c1e31e2363cc1f0c156c3a40d5b5774eca655fbb6ac101e3002d4ba5b5136909bbd31902b0f27212453a0987c5793bdfd79",
                    "mobile": "96306421",
                    "activation": "yes",
                    "Last Login Time": "13/02/2022 22:44:34"
                }
            }

            # file
            db["file"] = {
                "85ff3ea4d2895a10": {
                    "file_name": "fishes.txt",
                    "creator": "aquaman",
                    "c_time": "2022-02-13 22:40:51",
                    "sharing": True
                },
                "6fa0740c35c93941": {
                    "file_name": "catto.mp4",
                    "creator": "aquaman",
                    "c_time": "2022-02-13 22:41:02",
                    "sharing": False
                },
                "ca1d340d8a9fa74e": {
                    "file_name": "fishtank.png",
                    "creator": "aquaman",
                    "c_time": "2022-02-13 22:41:14",
                    "sharing": False
                }
            }

            # user file
            db["user_file"] = {
               
            }

            # file_protection
            db["file_protection"] = {

            }
            print("\nPrinting contents of Shelve file.\n")
            print(json.dumps(list(db.items()), indent=2))
    except dbm.error as e:
        print(e)


if __name__ == "__main__":
    list_shelve_contents()
    dbinput = input(
        "\n1: To perform a clean insert of test data. Deletes any current data in Shelve! \nEnter: To ignore this: \n")
    if dbinput == "1":
        insert_test_data()
