import shelve
import json
import os
import dbm
DB_PATH = "./database/virus.db"


def list_shelve_contents():
    print("\nPrinting contents of Shelve file.\n")
    with shelve.open(DB_PATH) as db:
        print(json.dumps(list(db.items()), indent=2))


def insert_test_data():
    try:
        with shelve.open(r"database/virus.db", "c") as db:
            db.clear()
            db["virus"] = ["c277e179cb4e607f9343f4115b75a6aa"]

    except dbm.error as e:
        print(e)


if __name__ == "__main__":
    list_shelve_contents()
    dbinput = input(
        "\n1: To perform a clean insert of test data. Deletes any current data in Shelve! \nEnter: To ignore this: \n")
    if dbinput == "1":
        insert_test_data()
