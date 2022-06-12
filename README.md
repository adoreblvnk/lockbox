# LockBox



## Execution

1. Create `venv`.
2. Install dependencies with `pip install -r requirements.txt`.
3. Setup DB.
   1. Run `lockboxdb.py`, located in base directory.
   2. Enter `1` when prompted.
4. Create `.env` file.
   1. Paste in simulated environment variables.
5. Run `main.py`.

*Note:* To check contents of Shelve, run `lockboxdb.py` in the same directory as LockBox location.

## Configurations

- test user accounts.
  - | username | password |
    | :------: | :------: |
    |    |    |
    |   |  |

## Password Complexity via ML (SVM)
- Accepted password: "Your_Name1234$#%^"
- Rejected password: "Passw0rd"

## Instructions on How to Code

- read `NOTE:` & `TODO:` before coding (eg there is 1 file where you should NOT format code!).
- comment & replace, NOT delete code.
- for Python API, your code should be located under your name, then import it (eg `joseph.py` in base folder).
- tag your code.

```py
# joseph
code here
```

## Changelog

- **v10.0.1 Removed errorlog**
- **v10.0 Removed Facial Recognition**
  - Code cleanup.
  - Fixed image icon issue.
- **v9.6 Updated README**
  - Code cleanup.
- **v9.5 Fixed Forms**
- **v9.4 Updated requirements.txt**
- **v9.3 Added Test Files**
- **v9.2 Fix Bug In A Person's Code**
- **v9.1 Added form2fa Class**
- **v9.0.1 Removed a_lockboxdb**
- **v9.0 Added Aden's Features**
   - Database changed from SQLite to shelves, with username set as the key
   - Added reCaptcha and 2FA
   - Added CSRF
   - [Joseph, Aden] Added Support Vector Machine (SVC) learning for passwords complexity.
   - Dynamic Password salting and hashing
   - Checks for duplicate usernames
   - Display password requirements
- **v8.0 Added Version Control**
  - Changed routes.
- **v7.0 Added File Metadata**
  - Ignore Version Control code, it's half done.
    - Do not attempt to interact with it, it will mess up the DB.
  - File Metadata documentation added.
- **v6.0.3 Updated gitignore**
  - Added execution steps.
- **v6.0.2 Moved LockBoxDB**
- **v6.0.1 Fixed DB Generation Error**
- **v6.0 New Baseline**
  - **Creation of DB**: Run `lockboxdb.py`.
  - Changed DB to Shelve.
  - Use `Path()` for paths for Linux compatibility.
  - Run `lockboxdb.py` to check contents of ShelveDB.
  - Insert test data to `lockboxdb.py`.
- **v5.2 Fixed DB Schema**
- **v5.1 Added .env**
  - `DB_PATH` is `database\lockbox.db`.
- **v5 Added SQL for DB**
  - Included new tables (file, user_file).
- **v4.0.1 Fixed Typo**
- **v4 Added Rich Text Editor**
  - Powered by [TinyMCE](https://www.tiny.cloud).
  - Added capabilities for viewing, editing text-based files.
- **v3.4 Removed File Password Encryption**
  - Code for encryption is commented.
  - Cross-compatibility between Mac / Linux / Windows.
    - Converted file paths to use Path from pathlib.
    - NOTE: not all file paths have been converted.
  - Removed `files/temp` folder.
- **v3.3.3 Reduced README Icon Size**
- **v3.3.2 Fixed README LockBox Icon**
- **v3.3.1 Added License**
- **v3.3 Added User Folder Creation**
  - README changelog is now reverse chronological.
  - fixed crash if `files/` folder does not exist.
  - fixed crash if temp is not created.
    - TODO: not final, eventually hope to remove the need for temp.
- **v3.2 Added Database Folder for DB**
- **v3.1 Added CSRF Tokens for All Forms**
- **v3.0 Added Login, Register, & SQLite3 DB**
- **v2.1 Added Flash Messages**
- **v2.0 Version Control**
  - added API.
- **v1.4 Fixed Typos**
- **v1.3 Refactored Templates**
- **v1.2 Removed File Deletion Upon Download**
- **v1.1 Added Readme**
- **v1.0 Initial Commit**
  - refactored code.
    - added icon.
      - <img src="static/img/lockbox.ico" alt="LockBox icon" width="50"/>
    - changed variable names from Swedish to English.
    - code is formatted using `autopep8`.
  - added TODOs & NOTE.

## Credits

- joseph
- edwin
- aden
- mark
