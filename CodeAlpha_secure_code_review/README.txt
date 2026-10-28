=====================================================================
 TASK 2: SECURE CODING REVIEW
 Language: Python 3 (Flask)      Static Analyzer: Bandit
=====================================================================
Name        : Rehan Ahmad
---------------------------------------------------------------------
1. PROJECT DESCRIPTION
---------------------------------------------------------------------
This project is a secure code review of a small Flask web application
called "Student Portal".

  - vulnerable_app.py : version written with common security mistakes
                        (for learning only, never use in real systems)
  - secure_app.py     : fixed version with all vulnerabilities removed

The code was audited with Bandit (static analysis) and manual
inspection. 13 vulnerabilities were found (9 High, 4 Medium).
Bandit reports 17 issues on the vulnerable app and 0 on the secure app.

---------------------------------------------------------------------
2. FOLDER CONTENTS
---------------------------------------------------------------------
  vulnerable_app.py             Code with security problems
  secure_app.py                 Fixed code
  requirements.txt              Python libraries needed
  uploads/notes.txt             Sample file used by the download test
  bandit_vulnerable_report.html Bandit scan of vulnerable app (HTML)
  bandit_vulnerable_report.txt  Bandit scan of vulnerable app (text)
  bandit_secure_report.html     Bandit scan of secure app (HTML)
  bandit_secure_report.txt      Bandit scan of secure app (text)
  Task2_Report.docx             Full findings and remediation report
  screenshots/                  Screenshots of scans and tests
  README.txt                    This file

---------------------------------------------------------------------
3. REQUIREMENTS
---------------------------------------------------------------------
  - Python 3.8 or newer
  - Install the libraries:

        pip install -r requirements.txt

---------------------------------------------------------------------
4. HOW TO RUN THE STATIC ANALYSIS (BANDIT)
---------------------------------------------------------------------
Open Command Prompt in this folder and run:

    bandit -r vulnerable_app.py       (expected: 17 issues)
    bandit -r secure_app.py           (expected: 0 issues)

To create an HTML report:

    bandit -r vulnerable_app.py -f html -o my_report.html

---------------------------------------------------------------------
5. HOW TO RUN THE APPLICATIONS
---------------------------------------------------------------------
Run only ONE version at a time (both use port 5000).

  Vulnerable version (testing only, on your own computer):

        python vulnerable_app.py

  Secure version:

        python secure_app.py

Then open  http://127.0.0.1:5000  in a browser.

Optional: to test the admin login in the secure version, create a
password hash and set it before starting the app (Command Prompt):

    python -c "from werkzeug.security import generate_password_hash as g; print(g('MyStrongPass1'))"
    set ADMIN_PASSWORD_HASH=<paste the hash here>
    set SECRET_KEY=<any long random text>
    python secure_app.py

---------------------------------------------------------------------
6. HOW TO TEST THE VULNERABILITIES
---------------------------------------------------------------------
Run the vulnerable app, then try these in a browser:

  XSS:
    http://127.0.0.1:5000/search?name=<script>alert(1)</script>

  Path traversal:
    http://127.0.0.1:5000/download?file=..\vulnerable_app.py

  Code injection (eval):
    http://127.0.0.1:5000/calc?expr=__import__('os').getcwd()

  Command injection (Windows):
    http://127.0.0.1:5000/ping?host=127.0.0.1%20%26%20echo%20HACKED

  SQL injection (Command Prompt, use curl.exe):
    curl.exe -X POST http://127.0.0.1:5000/login -d "username=' OR '1'='1' --" -d "password=x"

Now stop it, run secure_app.py and repeat the same tests.
The secure version should block every attack, while normal use
(for example /calc?expr=2*(3+4) and a correct login with
ali / student123) still works.

---------------------------------------------------------------------
7. SUMMARY OF FINDINGS
---------------------------------------------------------------------
  F-01  SQL Injection                          High
  F-02  Command Injection                      High
  F-03  Code Injection (eval)                  High
  F-04  Insecure Deserialization (pickle)      High
  F-05  Unsafe YAML Loading                    High
  F-06  Weak Password Hashing (MD5)            High
  F-07  Hardcoded Secrets                      Medium
  F-08  Debug Mode / Open Network Binding      High
  F-09  Insecure Temporary File                Medium
  F-10  Cross-Site Scripting (XSS)             Medium   (manual)
  F-11  Path Traversal                         High     (manual)
  F-12  Weak Admin Authentication              High     (manual)
  F-13  No Input Validation / Security Headers Medium   (manual)

See Task2_Report.docx for details and fixes.

---------------------------------------------------------------------
8. WARNING
---------------------------------------------------------------------
vulnerable_app.py contains deliberate security flaws. Run it only on
your own computer for learning. Never put it on a public server.
