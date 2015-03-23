Email Parser
==========

Generating lots of useful SMTP metadata from pcaps containing SMTP (tcp.port == 25 or decrypted tcp.port == 587) sessions.

Required Things
-----
* MySQL or MariaDB (supports both)
* Python 2.6 / 2.7
* [MySQL-python](https://github.com/farcepest/MySQLdb1) (yum install MySQL-python || pip install mysql-python)
* [dpkt 1.8](https://code.google.com/p/dpkt/) (easy_install dpkt)
* [libmagic](https://github.com/threatstack/libmagic) (yum install libmagic)
* [python-magic](https://github.com/ahupp/python-magic) (yum install python-magic || pip install python-magic)
* GeoIP, GeoIP-devel, GeoIP-update (yum install)
* [Python GeoIP](https://github.com/maxmind/geoip-api-python) (pip install GeoIP)
* MySQL config change
  * max_allowed_packet = __25M__ (database config default = 1M, set the max to your organization's)

Important Files
-----
* email-parser.py
 * Command line and database functionality
* parse_sessions.py
  * Addresses TCP sessions (reordering, tracking, layer2-4 metadata)
* parse_smtp.py
  * Uses parse_sessions.py, iterates through the PCAP file and extracts and parses all SMTP traffic into pretty things like email.sender, email.recipient, attachment.name, attachment.payload
* schema.sql
  * To prepare a MySQL (or Maria) DB for use with email metadata

Program Usage
-----
```
Usage: email-parser.py [options]

email-parser.py parses individual PCAP files and outputs SMTP metadata to
multiple formats. You can enhance the way you interact with this data by using
the database and the web page.

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -p PCAPFILE        Filename of the of the pcap to process
  -d DIRECTORY       Directory containing pcap files

  Output Options:
    Choose how you would like the data output to you.

    -o OUTPUT        db, csv, cef [default: cef]

  Database Options:
    The following options are to be used in conjunction with the SQL
    database you have configured.

    -s SQLSTATEMENT  SQL SELECT query to pass to the database
    -m MD5SUM        md5sum of file to retrieve from database
```

Credits
-----
findsmtpinfo.py (forensics challenge #2)<br />
other stuff added later
