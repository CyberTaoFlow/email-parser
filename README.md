Email Parser
==========

Generating lots of useful SMTP metadata from pcaps containing SMTP (tcp.port == 25 or decrypted tcp.port == 587) sessions.

Required Things
-----
* MySQL or MariaDB (MariaDB used for this project)
* Python 2.x (2.7 used for this project)
* [MySQL-python](https://github.com/farcepest/MySQLdb1) (yum install MySQL-python || pip install mysql-python)
* [dpkt](https://code.google.com/p/dpkt/) (v1.8 used for this project)
* [libmagic](https://github.com/threatstack/libmagic) (yum install libmagic)
* [python-magic](https://github.com/ahupp/python-magic) (yum install python-magic || pip install python-magic)
* [python-netaddr](https://github.com/drkjam/netaddr) (yum install python-netaddr || pip install python-netaddr)
* MySQL config change
  * max_allowed_packet = __32M__ (database config default = 1M, attachments are bigger)

Important Files
-----
* email-parser.py
 * Command line and database functionality
* parse_sessions.py
  * Addresses TCP sessions (reordering, tracking, layer2-4 metadata)
* parse_smtp.py
  * Uses parse_sessions.py, iterates through the PCAP file and extracts and parses all SMTP traffic into pretty things like email.sender, email.recipient, attachment.name, attachment.payload
* email-schema.sql
  * To prepare a MySQL (or Maria) DB for use with email metadata

#### Some functionality
```
Usage: email-parser.py [options]

This ultimate python pcap processing program will generate some outrageous
SMTP metadata. If I were you, I wouldn't run a 16GB pcap file against this.
Results my vary.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p PCAPFILE           Filename of the of the pcap to process
  -d DIRECTORY          Directory containing pcap files

  Database Options:
    The following options are to be used in conjunction with the MySQL
    database you have configured.

    -s SQLSTATEMENT     Statement to pass to MySQLdb
    -m MD5SUM           md5sum of file to retrieve from database
    --analyzed=ANALYZED
                        Once an md5 from --top10 has been analyzed, input it
                        here so it no longer shows up!
    --showanalyzed=SHOWME
                        Show analyzed files, and who did it!

  Statistics:
    The following options are to be used when a user requires stats. What
    are stats? Metrics? Unfortunately you'll have to generate your own pie
    charts.

    --top10             Print top 10 most suspicious emails (files) by md5
    --campaigns         Print out the phishing campaigns
    --domains           Print the top 25 domains where emails originated
    --howitworks        Display how suspicion is generated
    --csv               Change output format to CSV
```

Credits
-----
findsmtpinfo.py (forensics challenge #2)<br />
other stuff added later
