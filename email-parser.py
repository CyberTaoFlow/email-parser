#!/usr/bin/env python

# BY GALARNEAU, HAYES, PULSIFER

# TODO
# retention

# REQUIRED FOR USAGE
# Watch out for old versions of python-magic in both /lib and /lib64
# libmagic (yum -y install libmagic)
# python-magic (pip install python-magic)
# MySQL python wrapper (yum -y install MySQL-python)
# Set MySQL variable (in my.cnf) based on max attachment size: max_allowed_packet = 32M

# Function to implement a file-like string buffer (make strings "files" in memory)
from cStringIO import StringIO
# Library to let us get the username of the person who called the program
import getpass
# Library to generate MD5 and SHA256 sums
import hashlib
# Libraries for finding files in the OS and capturing CLI arguments
import os
import os.path
import sys
# Library that lets us search by Regular Expression (regex)
import re
# Library to work with different structures (hex bytestrings .etc)
import struct
# Library for working with zip files
import zipfile
# Library for compressing files before sending to the database
import zlib
# Functions to help with parsing command line arguments
from optparse import OptionParser, OptionGroup
# Enables us to interact with databases (MySQL (EL6) and Maria (EL7))
import MySQLdb
# Enables us to return results in dictionary form (instead of tuples)
import MySQLdb.cursors
# Enables us to push results to syslog with CEF for HP Arcsight
import logging
from logging.handlers import SysLogHandler
# Enables us to map IP addresses to countries
# Keep the GeoIP data files as updated as possible
import GeoIP
# Enables us to perform fuzzy hashing
import ssdeep

# SMTP heavy lifting
import parse_smtp

# Define Database Connection Details
db_host = "localhost"
db_port = 3306
db_user = "root"
db_pass = ""
db_name = "mail"

# EMAIL SUSPICION THRESHOLDS
# Raise the suspicion if more than this many unique IP addresses or filenames
SUSPICION_IP_THRESHOLD_LOW = 5   # suspicion + 1
SUSPICION_IP_THRESHOLD_MED = 10  # suspicion + 2
SUSPICION_IP_THRESHOLD_HIGH = 20 # suspicion + 3
SUSPICION_BAD_EXTENSION = 3      # suspicion + 3

# The attachment types we care about (by extension)
file_exe = [".application", ".com", ".cpl", ".exe", ".gadget", ".hta", ".jar", ".msc", ".msi", ".msp", ".pif", ".scr"]
file_google = [".ade", ".adp", ".chm", ".hta", ".ins", ".isp", ".lib", ".mde", ".mst", ".sct", ".shb", ".sys", ".vxd"]
file_macros = [".docm",".dotm", ".potm", ".ppam", ".ppsm", ".pptm", ".sldm", ".xlam", ".xlsm", ".xltm"]
file_script = [".bat", ".cmd", ".js", ".jse", ".msh", ".msh1", ".msh1xml", ".msh2", ".msh2xm", ".mshxml", ".ps1",
               ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".vb", ".vbe", ".vbs", ".ws", ".wsc", ".wsf", ".wsh"]
file_shortcuts = [ ".inf", ".lnk", ".reg",".scf"]

# A list of lists!
file_extensions = [file_exe, file_google, file_macros, file_script, file_shortcuts]

class db(object):
	# This is the main database class; all interactions with
    # the database happen through this class

    def __init__(self):
        # This special method runs as soon as the object (db) is initialized
        # Database connection handling here
        try:
            connection = MySQLdb.connect(host=db_host, user=db_user, passwd=db_pass, db=db_name, port=db_port)
            # Sets database cursor to dictionary
            self.db = connection.cursor(MySQLdb.cursors.DictCursor)
            # Sets database cursor to tuple [default]
            # self.db = connection.cursor()
        except:
            print "Sorry, can't connect to database:", sys.exc_info()[0], "\n"
            raise

    def __del__(self):
        # This special method runs before the object (db) ends
        # Close connection with database
        self.db.close()

    def Action(self, statement, single_return=0):
        # This function interacts with the database

        # Checks to see if the statement is a string
        if not isinstance(statement, str):
            return False

        # Attempts the query
        # eg: "SELECT id, sender FROM email LIMIT 10"
        try:
            self.db.execute(statement)
        except:
            print "You had an error in your SQL statement.", sys.exc_info()[0]
            raise

        # If the second argument is 1, return only one row
        if single_return == 1:
            return self.db.fetchone()
        else:
            return self.db.fetchall()

    def AnalyzeFile(self, md5):
        """ This function will adjust the database to filter files
        already analyzed from the top10 results """
        # Get the current user
        username = getpass.getuser()

        # Prepare the statement
        statement = "UPDATE attachment SET analyzed='1',bywho='%s' WHERE md5='%s'" % (username, md5)

        # Do the dirty
        self.Action(statement)

    def CleanUp(self):
        # Function will remove items from the db based on params below
        # Number of days to keep attachment payloads
        days = 30

        query = "SELECT COUNT(*) AS count FROM email WHERE timestamp > DATE_SUB(now(), INTERVAL %d DAY)" % (days)

        # self.Action(query)

        # something like this
        query = "SELECT COUNT(email.id) AS count FROM attachments INNER JOIN email ON attachments.id=email.id"

        # self.Action(query)

    def GetFile(self, hash):
        # This function fetches a file from the database
        # the file is saved as its first seen filename
        query = "SELECT attachment_ref.name AS name, attachment.payload AS payload FROM attachment INNER JOIN attachment_ref ON attachment_ref.attachment_id=attachment.id WHERE md5='%s'" % hash
        result = self.Action(query, 1)
        print "Downloading:", result['name']
        print "Filesize:", len(result['payload']), "bytes"
        with open(result['name'], 'wb') as f:
            f.write(zlib.decompress(result['payload']))
        print "Download complete"

    def InsertMeta(self, file):
        # Grab all the emails from the PCAP file (via parse_smtp)
        email_list = parse_smtp.EmailList(file)

        # Iterate through the emails
        for email_session in email_list.emails:

            # Just making sure the email has attachments
            if email_session.attachments:
                # Insert metadata meow
                statement = "INSERT INTO email (sessionstart, country, ip_src, ip_dst, tcp_sport, tcp_dport, sender, recipients, subject, message_body) VALUES (%d, '%s', %d, %d, %d, %d, '%s', %d, '%s', '%s')" % (int(email_session.timestamp), GetCountry(IPint_to_string(ip_to_uint32(email_session.ip_source))), ip_to_uint32(email_session.ip_source), ip_to_uint32(email_session.ip_dest), email_session.sport, email_session.dport, MySQLdb.escape_string(email_session.sender.address), email_session.recipient_count, MySQLdb.escape_string(email_session.subject), MySQLdb.escape_string(email_session.plaintext))
                self.Action(statement)

                # Get Email ID (to reference individual attachments to this email)
                statement = "SELECT LAST_INSERT_ID() AS last_id"
                result = self.Action(statement, 1)
                email_id = result['last_id']

                # Iterate through all the recipients of the email
                recipient_list = []
                for recipient in email_session.to:
                    recipient_list.append(recipient.address)
                for recipient in email_session.cc:
                    recipient_list.append(recipient.address)

                # prepare the statement
                for address in recipient_list:
                    statement = "INSERT INTO email_recipients (email_id, recipient) VALUES (%s, '%s')" % (email_id, MySQLdb.escape_string(address))
                    self.Action(statement, 1)

                # Iterate through the attachments in the email
                for attachment in email_session.attachments:
                    # Each attachment gets a new suspicion
                    suspicion = 0

                    # Check if we have the attachment already, by md5
                    query = "SELECT id FROM attachment WHERE md5 = '%s'" % (attachment.md5)
                    result = self.Action(query, 1)

                    # If we do have the attachment
                    if result:
                        # Get the ID!
                        attachment_id = result['id']

                        # Update the references table since we have an attachment!
                        statement = "INSERT INTO attachment_ref (email_id, attachment_id, name) VALUES (%s, %s, '%s')" % (email_id, attachment_id, MySQLdb.escape_string(attachment.filename))
                        self.Action(statement)

                        # Recalculates the count of uniq IP addresses which sent the same file
                        query = "SELECT COUNT(distinct ip_src) AS count FROM email INNER JOIN attachment_ref ON attachment_ref.email_id=email.id INNER JOIN attachment ON attachment_ref.attachment_id=attachment.id WHERE (attachment.md5 = '%s')" % (attachment.md5)
                        uniq_ips = self.Action(query, 1)

                        # Update the count field in attachments table
                        statement = "UPDATE attachment SET count='%d' WHERE md5='%s'" % (uniq_ips['count'], attachment.md5)
                        self.Action(statement)

                        # If we have it at least SUSPICION_IP_THRESHOLD times, raise suspicion
                        if uniq_ips['count'] > SUSPICION_IP_THRESHOLD_HIGH:
                            suspicion += 3
                        elif uniq_ips['count'] > SUSPICION_IP_THRESHOLD_MED:
                            suspicion += 2
                        elif uniq_ips['count'] > SUSPICION_IP_THRESHOLD_LOW:
                            suspicion += 1

                        # Since we have it, has the filename morphed?
                        query = "SELECT COUNT(*) AS count FROM attachment_ref INNER JOIN attachment ON attachment_ref.attachment_id=attachment.id WHERE attachment.md5 = '%s' AND attachment_ref.name != '%s'" % (attachment.md5, MySQLdb.escape_string(attachment.filename))
                        result = self.Action(query, 1)

                        # Based on the count, adjust suspicion
                        if result['count'] > SUSPICION_IP_THRESHOLD_HIGH:
                            suspicion += 3
                        elif result['count'] > SUSPICION_IP_THRESHOLD_MED:
                            suspicion += 2
                        elif result['count'] > SUSPICION_IP_THRESHOLD_LOW:
                            suspicion += 1

                        # Raise the suspicion in the db
                        self.RaiseSuspicion(attachment.md5, suspicion)

                    else:
                        # Check attachment filename and adjust suspicion if necessary
                        suspicion += CheckExtension(attachment.filename)

                        # If the attachment is a zip, look inside!
                        if attachment.filename.lower().endswith(".zip"):
                            print "Processing:", attachment.filename
                            zip_result = ZippedAttachment(attachment.payload)
                            if not zip_result == False and zip_result > 0:
                                suspicion += zip_result

			# Get the ssdeep hash
			ssdeep_hash = ssdeep.hash(attachment.payload)

                        # Upload the attachment to the database
                        statement = "INSERT INTO attachment (md5, sha256, ssdeep, suspicion, payload) VALUES (%s, %s, %s, %s, %s)"
                        print "UPLOADING", attachment.filename, "WITH SUSPICION", suspicion
                    
			try:
			    self.db.execute(statement, (attachment.md5, attachment.sha256, ssdeep_hash, suspicion, zlib.compress(attachment.payload)))
                        except:
                            print "Something went awry, probably too big"

                        # Get the ID for the attachment we just uploaded
                        statement = "SELECT LAST_INSERT_ID() AS last_id"
                        result = self.Action(statement, 1)
                        attachment_id = result['last_id']

                        # Update the references table since we have a new attachment!
                        statement = "INSERT INTO attachment_ref (email_id, attachment_id, name) VALUES (%s, %s, '%s')" % (email_id, attachment_id, MySQLdb.escape_string(attachment.filename))
                        self.Action(statement)

    def RaiseSuspicion(self, md5, new_suspicion):
        # This function raises the suspicion of a file in the database
        # by pulling the current suspicion and adding to it
        query = "SELECT suspicion FROM attachment WHERE md5='%s'" % (md5)
        result = self.Action(query, 1)
        current_suspicion = result['suspicion']
        new_suspicion += current_suspicion

        statement = "UPDATE attachment SET suspicion = '%d' WHERE md5 = '%s'" % (new_suspicion, md5)
        self.Action(statement)

class meta(object):
    def __init__(self):
        # this function runs when the program is called
        # not sure if we need to do anything here
        pass
    def generate(self, pcap):
        # Grab all the emails from the PCAP file (via parse_smtp)
        email_list = parse_smtp.EmailList(pcap)
        # Iterate through the emails
        for email_session in email_list.emails:
            # Just making sure the email has attachments
            if email_session.attachments:
                # Insert metadata meow
                statement = MySQLdb.escape_string(email_session.subject), MySQLdb.escape_string(email_session.plaintext)
                # print ip_to_uint32(email_session.ip_source), email_session.sport, ip_to_uint32(email_session.ip_dest), email_session.dport, email_session.sender.address, email_session.recipient_count, MySQLdb.escape_string(email_session.subject)

                # Iterate through all the recipients of the email
                recipient_list = []
                for recipient in email_session.to:
                    recipient_list.append(recipient.address)
                for recipient in email_session.cc:
                    recipient_list.append(recipient.address)

                # prepare the statement
                for address in recipient_list:
                    recipient = MySQLdb.escape_string(address)
                    # Iterate through the attachments in the email
                    for attachment in email_session.attachments:
                        # Each attachment gets a new suspicion
                        suspicion = 0
                        # Check attachment filename and adjust suspicion if necessary
                        suspicion += CheckExtension(attachment.filename)

                        # If the attachment is a zip, look inside!
                        if attachment.filename.lower().endswith(".zip"):
                            print "Processing:", attachment.filename
                            if "zip" not in attachment.header_type and "zip" not in attachment.extension_type:
                                suspicion += 2
                            else:
                                zip_result = ZippedAttachment(attachment.payload)
                                if not zip_result == False and zip_result > 0:
                                    suspicion += zip_result

			# FUZZY HASH
                        ssdeep_hash = ssdeep.hash(attachment.payload)

                        # MAKE A CEF
                        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
                        # cef_string = "CEF:0|Custom|email-parser|1.0|0|Suspicious Email|%d|app=SMTP duser=%s fileHash=%s fname=%s src=%s suser=%s" % (suspicion, recipient, ip_to_uint32(email_session.ip_source))
                        cef_string = "CEF:0|Custom|email-parser|1.0|0|Suspicious Email|%d|app=SMTP cs1Label=Attachment cs1=%s duser=%s fileHash=%s fname=%s src=%s suser=%s" % (suspicion, attachment.filename, recipient, attachment.md5, os.path.basename(pcap), IPint_to_string(ip_to_uint32(email_session.ip_source)), email_session.sender.address)
                        #push_syslog(cef_string)
			print cef_string

def CheckExtension(filename):
    # Function to check the file extension of an attachment
    for ext_category in file_extensions:
        for ext in ext_category:
            # If we've found the droids we're looking for
            if filename.lower().endswith(ext):
                # Return the bad suspicion
                return SUSPICION_BAD_EXTENSION
    return 0

def GetCountry(ipaddr):
    # Function to check the country of an IP address

    # Alternate caching methods from GeoIP github
    # GEOIP_STANDARD - Read database from file system. This uses the least memory.
    # GEOIP_MEMORY_CACHE - Load database into memory. Provides faster performance but uses more memory.

    # If you use a custom directory for geoip
    # gi = GeoIP.open("/usr/local/share/GeoIP.dat", GeoIP.GEOIP_STANDARD)

    # Initialize the GeoIP class
    gi = GeoIP.new(GeoIP.GEOIP_STANDARD)

    # Try to get the country
    try:
        country = gi.country_code_by_addr(ipaddr).lower()
    except:
        # exceptions usually occur when the IP address is private
        return "ip"

    return country

def ip_to_uint32(ipaddr):
    # Function to convert a bytestring to an INT
    return struct.unpack("!I", ipaddr)[0]

def IPint_to_string(IPint):
    # Function to convert 32-bit integer to dotted IPv4 address
    return ".".join(map(lambda n: str(IPint>>n & 0xFF), [24,16,8,0]))

def push_syslog(message, local=False):
    # Function to send syslog messages

    # set the syslog server variables
    sl_hostname = 'localhost'
    sl_port = 514
    sl_facility = 'daemon'

    # Create logger instance
    logger = logging.getLogger()
    # set the logging level
    logger.setLevel(logging.INFO)
    # set up the syslog handler
    if local:
        syslog = SysLogHandler(address=('/dev/log'), facility=sl_facility)
    else:
        syslog = SysLogHandler(address=(sl_hostname, sl_port), facility=sl_facility)

    # how to format your syslog message
    # email-parser.py[12345]: INFO $message
    # formatter = logging.Formatter('%(module)s[%(process)d]: %(levelname)s %(message)s')

    # CEF standard
    # email-parser[12345]: CEF0:this|that|other
    formatter = logging.Formatter('%(module)s[%(process)d]: %(message)s')
    syslog.setFormatter(formatter)
    # add the handler to the instance
    logger.addHandler(syslog)

    # logging options are info, warning, error, critical, exception or log
    # logger.log(19, message)

    # send the message as INFO
    logger.info(message)

    # closes (removes the syslog handler)
    logger.removeHandler(sys)

def ZippedAttachment(data):
    # Function to determine if a zipfile contains bad

    # ZA also adds to suspicion
    suspicion = 0

    # Convert attachment.payload (string) to a file object
    file_data = StringIO(data)
    memory_zip = StringIO()

    # Initialize the zipfile
    parent_zipfile = zipfile.ZipFile(file_data)

    # Iterate through the files in the zip
    for file in parent_zipfile.namelist():
        # Try to check the extensions of each file inside
        try:
            suspicion += CheckExtension(file)
        except RuntimeError:
            # Errored out, probably encrypted or not a zip
            return 15
        # if a file inside is a zip (nested zips)
        if file.lower().endswith(".zip"):
            # Try to open the new zip
            try:
                memory_zip.write(parent_zipfile.open(file).read())
            except RuntimeError:
                # Errored out, probably encrypted or not a zip
                return 30

                for file in zipfile.ZipFile(memory_zip).namelist():
                    # if the darn thing is triple zipped, raise_tha_roof
                    if file.lower().endswith(".zip"):
                        return 50
                    # double the suspicion for a zipzip
                    suspicion += CheckExtension(file) * 2
    # Zipped bad files are doubled anyways
    return suspicion * 2


# the if __name__ == '__main__' string allows other python programs to
# reference this script and call on its functions and classes without actually
# executing the program from scratch
if __name__ == '__main__':
    # simple usage string
    usage = "usage: %prog [options]"

    # simple program description
    desc = "%prog parses individual PCAP files and outputs SMTP metadata to multiple formats. You can enhance the way you interact with this data by using the database and the web page."

    # Initialize the OptionParser
    parser = OptionParser(usage, description=desc, version="%prog 1.0 by github.com/JonPulsifer, github.com/JonGalarneau, Andrew Hayes")

    # Options for main program operation
    # COMMANDS TO TYPE IN -p or --pcap
    parser.add_option("-p",
                      # Destination variable will be options.pcapfile
                      dest="pcapfile",
                      # Message to show in -h or --help
                      help="Filename of the of the pcap to process")
    parser.add_option("-d", dest="directory", help="Directory containing pcap files")

    # Options for output options
    outputgroup = OptionGroup(parser, "Output Options", "Choose how you would like the data output to you.")

    outputgroup.add_option("-o", dest="output", default="ascii", help="db, csv, ascii [default: %default]")

    parser.add_option_group(outputgroup)

    # Options for the database
    dbgroup = OptionGroup(parser, "Database Options", "The following options are to be used in conjunction with the SQL database you have configured.")

    dbgroup.add_option("-s", dest="sqlstatement", help="SQL SELECT query to pass to the database")
    dbgroup.add_option("-m", dest="md5sum", help="md5sum of file to retrieve from database")
    # Add the database options to OptionParser
    parser.add_option_group(dbgroup)

    # If the user didn't supply any arguments
    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(1)

    # Iterate through all user supplied comand line arguments
    (options, args) = parser.parse_args(sys.argv)

    # Error handling if users are being stupid
    if options.pcapfile and options.directory:
        parser.error("You can not specify both an individual PCAP file and a directory. See --help for more details")
    elif (options.pcapfile or options.directory) and (options.sqlstatement or options.md5sum):
        parser.error("You can not use the database and process PCAP files at the same time. See --help for more details")

    # Making sure the user actually has a file
    if options.pcapfile:
        if not os.path.isfile(options.pcapfile):
            parser.error("-p %s (the file you chose) must exist and be readable" % (options.pcapfile))
        # Insert metadata and attachments to the database
        if options.output == "db":
            db().InsertMeta(options.pcapfile)
        else:
            meta().generate(options.pcapfile)

    # Making sure the user actually has the directory
    if options.directory:
        if not os.path.isdir(options.directory):
            parser.error("-d %s (the directory you chose) must exist and be readable" % (options.directory))

        if options.output == "db":
            # Initialize the database before the for loops (keeps the db open for all the pcaps)
            database = db()
        # Find all the files that end in .pcap
        for root, dirs, files in os.walk(options.directory):
            for f in files:
                if f.endswith(".pcap"):
                    fullpath = os.path.join(root, f)
                    # Insert metadata and attachments to the database
                    print "Processing:", fullpath
                    if options.output == "db":
                        database.InsertMeta(fullpath)
                    else:
                        meta().generate(fullpath)

    # Error handling for database options
    if options.md5sum and options.sqlstatement:
        parser.error("You can not request a file and perform SQL operations at the same time")

    # Making sure your query starts with SELECT and returns rows
    if options.sqlstatement:
        if options.sqlstatement.startswith("SELECT"):
            query_results = db().Action(options.sqlstatement)
            for row in query_results:
                print row
        else:
            parser.error("SQL statement must begin with SELECT; we don't need yo updates here!")

    # Making sure the user's input was an md5 (or at least looks like one)
    if options.md5sum:
        if re.match('[0-9a-fA-F]{32}$', options.md5sum):
            db().GetFile(options.md5sum)
        else:
            parser.error("You must submit a valid MD5 for this function to proceed")
