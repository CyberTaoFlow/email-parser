#!/usr/bin/env python
import re
import StringIO
import unicodedata
import email
import base64
import hashlib

# custom libs
import parse_sessions
import file_type


class EmailAddress(object):
	"""
   This class just encapsulates the name and address for code legibility
"""
	def __init__(self, addr, name=""):
		self.address = addr
		self.name = name

"""
	Credits:

	The following two functions:
		DecodeHeader(header_text, default="ascii")
		GetEmailAddresses(msg, name)
	Are a slight modification of the code found on Alain Spineux' article:
	"Parsing email using Python part 2 of 2 : The content".
"""

def DecodeHeader(header_text, default="ascii"):
	"""Decode header_text if needed"""
	try:
		headers = email.Header.decode_header(header_text.encode('ascii', 'xmlcharrefreplace'))
	except email.Errors.HeaderParseError:
		return header_text.encode('ascii', 'replace').decode('ascii')
	else:
		for i, (text, charset) in enumerate(headers):
			try:
				headers[i] = unicode(text, charset or default, errors='replace').encode('ascii', 'ignore')
			except LookupError:
				# if the charset is unknown, force default
				headers[i] = unicode(text, default, errors='replace').encode('ascii', 'ignore')
		return "".join(headers)


def GetEmailAddresses(msg, name):
	"""retrieve addresses from header, 'name' supposed to be from, to,  ..."""

	# build a regex for validating email address
	atom_rfc2822 = r"[a-zA-Z0-9_!# \$\%&'*+/=?\^`{}~|\-]+"
	atom_posfix_restricted = r"[a-zA-Z0-9_# \$&'*+/=?\^`{}~|\-]+"
	atom = atom_rfc2822
	dot_atom = atom + r"(?:\." + atom + ")*"
	quoted = r'"(?:\\[^\r\n]|[^\\"])*"'
	local = "(?:" + dot_atom + "|" + quoted + ")"
	domain_lit = r"\[(?:\\\S|[\x21-\x5a\x5e-\x7e])*\]"
	domain = "(?:" + dot_atom + "|" + domain_lit + ")"
	addr_spec = local + "\@" + domain
	email_address_re = re.compile('^' + addr_spec + '$')

	addresses = []
	addrs = email.utils.getaddresses(msg.get_all(name, []))

	for i, (name, addr) in enumerate(addrs):
		if not name and addr:
			# only one string! Is it the address or is it the name ?
			# use the same for both and see later
			name = ''

		try:
			# address must be ascii only
			addr = addr.encode('ascii')
		except UnicodeError:
			addr = ''
		else:
			# address must match address regex
			if not email_address_re.match(addr):
				addr = ''
		if name:
			name = DecodeHeader(name)
		addresses.append(EmailAddress(addr, name))
	return addresses


class FileAttachment(object):
	"""
	This class holds entire file attachments and provides meta-data for
	the filename, size, file type, mime type, md5 and sha256 hashes.
"""

	def __init__(self, filename, buf):

		# entire contents of the file, once decoded back to its original format.
		self.payload = buf
		# filename as indicated by the email
		self.filename = filename
		
		if self.payload is not None:
			self.size = len(buf)

			# get the assumed mime type from the file extention
			self.extension_type = file_type.check_file_type_from_extension(filename)

			# get the file type from the file header (magic number)
			self.header_type = file_type.check_file_type_from_buffer(buf)

			# calculate the hashes
			self.md5 = hashlib.md5(buf).hexdigest()
			self.sha256 = hashlib.sha256(buf).hexdigest()

		else:
 			self.filename = "ENVELOPE-BROKEN-FILE:" + self.filename
 			self.md5 = "0" * 32



class EmailSession(object):
	"""
	This class contains all of the login data, sender and recipient information,
	a list of file attachments and the tcp/ip information for any given email.
"""

	def __init__(self, buf):

		# TCP session data
		self.ip_source = 0
		self.ip_dest = 0
		self.sport = 0
		self.dport = 0
		self.timestamp = 0

		# SMTP session data
		self.login = ""
		self.password = ""
		self.mail_from = ""
		self.rcpt_to = ""

		# multipart email data
		self.sender = EmailAddress('')
		self.to = []			 # EmailAddress
		self.cc = []			 # EmailAddress
		self.resent_to = []	 # EmailAddress
		self.resent_cc = []	 # EmailAddress
		self.recipient_count = 0
		self.attachments = []	 # FileAttachment
		self.plaintext = ""	 # decoded to ascii
		self.subject = ""		 # decoded to ascii
		login_portion = False
		message_portion = False

		message_data = ""

		"""
			The following algorithm algorithm for separating the SMTP session
			from the email is derived from Jeremy Rossi's submission for
			Forensics Contest 2 "findsmtpinfo.py".

		"""
		# read the entire session line by line
		for line in buf.splitlines(False):

			# the login portion (EHLO) ends with MAIL FROM
			if login_portion and line.startswith("MAIL FROM"):
				login_portion = False

			# the message portion (DATA) ends with a single "."
			if message_portion and line == ".":
				message_portion = False

			if login_portion:
				if not self.login:
					# SMTP login is encoded in base64
					self.login = base64.decodestring(line)
				else:
					# SMTP password is encoded in base64
					self.password = base64.decodestring(line)

			# accumulate all message lines into message_data and line-break
			if message_portion:
				message_data += line + '\r\n'

			# this is how we identify the start of the login portion
			if line == "AUTH LOGIN":
				login_portion = True

			# this is how we identify the start of the message portion
			if line == "DATA":
				message_portion = True

			# mail from field starts at the 12th byte
			if line.startswith("MAIL FROM:"):
				self.mail_from = line[11:]
			# rcpt to field starts at the 10th byte
			if line.startswith("RCPT TO:"):
				self.rcpt_to = line[9:]

		# converts the large message string into a list of Message class	objects
		msg = email.message_from_string(message_data)

		# grabs the subject line and decodes it
		self.subject = DecodeHeader(msg.get('Subject', ''))

		# grabs the from field and parses the email address/name
		from_ = GetEmailAddresses(msg, 'from')

		# split the from_ tuple into EmailAddress object
		if len(from_) >= 1:
			self.sender.address = from_[0].address
			self.sender.name = from_[0].name

		# each returns a list of EmailAddress objects
		self.to = GetEmailAddresses(msg, 'to')
		self.cc = GetEmailAddresses(msg, 'cc')
		self.resent_to = GetEmailAddresses(msg, 'resent_to')
		self.resent_cc = GetEmailAddresses(msg, 'resent_cc')

		# for convenience
		self.recipient_count = len(self.to) + len(self.cc) + len(self.resent_to) + len(self.resent_cc)

		for part in msg.walk():
			# multipart/* are just containers
			if part.get_content_maintype() == 'multipart':
				continue
			#sanitizes the filename
			filename = part.get_filename()

			if filename:
				filename = DecodeHeader(filename)
				self.attachments.append(FileAttachment(filename, part.get_payload(decode=True)))
			else:
				plaintext = part.get_payload(decode=True)
				if isinstance(plaintext, str):
 					try:
 						self.plaintext += plaintext.encode('ascii', 'ignore') + '\n\n'
 					except:
 						self.plaintext += plaintext.decode('iso-8859-1').encode('ascii', 'xmlcharrefreplace')



class EmailList(object):
	"""
	This class contains a list of EmailSession class objects and populates the
	list by searching through a SessionList class object created by the
	parse_sessions library.

	It checks each session's protocol string looking for "SMTP" and determines
	the IP that initiated the protocol (identified in parse_sessions by EHLO).

	It then gets the initiator's payload and adds a new EmailSession object to
	the emails list.
"""

	def __init__(self, pcap_filename):

		self.emails = []		# parse_sessions.EmailSession

		def FilterSMTP(session):
			"""
	Gets passed while initializing the session_list to be called on for each
	packet. If the current packet's payload starts with EHLO or HELO, return
	true so session_list gets populated with email sessions and their paylods.
"""
			if session.current_payload.startswith("EHLO ") or session.current_payload.startswith("HELO"):
				return True
			else:
				return False

		# build a session list and provide a filter function to only return
		# SMTP sessions and include their payloads
		session_list = parse_sessions.SessionList(pcap_filename, True, FilterSMTP)

		# iterate through all sessions in the pcap
		for session in session_list.sessions:

			payload = session.GetFilterPayload()

			# add a new EmailSession object to the list
			self.emails.append(EmailSession(payload))

			# position of this new email in the list
			index = len(self.emails) - 1

			# add ip and tcp/udp session information to the new email
			self.emails[index].info = session.Info()
			self.emails[index].ip_source = session.source
			self.emails[index].sport = session.sport
			self.emails[index].ip_dest = session.dest
			self.emails[index].dport = session.dport
			self.emails[index].timestamp = session.session_start


if __name__ == '__main__':
	"""
	Provides a simple command-line test that takes a pcap file as an argument
	and outputs information about the email:

	timestamp, source ip/port, destination ip/port
	from, to, cc, resent to, resent cc,	subject
	email body in plaintext

	and for each attachment:
	filename, size,	md5, sha256

	and then writes the file to the current path.

	This is crude and does very little error checking (overwrites files, etc)
"""
	import sys
	import os
	import struct

	def ip_to_str(packed_ip):
	#takes a 4 byte array and returns an IP string
		ip = struct.unpack("I", packed_ip)
		return str(str(ip[0] & 255)+'.'+str(ip[0] >> 8 & 255)+'.'+str(ip[0] >> 16 & 255)+'.'+str(ip[0] >> 24 & 255))

	# checks to see if user supplied arguments
	if len(sys.argv) < 2:
		print sys.arg[0], '<filename.pcap>'

	# first arg should be the filename of a pcap
	f = sys.argv[1]
	if os.path.isfile(f):

		# populate with a list of email sessions from the pcap file
		email_list = EmailList(f)

		for email_session in email_list.emails:
			print
			print email_session.info
			print
			print "From:", email_session.sender.address, email_session.sender.name
			if len(email_session.to) > 0:
				print "To:", email_session.to[0].address, email_session.to[0].name, email_session.recipient_count, "recipients"
			print "Subject:", email_session.subject
			print
			print email_session.plaintext
			for attachment in email_session.attachments:
				print 'Attachment:\t', attachment.filename, "("+str(attachment.size) + " bytes)"
				print 'Type:\t\t', "ext:" + attachment.extension_type + " header:" + attachment.header_type
				print 'MD5:\t\t', attachment.md5
				print 'SHA256:\t\t', attachment.sha256
#				with open(attachment.filename, "w") as f:
#					f.write(attachment.payload)
			print '========================================================================='
