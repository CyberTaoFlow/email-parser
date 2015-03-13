#!/usr/bin/env python
import magic
import sys
import os
import mimetypes

#From File
def check_file_type_from_header_long(filename):
        magic_file_type_long = magic.from_file(filename)
        return magic_file_type_long

def check_file_type_from_header(filename):
    magic_file_type = magic.from_file(filename, True)
    return magic_file_type

def check_file_type_from_extension(filename):
    mime_file_type = mimetypes.guess_type(filename, False)
    if mime_file_type[0]:
        return mime_file_type[0]
    return "UNKNOWN"

#From Buffer
def check_file_type_from_buffer_long(buf):
        magic_file_type_long = magic.from_buffer(buf)
        return magic_file_type_long

def check_file_type_from_buffer(buf):
        magic_file_type = magic.from_buffer(buf, True)
        return magic_file_type

#New Mime types because they aren't included
mimetypes.add_type('application/zip', '.docx', True)
mimetypes.add_type('application/zip', '.docm', True)
mimetypes.add_type('application/zip', '.dotx', True)
mimetypes.add_type('application/zip', '.dotm', True)
mimetypes.add_type('application/zip', '.xlsx', True)
mimetypes.add_type('application/zip', '.xlsm', True)
mimetypes.add_type('application/zip', '.xltx', True)
mimetypes.add_type('application/zip', '.xltm', True)
mimetypes.add_type('application/zip', '.xlsb', True)
mimetypes.add_type('application/zip', '.xlam', True)
mimetypes.add_type('application/zip', '.pptx', True)
mimetypes.add_type('application/zip', '.pptm', True)
mimetypes.add_type('application/zip', '.ppsx', True)
mimetypes.add_type('application/zip', '.ppsm', True)
mimetypes.add_type('application/zip', '.potx', True)
mimetypes.add_type('application/zip', '.potm', True)
mimetypes.add_type('application/zip', '.ppam', True)
mimetypes.add_type('application/zip', '.sldx', True)
mimetypes.add_type('application/zip', '.sldm', True)
mimetypes.add_type('application/zip', '.one', True)
mimetypes.add_type('application/zip', '.onetoc2', True)
mimetypes.add_type('application/zip', '.onetmp', True)
mimetypes.add_type('application/zip', '.onepkg', True)
mimetypes.add_type('application/zip', '.thmx', True)

if __name__ == '__main__':
        # checks to see if user supplied arguments
        if len(sys.argv) < 2:
                print "usage:", sys.arg[0], '<filename>'
                sys.exit(1)

        # first argument of script ./script.py [1] [2] [3]
        f = sys.argv[1]
        if not os.path.isfile(f):
            print "File %s does not exist"
            sys.exit(1)

	print "Header     Result:", check_file_type_from_header (f)
	print "Header       Long:", check_file_type_from_header_long(f)
	print "Extension  Result:", check_file_type_from_extension(f)
