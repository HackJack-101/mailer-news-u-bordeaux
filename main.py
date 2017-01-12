#!/usr/bin/python3

#TODO: logging
#TODO: config file

import nntplib
import os
import re
import smtplib
from email.header import decode_header
from datetime import date, timedelta

### Client settings
sendmail_command = "/usr/sbin/sendmail -t"
last_email_file_path_pattern = "/home/hackjack/newsgroup/{:s}.lst"

### NNTP Authentication settings
auth_user = 'username'
auth_password = 'password'

### NNTP settings
server_uri = 'news.u-bordeaux.fr'
server_port = 563
default_charset = 'utf-8'
rescue_charset = 'iso-8859-1'
known_groups = {
	'lstinfo' : 'lstinfo-u-bordeaux@googlegroups.com',
	'lstinfo.officiel' : 'lstinfo-officiel-u-bordeaux@googlegroups.com',
	'masterinfo' : 'masterinfo-u-bordeaux@googlegroups.com',
	'masterinfo.officiel' : 'masterinfo-officiel-u-bordeaux@googlegroups.com',
}
#subject_charset_regex = re.compile(r"=\?(.+)\?Q\?")
body_charset_regex = re.compile(r"charset=([a-zA-Z0-9-]+)")


def parse_header( header_list:list ) -> dict:
	header_dict = {}
	for line in header_list:
		try:
			(k, v) = line.split(b": ", 1)
		except ValueError:
			pass
		else:
			header_dict[k] = v
	return header_dict


def main( ) :
	with nntplib.NNTP_SSL(server_uri, server_port) as server_connection:
		server_connection.login(auth_user, auth_password)
		
		for (group, email) in known_groups.items():
			(response, count, first, last, name) = server_connection.group(group)
			
			with open(last_email_file_path_pattern.format(group), "r") as last_email_file :
				last_read = last_email_file.read()
			with open(last_email_file_path_pattern.format(group), "w") as last_email_file :
				last_email_file.write(str(last))
			
			message_id = int(first)
			
			if (last_read) :
				last_read = int(last_read)
			else:
				last_read = 0
			
			try :
				while (True) :
					if (message_id > last_read) :
						(response, header_info) = server_connection.head(message_id)
						header = parse_header(header_info.lines)
						
						body_charset = default_charset
						content_type = header[b"Content-Type"].decode('utf-8')
						_charset = body_charset_regex.findall(content_type)
						if (_charset) :
							charset_body = _charset[0]
						(response, body_info) = server_connection.body(message_id)
						
						p = os.popen(sendmail_command, "w")
						p.write("To: {:s}\n".format(email))
						
						for header_line in header_info.lines:
							if(not header_line.decode('utf-8').startswith("Cc:")):
								p.write(header_line.decode('utf-8') + "\n")
						
						p.write("\n") 
						
						for info_line in body_info.lines:
							try :
								p.write(info_line.decode(body_charset) + "\n")
							except Exception:
								p.write(info_line.decode(rescue_charset) + "\n")
						
						status = p.close()
					
					(response, message_id, _id) = server_connection.next()
			except nntplib.NNTPTemporaryError:
				pass


if (__name__ == "__main__") :
	main()
	print("Task finished")

