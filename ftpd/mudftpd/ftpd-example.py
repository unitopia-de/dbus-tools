#! /usr/bin/python3
import os, socket

from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import TLS_FTPHandler
from OpenSSL import SSL
import mudauthorizer


class UserSite:
    root_dir="/MUD/lib"
    login_msg_file="/static/adm/FTP.MOTD"
    users_dir="/w"
    dir_msg=".info"
    validate=True
    dir_overrides=[ ("/pub/pub", "", "lr"), ("/pub/incoming", "w", "lr"), ("/incoming", "w", "lr") ]

class AnonSite:
    root_dir="/MUD/lib/pub"
    login_msg_file="/.message"
    users_dir=None
    dir_msg=".message"
    validate=False
    dir_overrides=[ ("/pub/pub", "", "lr"), ("/pub/incoming", "w", "lr"), ("/incoming", "w", "lr") ]

def get_site(username):
    if username == 'anonymous':
        return AnonSite
    else:
        return UserSite

mudauthorizer.get_site = get_site

cmd_perm_overrides = {
    'APPE' : 'a', # Append file
    'CDUP' : 'e', # cd ..
    'CWD'  : 'e', # cd <name>
    'DELE' : 'd', # rm
    'LIST' : 'l', # ls
    'MDTM' : 'l', # get last modification time
    'MLSD' : 'l', # ls
    'MLST' : 'l', # ls
    'MKD'  : 'm', # mkdir
    'NLST' : 'l', # ls
    'RETR' : 'r', # get
    'RMD'  : 'n', # rmdir
    'RNFR' : 'f', # rename from
    'RNTO' : 't', # rename to
    'SIZE' : 'l', # get file size
    'STAT' : 'l', # stat
    'STOR' : 'w', # put
    'STOU' : 'w', # put unique
    'XCUP' : 'e', # cd ..
    'XCWD' : 'e', # cd ..
    'XMKD' : 'm', # mkdir
    'XRMD' : 'n', # rmdir
    }

class FTPHandler(TLS_FTPHandler):
    # The MUDAuthorizer gets the D-Bus address, bus name for the MUD and
    # the object paths to the authentification and authorization objects.
    authorizer = mudauthorizer.MUDAuthorizer("session", "de.mud", "/de/mud/auth", "/de/mud/ftp")
    abstracted_fs = mudauthorizer.MUDFS
    certfile = "/etc/ssl/certs/ftpd.pem"
    keyfile = "/etc/ssl/private/ftpd.pem"
    banner = "MUD FTPD ready."
    passive_ports = range(35000, 35100)

    def __init__(self, conn, server, ioloop=None):
        TLS_FTPHandler.__init__(self, conn, server, ioloop = ioloop)
        for (cmd,perm) in cmd_perm_overrides.items():
            self.proto_cmds[cmd]['perm'] = perm
        self.proto_cmds['PASS']['arg'] = None

    def on_login(self, username):
        # Increase timeout after successful login.
        if username != 'anonymous':
            self.timeout = 7200

    def ftp_USER(self, line):
        if not self.authenticated:
            if line == 'anonymous':
                self.respond('331 Anonymous login ok, send your complete email address as your password.')
            else:
                self.respond('331 Username ok, send password.')
        else:
            self.flush_account()
            msg = 'Previous account information was flushed'
            self.log(msg)
            self.respond('331 %s, send password.' % msg)
        self.username = line

os.umask(0o027)

def run_ftpd():
    import argparse

    parser = argparse.ArgumentParser(description='MUD FTP daemon.')
    parser.add_argument('-P, --inherit', metavar='fd-number', type=int, dest='inherit',
        help=' Inherit filedescriptor <fd-number> from the parent process as socket to listen for connections.')
    args = parser.parse_args()

    if args.inherit:
        ftpd = FTPServer(socket.fromfd(args.inherit, socket.AF_INET6, socket.SOCK_STREAM), FTPHandler)
    else:
        ftpd = FTPServer(('', 2221), FTPHandler)

    # set a limit for connections
    ftpd.max_cons = 256
    ftpd.max_cons_per_ip = 5

    # start ftp server
    ftpd.serve_forever()

try:
    run_ftpd()
except KeyboardInterrupt:
    pass
