MUD tools using D-Bus
=====================

FTPD
----
This is a FTP daemon using pyftpdlib.

The corresponding MUD needs to provide two objects via D-BUS with the following interfaces:
 * de.unitopia.Authentification
   * `int password(string user, string password, string application)`

     Check the given user and password. `application` will always be `"ftp"` in this case.
     Return a value > 0 for success.
 * de.unitopia.FTPAccess
   * `int check_permission(string wiz, string perm, string path)`

      Check the permissions of user `wiz` for `path`. Permission is a single character.

      Read permissions:
       - "e" = change directory (CWD command)
       - "l" = list files (LIST, NLST, STAT, MLSD, MLST commands)
       - "r" = retrieve file from the server (RETR command)

      Write permissions:
       - "a" = append data to an existing file (AxPPE command)
       - "d" = delete file (DELE command)
       - "f" = rename file or directory from (RNFR command)
       - "t" = rename file or directory to (RNTO command)
       - "m" = create directory (MKD command)
       - "n" = delete directory (RMD command)

The FTP daemon will be configured in the main program. See `ftpd-example.py` for an example.

License
-------
All tools are released under 2-clause BSD as given in COPYING.
