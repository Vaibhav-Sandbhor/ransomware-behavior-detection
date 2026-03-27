CVSS_RULES = {
    "ftp": 9.8,          # vsftpd backdoor, anonymous login
    "telnet": 9.0,       # plaintext creds
    "ssh": 6.5,          # brute force risk
    "smtp": 6.8,         # relay & enum risks
    "domain": 7.5,       # DNS cache poisoning
    "http": 7.2,         # web exploits
    "https": 5.5,        # encrypted but vulnerable apps
    "rpcbind": 8.0,
    "netbios-ssn": 8.5,
    "exec": 9.8,         # remote command execution
    "login": 8.8,
    "shell": 9.8,
    "java-rmi": 9.8,
    "bindshell": 10.0,
    "nfs": 8.0,
    "mysql": 7.8,
    "distccd": 9.8,
    "postgresql": 7.5,
    "vnc": 8.8,
    "X11": 8.0,
    "irc": 7.0,
    "ajp13": 8.0,
    "mountd": 7.5,
    "status": 6.0,
    "nlockmgr": 6.5
}
