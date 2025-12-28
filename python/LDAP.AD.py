import argparse
import datetime
import linecache
import os
import re
import socket
import ssl
import sys
import threading
import traceback
import urllib
from datetime import datetime, timedelta
from typing import List

import ldap3
from future.utils import iteritems
from ldap3 import Entry
from ldap3 import MODIFY_ADD
from ldap3.core.exceptions import LDAPBindError
from ldap3.utils.ciDict import CaseInsensitiveDict

class Color:
    DEFAULT = '\033[99m'
    RESET = '\033[39m'

    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\033[92m'
    LIGHT_YELLOW = '\033[93m'
    LIGHT_BLUE = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'
    LIGHT_CYAN = '\033[96m'
    LIGHT_WHITE = '\033[97m'

    ERROR = RED
    ALERT = LIGHT_RED
    WARN = YELLOW
    INFO = DEFAULT
    DEBUG = MAGENTA
    SUCCESS = GREEN
    DISPLAY = DEFAULT
    END = "\033[0m"


class Logger:
    TO_SCREEN = True
    TO_FILE = False
    TIMESTAMP_ON_SCREEN = False
    LOGFILE = None
    DISPLAY_SRC = False
    VERBOSE = False
    DEBUG = False
    COLOR = True

    # Create a lock to synchronize access to the database
    lock = threading.Lock()

    @staticmethod
    def set_color(val=True):
        Logger.COLOR = val

    @staticmethod
    def enable_log_src():
        Logger.DISPLAY_SRC = True

    @staticmethod
    def set_log_to_screen(bool_temp=True):
        Logger.TO_SCREEN = bool_temp

    @staticmethod
    def set_log_to_file(bool_temp=True, directory=".", filename="processing.log"):
        Logger.TO_FILE = bool_temp
        Logger.LOGFILE = directory + filename

    @staticmethod
    def set_timestamp_on_screen(bool_temp=True):
        Logger.TIMESTAMP_ON_SCREEN = bool_temp

    @staticmethod
    def enable_debug():
        Logger.DEBUG = True

    @staticmethod
    def enable_verbose():
        Logger.VERBOSE = True

    @staticmethod
    def show_traceback_and_code_lines(exc=None, context_lines=2):
        trace = ""
        if exc is not None:
            # Extract the traceback from the exception
            tb = exc.__traceback__
            stack = traceback.extract_tb(tb)
        else:
            # Extract the current stack and remove the last entry
            stack = traceback.extract_stack()[:-3]

        for frame in reversed(stack):
            filename, lineno, name, line = frame

            print(f'FILE: {filename}, FUNCTION: {name}, LINE: {lineno}')

            start = max(1, lineno - context_lines)
            for i in range(start, lineno + context_lines + 1):
                line = linecache.getline(filename, i).rstrip('\n')
                mark = '=>' if i == lineno else '  '
                trace += f'{i:3}{mark} {line}\n'

        return trace

    @staticmethod
    def _log(level, message, end=None):
        traceback_message = None
        if Logger.DISPLAY_SRC:
            traceback_message = Logger.show_traceback_and_code_lines()

        current_time = f"[{str(datetime.now())}] "
        current_time_scr = current_time
        if not Logger.TIMESTAMP_ON_SCREEN:
            current_time_scr = ""

        color = None
        txt = ""
        with Logger.lock:
            try:
                if level == "ERROR":
                    color = Color.ERROR
                    txt = "[ERROR]   "
                elif level == "ALERT":
                    color = Color.ALERT
                    txt = "[ALERT]   "
                elif level == "WARN":
                    color = Color.WARN
                    txt = "[WARN]    "
                elif level == "INFO":
                    color = Color.INFO
                    txt = "[INFO]    "
                elif Logger.DEBUG and level == "DEBUG":
                    color = Color.DEBUG
                    txt = "[DEBUG]   "
                elif Logger.VERBOSE and level == "VERBOSE":
                    color = Color.DEBUG
                    txt = "[VERBOSE] "
                elif level == "SUCCESS":
                    color = Color.SUCCESS
                    txt = "[SUCCESS] "
                elif level == "DISPLAY":
                    color = Color.DISPLAY
                    txt = "          "
            except Exception as e:
                if Logger.COLOR:
                    print(f"{Color.ERROR}{current_time} [ERROR] [{e}{Color.END}")
                else:
                    print(f"{current_time} [ERROR] [{e}")

        if Logger.TO_SCREEN:
            if end:
                if Logger.COLOR:
                    print(f"{color}{current_time_scr}{txt}{message}{Color.END}", end=end)
                else:
                    print(f"{current_time_scr}{txt}{message}", end=end)
            else:
                if Logger.COLOR:
                    print(f"{color}{current_time_scr}{txt}{message}{Color.END}")
                else:
                    print(f"{current_time_scr}{txt}{message}")
            if traceback_message:
                print(f"{traceback_message}")
        if Logger.TO_FILE and Logger.LOGFILE:
            with open(Logger.LOGFILE, "a") as file:
                file.write(f"{current_time}{txt}{message}\n")
                if traceback_message:
                    file.write(f"{traceback_message}\n")

    @staticmethod
    def error(message=""):
        Logger._log("ERROR", message)

    @staticmethod
    def alert(message=""):
        Logger._log("ALERT", message)

    @staticmethod
    def warn(message=""):
        Logger._log("WARN", message)

    @staticmethod
    def info(message=""):
        Logger._log("INFO", message)

    @staticmethod
    def success(message=""):
        Logger._log("SUCCESS", message)

    @staticmethod
    def verbose(message=""):
        if Logger.VERBOSE:
            Logger._log("VERBOSE", message)

    @staticmethod
    def debug(message=""):
        if Logger.DEBUG:
            Logger._log("DEBUG", message)

    @staticmethod
    def display(message="", end=None):
        Logger._log("DISPLAY", message, end)


class Display:
    RULER = "-"

    @staticmethod
    def input(line):
        Logger.display(line, end=" ")
        return input()

    @staticmethod
    def yn(line, default=None):
        valid = {"yes": True, "y": True,
                 "no": False, "n": False}
        prompt = ""
        if default is None:
            prompt = " [y/n] "
        elif (default.lower() == "yes") or (default.lower() == "y"):
            prompt = " [Y/n] "
        elif (default.lower() == "no") or (default.lower() == "n"):
            prompt = " [y/N] "
        else:
            Logger.alert("Please provide a valid default value: no, n, yes, y, or None")

        while True:
            choice = Display.input(line + prompt)
            if default is not None and choice == '':
                return valid[default.lower()]
            elif choice.lower() in valid:
                return valid[choice.lower()]
            else:
                Logger.alert("Please respond with 'yes/no' or 'y/n'.")

    @staticmethod
    def heading(line):
        Logger.display(Display.RULER * len(line))
        Logger.display(line.upper())
        Logger.display(Display.RULER * len(line))

    @staticmethod
    def print_list(_list, title=None):
        if title:
            Display.heading(title)

        if _list:
            for item in _list:
                Logger.display(item)
        else:
            Logger.display("None")

        Logger.display()

    @staticmethod
    def select_list(line, input_list, show_numbers=True):
        answers = []

        if input_list:
            i = 1
            for item in input_list:
                if show_numbers:
                    Logger.display(str(i) + ": " + str(item))
                else:
                    Logger.display(str(item))
                i = i + 1
        else:
            return answers

        choice = Display.input(line)
        if not choice:
            return answers

        answers = (choice.replace(' ', '')).split(',')
        return answers

    @staticmethod
    def longest_string_in_column(_data, column_index):
        longest = 0
        for row in _data:
            if row[column_index] is not None:
                if len(str(row[column_index])) > longest:
                    longest = len(str(row[column_index]))
        return longest

    @staticmethod
    def print_multi_column_list(_data):
        # Determine the maximum width of each column
        column_widths = []
        for i in range(len(_data[0])):
            column_widths.append(Display.longest_string_in_column(_data, i))

        # Print the top border
        s = '+'
        for width in column_widths:
            s += '-' * (width + 2) + '+'
        Logger.display(s)

        # Print the headers
        s = '|'
        for i, column in enumerate(_data[0]):
            s += ' ' + column.center(column_widths[i]) + ' |'
        Logger.display(s)

        # Print the separator
        s = '+'
        for width in column_widths:
            s += '-' * (width + 2) + '+'
        Logger.display(s)

        # Print the data
        for row in _data[1:]:
            s = '|'
            for i, column in enumerate(row):
                s += ' ' + column.ljust(column_widths[i]) + ' |'
            Logger.display(s)

        # Print the bottom border
        s = '+'
        for width in column_widths:
            s += '-' * (width + 2) + '+'
        Logger.display(s)

        Logger.display()



class LDAP_AD(object):
    _user_filter = '(objectcategory=user)'
    _user_attributes = [
        # 'cn',
        # 'name',
        'sAMAccountName',
        'memberOf',
        # 'primaryGroupId',
        # 'whenCreated',
        # 'whenChanged',
        'lastLogon',
        # 'userAccountControl',
        'pwdLastSet',
        # 'objectSid',
        'description',
        # 'comment',
        'lockoutTime',
        'userPassword',
        'distinguishedName',
        # 'objectClass'
    ]

    _group_filter = '(objectcategory=group)'
    _group_attributes = [
        # 'cn',
        # 'name',
        'sAMAccountName',
        'memberOf',
        'description',
        # 'whenCreated',
        # 'whenChanged',
        # 'objectSid',
        # 'distinguishedName',
        # 'objectClass'
    ]

    _computer_filter = '(objectcategory=computer)'
    _computer_attributes = [
        # 'cn',
        # 'sAMAccountName',
        'dNSHostName',
        'operatingSystem',
        # 'operatingSystemServicePack',
        # 'operatingSystemVersion',
        # 'lastLogon',
        # 'userAccountControl',
        # 'whenCreated',
        # 'objectSid',
        # 'primaryGroupID',
        # 'description',
        # 'distinguishedName',
        # 'objectClass'
    ]

    _passpol_filter = '(objectClass=domain)'
    _passpol_attributes = [
        'pwdProperties',
        'maxPwdAge',
        'minPwdAge',
        'minPwdLength',
        'pwdHistoryLength',
        'lockoutDuration',
        'lockoutObservationWindow',
        'lockoutThreshold'
    ]

    _pass_flags = {
        'PASSWORD_COMPLEX': 0x01,
        'PASSWORD_NO_ANON_CHANGE': 0x02,
        'PASSWORD_NO_CLEAR_CHANGE': 0x04,
        'LOCKOUT_ADMINS': 0x08,
        'PASSWORD_STORE_CLEARTEXT': 0x10,
        'REFUSE_PASSWORD_CHANGE': 0x20
    }

    _uac_flags = {
        'ACCOUNT_DISABLED': 0x00000002,
        'ACCOUNT_LOCKED': 0x00000010,
        'PASSWD_NOTREQD': 0x00000020,
        'PASSWD_CANT_CHANGE': 0x00000040,
        'PASSWORD_STORE_CLEARTEXT': 0x00000080,
        'NORMAL_ACCOUNT': 0x00000200,
        'WORKSTATION_ACCOUNT': 0x00001000,
        'SERVER_TRUST_ACCOUNT': 0x00002000,
        'DONT_EXPIRE_PASSWD': 0x00010000,
        'SMARTCARD_REQUIRED': 0x00040000,
        'TRUSTED_FOR_DELEGATION': 0x00080000,
        'NOT_DELEGATED': 0x00100000,
        'USE_DES_KEY_ONLY': 0x00200000,
        'DONT_REQ_PREAUTH': 0x00400000,
        'PASSWORD_EXPIRED': 0x00800000,
        'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x01000000,
        'PARTIAL_SECRETS_ACCOUNT': 0x04000000
    }

    _functional_levels = {
        0: "2000 Mixed/Native",
        1: "2003 Interim",
        2: "2003",
        3: "2008",
        4: "2008 R2",
        5: "2012",
        6: "2012 R2",
        7: "2016 / 2019 / 2022"
    }

    _common_sids = {
        "S-1-0": ("Null Authority", "USER"),
        "S-1-0-0": ("Nobody", "USER"),
        "S-1-1": ("World Authority", "USER"),
        "S-1-1-0": ("Everyone", "GROUP"),
        "S-1-2": ("Local Authority", "USER"),
        "S-1-2-0": ("Local", "GROUP"),
        "S-1-2-1": ("Console Logon", "GROUP"),
        "S-1-3": ("Creator Authority", "USER"),
        "S-1-3-0": ("Creator Owner", "USER"),
        "S-1-3-1": ("Creator Group", "GROUP"),
        "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
        "S-1-3-3": ("Creator Group Server", "COMPUTER"),
        "S-1-3-4": ("Owner Rights", "GROUP"),
        "S-1-4": ("Non-unique Authority", "USER"),
        "S-1-5": ("NT Authority", "USER"),
        "S-1-5-1": ("Dialup", "GROUP"),
        "S-1-5-2": ("Network", "GROUP"),
        "S-1-5-3": ("Batch", "GROUP"),
        "S-1-5-4": ("Interactive", "GROUP"),
        "S-1-5-6": ("Service", "GROUP"),
        "S-1-5-7": ("Anonymous", "GROUP"),
        "S-1-5-8": ("Proxy", "GROUP"),
        "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
        "S-1-5-10": ("Principal Self", "USER"),
        "S-1-5-11": ("Authenticated Users", "GROUP"),
        "S-1-5-12": ("Restricted Code", "GROUP"),
        "S-1-5-13": ("Terminal Server Users", "GROUP"),
        "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
        "S-1-5-15": ("This Organization", "GROUP"),
        "S-1-5-17": ("IUSR", "USER"),
        "S-1-5-18": ("Local System", "USER"),
        "S-1-5-19": ("NT Authority", "USER"),
        "S-1-5-20": ("Network Service", "USER"),
        "S-1-5-80-0": ("All Services ", "GROUP"),
        "S-1-5-32-544": ("Administrators", "GROUP"),
        "S-1-5-32-545": ("Users", "GROUP"),
        "S-1-5-32-546": ("Guests", "GROUP"),
        "S-1-5-32-547": ("Power Users", "GROUP"),
        "S-1-5-32-548": ("Account Operators", "GROUP"),
        "S-1-5-32-549": ("Server Operators", "GROUP"),
        "S-1-5-32-550": ("Print Operators", "GROUP"),
        "S-1-5-32-551": ("Backup Operators", "GROUP"),
        "S-1-5-32-552": ("Replicators", "GROUP"),
        "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
        "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
        "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
        "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
        "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
        "S-1-5-32-559": ("Performance Log Users", "GROUP"),
        "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
        "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
        "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
        "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
        "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
        "S-1-5-32-573": ("Event Log Readers", "GROUP"),
        "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
        "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
        "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
        "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
        "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
        "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
        "S-1-5-32-582": ("Storage Replica Administrators", "GROUP")
    }

    def __init__(self, connection, ip_mode=ldap3.IP_V4_ONLY, timeout=10):
        self.connection = connection.copy()

        self.connection['password'] = self.handle_password_and_hash()
        self.connection['kerberos'] = 'kerberos' in connection.get('auth')
        self.connection['ssl'] = 'ldaps' in connection.get('protocol')
        self.connection['null_bind'] = 'anonymous' in connection.get('auth')

        self._username = self.connection.get('username')
        self._password = self.connection.get('password')
        self._domain = self.connection.get('domain')

        self._ssl = False
        if self.connection.get('ssl'):
            self._ssl = True

        self._ip_mode = ip_mode
        self._timeout = timeout
        self._base_dn = ""
        self._distinguished_name = None
        self._functional_level_domain = None
        self._functional_level_forest = None
        self._functional_level_domaincontroller = None

        self._ldap_client = None
        self._ldap_server = None
        self._tls = None

        result = self.query_rootdse(self.connection.get('ip'))
        if result:
            self._base_dn = result.info.other['defaultNamingContext'][0]
            self._functional_level_domain = result.info.other['domainFunctionality'][0]
            self._functional_level_forest = result.info.other['forestFunctionality'][0]
            self._functional_level_domaincontroller = result.info.other['domainControllerFunctionality'][0]
        if not self._base_dn:
            temp_dn = self._domain.replace('.', ',dc=')
            self._base_dn = 'dc={0}'.format(temp_dn)

        self.prepare_connection()
        self._authuser_dn = self.get_authenticated_user_dn()

    def handle_password_and_hash(self):
        password = None
        if 'password' in self.connection.get('auth'):
            password = self.connection.get('password')
        nt_hash = None
        if '_nt' in self.connection.get('auth'):
            nt_hash = self.connection.get('password')
            if nt_hash and ":" in nt_hash:
                temp = nt_hash.split(':')
                nt_hash = ("aad3b435b51404eeaad3b435b51404ee:" + temp[1]).upper()
        return password if not nt_hash else nt_hash

    def prepare_ssl(self):
        if self.connection.get('ssl'):
            self._tls = ldap3.Tls(validate=ssl.CERT_NONE)

    def prepare_server(self):
        self.prepare_ssl()
        self._ldap_server = ldap3.Server(self.connection.get('ip'),
                                         port=int(self.connection.get('port')),
                                         use_ssl=self.connection.get('ssl'),
                                         tls=self._tls,
                                         get_info=ldap3.ALL,
                                         mode=self._ip_mode,
                                         connect_timeout=self._timeout)
        Logger.debug(f'Connecting to LDAP server at "{self.connection.get("ip")}:{self.connection.get("port")}"...')

    def prepare_connection(self):
        self.prepare_server()
        try:
            if self.connection.get('null_bind'):
                Logger.debug("LDAP Connection method: NULL BIND")
                self._ldap_client = ldap3.Connection(self._ldap_server)
            elif self.connection.get('kerberos'):
                Logger.debug("LDAP Connection method: Kerberos TGT")
                self._ldap_client = ldap3.Connection(self._ldap_server,
                                                     sasl_credentials=(self._ldap_server,),
                                                     authentication=ldap3.SASL,
                                                     sasl_mechanism=ldap3.KERBEROS,
                                                     raise_exceptions=True,
                                                     receive_timeout=self._timeout,
                                                     auto_range=True,
                                                     return_empty_attributes=False)
            elif self.connection.get('password'):
                Logger.debug("LDAP Connection method: domain\\username + password or NTHash")
                self._ldap_client = ldap3.Connection(self._ldap_server,
                                                     user=self.connection.get('domain') + '\\' + self.connection.get(
                                                         'username'),
                                                     password=self.connection.get('password'),
                                                     authentication=ldap3.NTLM,
                                                     raise_exceptions=True,
                                                     receive_timeout=self._timeout,
                                                     auto_range=True,
                                                     return_empty_attributes=False)
            else:
                Logger.error("No proper set of authentication credentials or methods provided.")
                exit(1)

            if self._ldap_client.bind():
                Logger.debug("LDAP connection successful.")
            else:
                Logger.error("LDAP connection failed.")
                exit(1)
        except ldap3.core.exceptions.LDAPOperationsErrorResult as e:
            if 'perform this operation a successful bind' in str(e):
                Logger.error(f'{e} - Although an initial connection was made, a bind failed to connect.')
            exit(1)
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            if 'invalid server address' in str(e):
                Logger.error(f'{e} - An invalid server address was provided.')
            elif ('unreachable' in str(e)) or ('timed out' in str(e)):
                Logger.error(
                    f'{e} - This host is unreachable; please check the IP address/hostname or the network connection.')
            else:
                Logger.error(e)
            exit(1)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
            if 'invalidCredentials' in str(e):
                Logger.error(f'{e} - Invalid credentials or domain were provided.')
            exit(1)
        except Exception as e:
            Logger.error(e)
            exit(1)

    @staticmethod
    def has_attribute(obj, attribute):
        try:
            value = obj[attribute]
            if value:
                return True
            return False
        except Exception as ex:
            Logger.error(f'{ex} - Could not find attribute {attribute}')
            return False

    def get_authenticated_user_dn(self):
        search_filter = f'(sAMAccountName={self._username})'
        search_attributes = ['distinguishedName']
        results = self.query(search_filter=search_filter,
                             attributes=search_attributes)
        if results:
            return results[0]["distinguishedName"][0]
        else:
            return self._ldap_client.user

    def get_user_dn(self, username):
        search_filter = f'(sAMAccountName={username})'
        search_attributes = ['distinguishedName']
        results = self.query(search_filter=search_filter,
                             attributes=search_attributes)
        if results:
            return results[0]["distinguishedName"][0]
        return None

    def query(self, base_dn=None, search_filter='(objectClass=site)', attributes=None, query_limit=1000,
              page_size=500, search_scope=ldap3.SUBTREE):

        if not attributes:
            attributes = ldap3.NO_ATTRIBUTES

        temp_base_dn = self._base_dn
        if base_dn:
            temp_base_dn = base_dn

        """Get all the Active Directory results from LDAP using a paging approach.
           By default Active Directory will return 1,000 results per query before it errors out."""
        self._ldap_client.extend.standard.paged_search(search_base=temp_base_dn,
                                                       search_filter=search_filter,
                                                       search_scope=search_scope,
                                                       paged_criticality=True,
                                                       time_limit=query_limit,
                                                       attributes=attributes,
                                                       paged_size=page_size,
                                                       generator=False)
        return self._ldap_client.entries

    @staticmethod
    def map_flags(attr, flags_def):
        outflags = []
        if attr is None:
            return outflags
        for flag, val in iteritems(flags_def):
            if isinstance(attr, str):
                if int(attr) & val:
                    outflags.append(flag)
            else:
                if attr & val:
                    outflags.append(flag)
        return outflags

    def add_user(self, fname="john", lname="doe", accountname="jdoe", password="SuperSecret123!"):
        user_dn = f'CN={fname} {lname},CN=Users,{self._base_dn}'
        user_attrs = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'cn': f'{fname} {lname}',
            'givenName': fname,
            'sn': lname,
            'userPrincipalName': f'{fname}.{lname}@{self._domain}',
            'sAMAccountName': accountname,
            'userPassword': password,
            'mail': f'{fname}.{lname}@{self._domain}',
            'telephoneNumber': '+1 555-123-4567',
            'memberOf': [f'CN=Users,CN=Builtin,{self._base_dn}']
        }
        result = self._ldap_client.add(user_dn, ['user'], user_attrs)
        return result

    def get_domain_sid(self):
        results = self.query(search_filter="(objectClass=domain)", attributes=["objectSid"])
        sid = results[0]["objectSid"].value
        return sid

    def get_passpol(self):
        result = self.query(search_filter=self._passpol_filter, attributes=self._passpol_attributes)
        passpol = {}
        if result:
            for entry in result:
                # Assuming `entry` is an LDAP entry object
                entry_attributes = entry.entry_attributes_as_dict

                # Iterate over the attributes and values of the entry
                for attr_name, attr_values in entry_attributes.items():
                    passpol[attr_name] = attr_values[0]
        return passpol

    def get_sites(self):
        sites = {}
        try:
            base_dn = "CN=Sites,CN=Configuration," + self._base_dn
            results = self.query(base_dn=base_dn,
                                 search_filter='(objectClass=site)',
                                 attributes=['name',
                                             'siteObjectBL',
                                             'msDS-Site-Affinity'])
            for _entry in results:
                site_name = _entry['name'][0]
                network_list = []

                try:
                    network_list = _entry['siteObjectBL']
                except KeyError:
                    pass

                network_names = []
                for network in network_list:
                    network_name = network.split(',')[0].split('=')[1]
                    network_names.append(network_name)
                sites[site_name] = network_names
            return sites
        except LDAPBindError as e:
            Logger.error(e)
        except Exception as e:
            Logger.error(e)
        return []

    def get_maq(self):
        result = self.query(search_filter='(objectClass=domain)', attributes=['ms-DS-MachineAccountQuota'])
        return str(result[0]["ms-DS-MachineAccountQuota"])

    def process_attribute(self, att, value):
        if att == "userAccountControl":
            return ', '.join(self.map_flags(value, self._uac_flags))
        else:
            return value

    def get_users(self):
        users = []
        # result = self.query(search_filter=self._user_filter, attributes=ldap3.ALL_ATTRIBUTES)
        result = self.query(search_filter=self._user_filter, attributes=self._user_attributes)

        if result:
            for entry in result:
                temp_user = {}
                entry_attributes = entry.entry_attributes_as_dict
                for attr_name, attr_values in entry_attributes.items():
                    temp_user[attr_name] = self.process_attribute(attr_name, attr_values[0])
                users.append(temp_user)
        return users

    def get_user_info(self, user):
        # If user is a DN, use it directly, otherwise build the DN from the username
        if user.startswith('cn=') or user.startswith('CN='):
            user_dn = user
        else:
            user_dn = self.get_user_dn(user)

        if user_dn:
            results = self.query(base_dn=user_dn, search_filter=self._user_filter, attributes=self._user_attributes)
            info = {}
            if results:
                entry = results[0]
                entry_attributes = entry.entry_attributes_as_dict
                for attr_name, attr_values in entry_attributes.items():
                    info[attr_name] = self.process_attribute(attr_name, attr_values[0])
            return info
        return []

    def get_computers(self):
        computers = []
        result = self.query(search_filter=self._computer_filter, attributes=self._computer_attributes)
        if result:
            for entry in result:
                temp_computer = {}
                entry_attributes = entry.entry_attributes_as_dict
                for attr_name, attr_values in entry_attributes.items():
                    temp_computer[attr_name] = self.process_attribute(attr_name, attr_values[0])
                computers.append(temp_computer)
        return computers

    def add_computer(self, computer_name, computer_password):
        # Create a new computer object
        computer_dn = "CN={0},CN=Computers,{1}".format(computer_name, self._base_dn)
        computer_attrs = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
            'sAMAccountName': computer_name + "$",
            'userAccountControl': '4096'
        }
        self._ldap_client.add(computer_dn, ['computer'], computer_attrs)

        # Set the computer's password
        password_attrs = {'unicodePwd': '"{}"'.format(computer_password).encode('utf-16-le')}
        self._ldap_client.modify(computer_dn, password_attrs)

        # Add the computer to the default computers group
        group_dn = "CN=Computers,CN=Users,{0}".format(self._base_dn)
        self._ldap_client.modify(group_dn, {'member': [(MODIFY_ADD, [computer_dn])]})

    def get_groups(self):
        groups = []
        result = self.query(search_filter=self._group_filter, attributes=self._group_attributes)

        if result:
            for entry in result:
                temp_group = {}
                entry_attributes = entry.entry_attributes_as_dict
                for attr_name, attr_values in entry_attributes.items():
                    temp_group[attr_name] = self.process_attribute(attr_name, attr_values[0])
                groups.append(temp_group)
        return groups

    def get_group_info(self, group_name):
        search_filter = f'(cn={group_name})'
        results = self.query(search_filter=search_filter, attributes=ldap3.ALL_ATTRIBUTES)  # self._group_attributes)
        return results[0]

    def get_group_members(self, group):
        # If group is a DN, use it directly, otherwise build the DN from the group name
        if group.startswith('cn=') or group.startswith('CN='):
            group_dn = group
        else:
            group_dn = self.get_group_info(group)["distinguishedName"][0]

        results = self.query(
            search_filter=f'(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))',
            attributes=ldap3.ALL_ATTRIBUTES)

        members = []
        if results:
            for entry in results:
                members.append(entry['sAMAccountName'][0])
        return members

    def get_group_rid(self, group_dn):
        """Return the RID (last part of the objectSid) for the given group DN."""
        results = self.query(search_filter=f'(distinguishedName={group_dn})',
                             attributes=['objectSid'])
        if not results:
            return None
        sid = results[0]['objectSid'].value
        # SID format: S-1-5-21-...-RID
        return int(sid.split('-')[-1])

    def get_nested_group_members(self, group):
        """
        Return all user sAMAccountNames that are direct or nested members of the given group,
        including the case where the group is set as the primary group.
        """
        # Normalize group input (accept name or DN)
        if group.lower().startswith('cn='):
            group_dn = group
        else:
            group_dn = self.get_group_info(group)["distinguishedName"][0]

        # Resolve group RID for primaryGroupID check
        group_rid = self.get_group_rid(group_dn)
        if not group_rid:
            Logger.error(f"Could not resolve RID for group: {group}")
            return []

        # Build filter
        search_filter = (
            f'(&(objectCategory=person)(sAMAccountType=805306368)'
            f'(|(memberOf:1.2.840.113556.1.4.1941:={group_dn})(primaryGroupID={group_rid})))'
        )

        results = self.query(search_filter=search_filter, attributes=['sAMAccountName'])
        members = []
        if results:
            for entry in results:
                try:
                    members.append(entry['sAMAccountName'][0])
                except Exception:
                    continue
        return members

    @staticmethod
    def convert_ad_timestamp(attribute):
        # Extract the actual value from the attribute
        timestamp = attribute.value

        # Convert to seconds from 100-nanosecond intervals
        seconds_since_1601 = timestamp / 1e7

        # Define the start date
        start_date = datetime(1601, 1, 1)

        # Add the seconds to the start date
        date = start_date + timedelta(seconds=seconds_since_1601)

        # Convert to desired string format
        date_str = date.strftime('%Y-%m-%d %H:%M:%S')

        return date_str

    def check_laps(self):
        results = self.query(search_filter="(objectClass=*)",
                             attributes=['*'])

        if 'ms-Mcs-AdmPwd' in results[0]:
            return True

        return False

    def get_laps(self):
##        Logger.alert("Ai.1")
##        if not self.check_laps():
#            Logger.alert("LAPS is NOT enabled")
#            return []

        results = self.query(search_filter="(&(objectCategory=computer)(ms-MCS-AdmPwd=*))",
                             attributes=['ms-MCS-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'dNSHostName'])


        laps = []
        for entry in results:
            fqdn = entry['dNSHostName'][0]
            pwd = entry['ms-Mcs-AdmPwd']
            date_stamp = LDAP_AD.convert_ad_timestamp(entry['ms-Mcs-AdmPwdExpirationTime'])
            line = f'{fqdn} {pwd} {date_stamp}'
            laps.append(line)
        return laps

    def get_dcs(self):
        dcs = []
        results = self.query(
            search_filter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=['dNSHostName'])
        for entry in results:
            dcs.append(entry['dNSHostName'][0])
        return dcs

    def get_trusts(self):
        results = self.query(
            search_filter='(objectClass=trustedDomain)',
            attributes=['cn','securityIdentifier','name','trustDirection','trustPartner','trustType','trustAttributes','flatName'])
#            attributes=ldap3.ALL_ATTRIBUTES)
        print(results)
        return results

    def get_adcstemplates(self):
        print("CN=Configuration,"+self._base_dn)
        results = self.query(
                base_dn="CN=Configuration,"+self._base_dn,

#            search_filter='(objectCategory=pKIEnrollmentService)',
#            attributes=[
#                "cn",
#                "name",
#                "dNSHostName",
#                "cACertificateDN",
#                "cACertificate",
#                "certificateTemplates",
#                "objectGUID",])

#	    search_filter='(&(cn=SCCMCMGTemplate)(objectClass=pKICertificateTemplate))',
#            attributes=["cn",
#                "name",
#                "displayName",
#                "pKIExpirationPeriod",
#                "pKIOverlapPeriod",
#                "msPKI-Enrollment-Flag",
#                "msPKI-Private-Key-Flag",
#                "msPKI-Certificate-Name-Flag",
#                "msPKI-Minimal-Key-Size",
#                "msPKI-RA-Signature",
#                "pKIExtendedKeyUsage",
#                "nTSecurityDescriptor",
#                "objectGUID"])
            search_filter='(objectGUID=f8a90988-86ed-4c81-8054-5cdd943d76fe)',
#            search_filter='(objectGUID=3480c81f-4e67-4e52-be15-708d1292dd15)',
            attributes=ldap3.ALL_ATTRIBUTES)
        print(results)
        return results

    def get_gpo(self):
        results = self.query(search_filter='(objectClass=groupPolicyContainer)',
                             attributes=['displayName', 'gPCFileSysPath'])
        gpos = {}
        if results:
            for entry in results:
                temp_gpos = []
                for attr in entry:
                    temp_gpos.append(attr.value)
                gpos[entry.entry_dn] = temp_gpos
            return gpos
        return []

    def sid_to_name_and_type(self, sid):
        search_filter = f'(objectSid={sid})'
        search_attributes = ['cn', 'objectClass']
        results = self.query(search_filter=search_filter, attributes=search_attributes)

        if not results:
            return None, None

        name = results[0]['cn'].value
        object_classes = results[0]['objectClass'].value
        object_type = None

        if 'group' in object_classes:
            object_type = 'GROUP'
        elif 'user' in object_classes:
            object_type = 'USER'

        return name, object_type

    def get_admincount(self):
        admincount = {}
        results = self.query(search_filter='(&(adminCount=1)(objectcategory=user))',
                             attributes=['sAMAccountName',
                                         'distinguishedName'])
        temp_list = []
        for entry in results:
            temp_list.append(entry["sAMAccountName"][0])
        admincount["users"] = temp_list

        results = self.query(search_filter='(&(adminCount=1)(objectcategory=group))',
                             attributes=['sAMAccountName',
                                         'distinguishedName'])
        temp_list = []
        for entry in results:
            temp_list.append(entry["sAMAccountName"][0])
        admincount["groups"] = temp_list

        results = self.query(search_filter='(&(adminCount=1)(objectcategory=computer))',
                             attributes=['sAMAccountName',
                                         'distinguishedName'])
        temp_list = []
        for entry in results:
            temp_list.append(entry["sAMAccountName"][0])
        admincount["computers"] = temp_list

        return admincount

    def change_user_password(self, target_user, new_password, old_password=None):
        if not self._ssl:  # Changing a password requires SSL
            return False

        target_dn = self.get_user_dn(target_user)
        if target_dn:
            return self._ldap_client.extend.microsoft.modify_password(target_dn, new_password,
                                                                      old_password=old_password)

    @staticmethod
    def query_rootdse(server_ip):
        try:
            if 'ldaps' in server_ip:
                tls_config = ldap3.Tls(validate=ssl.CERT_NONE)
                server = ldap3.Server(server_ip,
                                      port=636,
                                      use_ssl=True,
                                      tls=tls_config,
                                      get_info=ldap3.ALL)
            else:
                server = ldap3.Server(server_ip,
                                      get_info=ldap3.ALL)
            conn = ldap3.Connection(server)
            conn.bind()

            conn.search(search_base='',
                        search_scope=ldap3.BASE,
                        search_filter='(objectClass=*)',
                        attributes=ldap3.NO_ATTRIBUTES)
            conn.unbind()
            return server
        except Exception as e:
            traceback.print_exc()
            Logger.error(e)
            return None

    def requires_signing(self):
        for server in self.get_dcs():
            # Set up the LDAP connection with the server
            if self._authuser_dn:
                conn = ldap3.Connection(server,
                                        user=self._distinguished_name,
                                        password=self._password,
                                        client_strategy='SYNC',
                                        receive_timeout=self._timeout)
            else:
                conn = ldap3.Connection(server,
                                        authentication=ldap3.NTLM,
                                        user=self._domain + '\\' + self._username,
                                        password="Farmer",
                                        client_strategy='SYNC',
                                        receive_timeout=self._timeout)

            conn.bind()
            # Check if the server requires signing
            if conn.tls_started:
                conn.unbind()
                Logger.debug(f"LDAP Server {server} requires signing")
#                return True
            else:
                conn.unbind()
                Logger.alert(f"LDAP Server {server} does NOT require signing")
#                return False

    def get_unconstrained(self):
        results = []
        result = self.query(
            search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            attributes=['sAMAccountName'])

        if result:
            for entry in result:
                results.append(entry["sAMAccountName"][0])
        return results

    def get_asrep(self):
        results = []
        result = self.query(
            search_filter='(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            attributes=['sAMAccountName'])

        if result:
            for entry in result:
                results.append(entry["sAMAccountName"][0])
        return results

    def get_constrained(self):
        results = []
        result = self.query(
            search_filter='(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            attributes=['sAMAccountName'])

        if result:
            for entry in result:
                results.append(entry["sAMAccountName"][0])
        return results

    def get_PASSWD_NOTREQD(self):
        results = []
        result = self.query(search_filter='(userAccountControl:1.2.840.113556.1.4.803:=32)',
                            attributes=['sAMAccountName', 'userAccountControl', 'cn'])

        if result:
            for entry in result:
                results.append(entry["sAMAccountName"][0])
        return results

    def get_DONT_EXPIRE_PASSWD(self):
        results = []
        result = self.query(search_filter='(userAccountControl:1.2.840.113556.1.4.803:=65536)',
                            attributes=['sAMAccountName', 'userAccountControl', 'cn'])

        if result:
            for entry in result:
                results.append(entry["sAMAccountName"][0])
        return results

    def get_unsupported_os(self):
        results = []
        # Calculate the timestamp for one year ago
        one_year_ago = datetime.now() - timedelta(days=365)
        one_year_ago_timestamp = int(one_year_ago.timestamp() * 10000000) + 116444736000000000

        _filter = '(&(lastLogonTimestamp>={})(|(operatingSystem=*2000*)(operatingSystem=*2003*)(operatingSystem=*2008*)(operatingSystem=*XP*)(operatingSystem=*Vista*)(operatingSystem=*7*)(operatingSystem=*ME*)))'.format(
            one_year_ago_timestamp)
        result = self.query(search_filter=_filter, attributes=self._computer_attributes)

        if result:
            for entry in result:
                dns = entry["dNSHostName"]
                os_val = entry["operatingSystem"]
                results.append(f'{os_val}, {dns}')
        return results


queries = {
    '1': ('get_domain_sid', 'Get the domain SID'),
    '2': ('get_sites', 'Get domain sites'),
    '3': ('get_passpol', 'Get password policy'),
    '4': ('get_admincount', 'Get admincount'),
    '5': ('get_users', 'Get users'),
    '6': ('get_groups', 'Get groups'),
    '7': ('get_computers', 'Get computers'),
    '8': ('get_maq', 'Get MAQ'),
    '9': ('get_dcs', 'Get DC list'),
    '10': ('requires_signing', 'Check if signing is required for a server'),
    '11': ('get_laps', 'Get LAPS'),
    '12': ('get_user_info', 'Get user info'),
    '13': ('get_group_members', 'Get group members'),
    '14': ('sid_to_name_and_type', 'Convert SID to user and type'),
    '15': ('get_unconstrained', 'Get unconstrained delegation'),
    '16': ('get_constrained', 'Get constrained delegation'),
    '17': ('get_asrep', 'Get ASREP'),
    '18': ('get_PASSWD_NOTREQD', 'Get accounts without password requirement'),
    '19': ('get_DONT_EXPIRE_PASSWD', 'Get accounts with non-expiring passwords'),
    '20': ('get_unsupported_os', 'Get unsupported operating systems'),
    '21': ('get_trusts', 'Get Domain Trusts'),
    '22': ('get_adcstemplates', 'Get List of ADCS Templates'),
    '23': ('get_nested_group_members', 'Get Nested Group Members'),
}

queries_with_args = {
#    '10': True,
    '12': True,
    '13': True,
    '14': True,
    '23': True,
}


def perform_query(ldap, query, args=None):
    # Check if the method exists in the queries dictionary
    if query in queries:
        # Get the method name from the queries dictionary
        method_name = queries[query][0]
        # Check if the method exists in the ldap object
        if hasattr(ldap, method_name):
            # Get the method from the ldap object
            func = getattr(ldap, method_name)
            # Check if the method requires arguments
            if query in queries_with_args:
                results = func(args)
            else:
                results = func()
            pretty_print(results)
        else:
            Logger.alert(f"Invalid method: {method_name}")
    else:
        Logger.alert(f"Invalid option: {query}")


def pretty_print(obj, indent=0):
    if not obj:
        return
    if isinstance(obj, str):
        print(' ' * indent + obj)
    elif isinstance(obj, bytes):
        try:
            print(' ' * indent + obj.decode("utf-8"))
        except UnicodeDecodeError:
            print(' ' * indent + str(obj))
    elif isinstance(obj, int) or isinstance(obj, bool):
        print(' ' * indent + str(obj))
    elif isinstance(obj, datetime) or isinstance(obj, timedelta):
        print(' ' * indent + str(obj))
    elif isinstance(obj, list):
        for item in obj:
            pretty_print(item, indent + 2)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            print(' ' * (indent + 2) + str(key) + ':')
            pretty_print(value, indent + 4)
    elif isinstance(obj, CaseInsensitiveDict):
        for key, value in obj.items():
            print(' ' * (indent + 2) + str(key) + ':')
            pretty_print(value, indent + 4)
    # elif not isinstance(obj, CaseInsensitiveDict) and isinstance(obj, Entry):
    elif isinstance(obj, Entry):
        print(' ' * (indent + 2) + "DN: " + obj.entry_dn + ':')
        for key in obj:
            print(' ' * (indent + 4) + str(key) + ':')
            pretty_print(key.value, indent + 6)
    else:
        print(' ' * indent + str(obj))
        print(' ' * indent + 'Unknown object type:', type(obj))
    return


def interactive_mode(ldap):
    while True:
        Logger.display("")
        options: List[str] = []
        for query_num, (method_name, display_string) in queries.items():
            options.append(f"{query_num}: {display_string}")
        options.append("0 EXIT")
        query = Display.select_list("Select an option: ", options, False)[0]
        Logger.display("")

        if query == '0':
            Logger.debug("Exiting interactive mode.")
            break
        elif query in queries_with_args:
            args = input("Enter arguments for the query: ")
            perform_query(ldap, query, args)
        else:
            perform_query(ldap, query)


def print_query_options():
    Logger.display("Available query options:")
    for number, (func_name, display_string) in queries.items():
        Logger.display(f"{number}: {display_string}")
    sys.exit(0)

def build_connection(args):
    """
    Build a connection dictionary from argparse arguments.
    Replaces ConnectionURL.parse().
    """

    protocol = args.protocol.lower()
    if protocol not in ("ldap", "ldaps"):
        raise ValueError("Protocol must be ldap or ldaps")

    # Default ports
    port = 636 if protocol == "ldaps" else 389

    # Build the connection dictionary
    connection = {
        "protocol": protocol,
        "auth": None,  # handled below
        "domain": args.domain,
        "username": args.username,
        "password": None,
        "ip": args.target,
        "fqdn": None,
        "port": port,
        "tree": None,
        "params": {},
    }

    # Authentication type
    if args.hash:
        connection["auth"] = "ntlm-nt"
        connection["password"] = args.hash
    elif args.password:
        connection["auth"] = "ntlm-password"
        connection["password"] = args.password
    else:
        connection["auth"] = "anonymous"

    return connection

def main():
    parser = argparse.ArgumentParser(description="Interactive AD LDAP Query Tool")

    # Explicit connection args
    parser.add_argument(
        "--protocol", choices=["ldap", "ldaps"], default="ldap",
        help="Protocol: ldap or ldaps (default: ldap)"
    )
    parser.add_argument("-u", "--username", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("-d", "--domain", help="Active Directory domain")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("--hash", help="NTLM hash for authentication")

    qgroup = parser.add_argument_group("Query Options", "Data to enumerate from LDAP")
    qgroup.add_argument("-i", "--interactive", default=False, action="store_true", help="Use interactive mode")
    qgroup.add_argument("--list-queries", action="store_true", help="List available query options and exit")
    qgroup.add_argument("-q", "--query", dest="query", help="Query to perform")
    qgroup.add_argument("--args", help="Arguments for the Query option")

    agroup = parser.add_argument_group("Additional Options", "Additional Configuration Options")
    agroup.add_argument("--dns", help="DNS server (optional)")
    agroup.add_argument("-v", "--verbose", action="count", default=0, help="Verbosity, can be stacked")

    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

    if args.list_queries:
        print_query_options()

    # VERBOSITY
    if args.verbose == 1:
        Logger.enable_verbose()
    elif args.verbose == 2:
        Logger.enable_verbose()
        Logger.enable_debug()
    elif args.verbose >= 3:
        Logger.enable_verbose()
        Logger.enable_debug()
        Logger.enable_log_src()

    # Build connection dict (instead of parsing URL)
    connection = build_connection(args)
    Logger.debug(connection)

    # Check for conditions and set up Connection
    if 'kerberos' in connection.get('auth'):
        if connection.get('fqdn') is None:
            Logger.error('Kerberos requires a fqdn to be specified')
            return

    ldap = LDAP_AD(connection, ip_mode=ldap3.IP_V4_ONLY, timeout=10)

    if args.interactive:
        interactive_mode(ldap)
    else:
        # Perform selected query
        perform_query(ldap, args.query, args.args)


if __name__ == '__main__':
    if os.isatty(sys.stdout.fileno()):
        Logger.set_color(False)
    Logger.set_log_to_screen(True)
    main()
