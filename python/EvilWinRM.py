import argparse
import base64
import datetime
import os
import shlex
from getpass import getpass
from typing import List, Optional, Tuple

from winrm import Session
from winrm.protocol import Protocol


class EvilWinRM:
    """
    EvilWinRM is a class that provides a remote shell interface to interact with a Windows machine using WinRM.

    Args:
        ip (str): The IP address or hostname of the remote machine.
        username (Optional[str]): The username to authenticate with. Default is None.
        password (Optional[str]): The password to authenticate with. Default is None.
        domain (Optional[str]): The domain of the user account. Default is None.
        krb5_ccache (Optional[str]): The path to the Kerberos credential cache file. Default is None.
        ntlm_hash (Optional[str]): The NTLM hash of the user's password. Default is None.

    Attributes:
        ip (str): The IP address or hostname of the remote machine.
        username (Optional[str]): The username to authenticate with.
        password (Optional[str]): The password to authenticate with.
        domain (Optional[str]): The domain of the user account.
        krb5_ccache (Optional[str]): The path to the Kerberos credential cache file.
        ntlm_hash (Optional[str]): The NTLM hash of the user's password.
        session (Session): The WinRM session object.
        protocol (Protocol): The WinRM protocol object.
        shell_id (str): The ID of the remote shell.
        working_directory (str): The current working directory on the remote machine.
        local_working_directory (str): The current working directory on the local machine.

    Methods:
        execute(): Starts the interactive shell session.
        build_script(encoded_exe: str, encoded_parameters: str) -> str: Builds a PowerShell script to execute an encoded executable.
        load_and_execute_exe(local_exe_path: str, parameters: Optional[str] = None) -> None: Loads and executes a local executable on the remote machine.
        get_local_working_path(current_directory: str, new_directory: str) -> str: Returns the absolute path of a new local working directory.
        list_directory_contents(directory: str) -> None: Lists the contents of a directory.
        get_system_info() -> None: Prints the system information of the remote machine.
        get_session() -> None: Establishes a WinRM session with the remote machine.
        get_password_session() -> Session: Creates a WinRM session using username and password authentication.
        get_kerberos_session() -> Session: Creates a WinRM session using Kerberos authentication.
        get_ntlm_session() -> Session: Creates a WinRM session using NTLM authentication.
        display_help() -> None: Displays the available commands and their descriptions.
        encode_powershell_command(cmd: str) -> str: Encodes a PowerShell command for execution.
        run_ps_command(cmd: str) -> None: Runs a PowerShell command on the remote machine.
        encode_command(cmd: str) -> Tuple[str, List[str]]: Encodes a command for execution.

    """

    def __init__(self, ip: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, krb5_ccache: Optional[str] = None, ntlm_hash: Optional[str] = None) -> None:
        self.ip = ip
        self.username = username
        self.password = password
        self.domain = domain
        self.krb5_ccache = krb5_ccache
        self.ntlm_hash = ntlm_hash

        self.session: Session = None
        self.protocol: Protocol = None
        self.shell_id: str = None
        self.working_directory: str = None

        self.local_working_directory = "."
        self.get_session()

        self.get_system_info()

    # Rest of the code...
class EvilWinRM:
    def __init__(self, ip: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None, krb5_ccache: Optional[str] = None, ntlm_hash: Optional[str] = None) -> None:
        self.ip = ip
        self.username = username
        self.password = password
        self.domain = domain
        self.krb5_ccache = krb5_ccache
        self.ntlm_hash = ntlm_hash

        self.session: Session = None
        self.protocol: Protocol = None
        self.shell_id: str = None
        self.working_directory: str = None

        self.local_working_directory = "."
        self.get_session()

        self.get_system_info()

    def execute(self) -> None:
        self.get_session()

        try:
            while True:
                if not self.working_directory:
                    self.working_directory = self.session.run_cmd("echo %cd%").std_out.decode("utf-8").rstrip()

                hostname = self.session.run_cmd("echo %COMPUTERNAME%.%USERDNSDOMAIN%").std_out.decode("utf-8").rstrip()

                cmd = input(f"\n{self.username}@{self.ip} ({hostname}): {self.working_directory}> ")
                if cmd.lower() in ('exit', 'quit'):
                    break
                elif cmd.lower() in ('?', 'help', 'menu'):
                    EvilWinRM.display_help()
                    continue

                if cmd.lower().startswith('powershell '):
                    cmd = cmd[len('powershell '):]
                    self.run_ps_command(cmd)
                elif cmd.lower().startswith('cmd '):
                    cmd = cmd[len('cmd '):]
                    self.run_cmd_command(cmd)

                elif cmd.lower().startswith('exec '):
                    exe = cmd[len('exec '):]
                    self.load_and_execute_exe(exe)

                elif cmd.lower().startswith('get '):
                    filenames = shlex.split(cmd[len('get '):].strip())
                    remote_file = filenames[0]
                    local_file = filenames[1] if len(filenames) > 1 else filenames[0]
                    self.get_file(remote_file, local_file)
                elif cmd.lower().startswith('put '):
                    filenames = shlex.split(cmd[len('put '):].strip())
                    local_file = filenames[0]
                    remote_file = filenames[1] if len(filenames) > 1 else filenames[0]
                    self.put_file(local_file, remote_file)

                elif cmd.lower().startswith('lls '):
                    EvilWinRM.list_directory_contents(cmd[4:])
                elif cmd.lower() == "lls":
                    EvilWinRM.list_directory_contents(self.local_working_directory)
                elif cmd.lower().startswith('lcd '):
                    self.local_working_directory = EvilWinRM.get_local_working_path(self.local_working_directory,cmd[4:])

                elif cmd.lower() == "services":
                    ps_script = '''
$servicios = Get-ItemProperty "registry::HKLM\System\CurrentControlSet\Services\*" | Where-Object {$_.imagepath -notmatch "system" -and $_.imagepath -ne $null } | Select-Object pschildname,imagepath  ; foreach ($servicio in $servicios  ) {Get-Service $servicio.PSChildName -ErrorAction SilentlyContinue | Out-Null ; if ($? -eq $true) {$privs = $true} else {$privs = $false} ; $Servicios_object = New-Object psobject -Property @{"Service" = $servicio.pschildname ; "Path" = $servicio.imagepath ; "Privileges" = $privs} ;  $Servicios_object }
'''
                    self.run_ps_command(ps_script)

                else:
                    self.run_cmd_command(cmd)
        except Exception as e:
            print(e)

    @staticmethod
    def build_script(encoded_exe: str, encoded_parameters: str) -> str:
        script = f'''
$exeBytes = [System.Convert]::FromBase64String('{encoded_exe}')
$memStream = New-Object IO.MemoryStream($exeBytes, 0, $exeBytes.Length)
$assembly = [Reflection.Assembly]::Load($memStream)
$entryPoint = $assembly.EntryPoint

if ('{encoded_parameters}' -ne '') {{
    $parametersBytes = [System.Convert]::FromBase64String('{encoded_parameters}')
    $parameters = [System.Text.Encoding]::UTF8.GetString($parametersBytes)
    $args = $parameters.Split([char]0x20)
    [Reflection.Assembly]::Load($exeBytes).EntryPoint.Invoke($null, @($args))
}} else {{
    [Reflection.Assembly]::Load($exeBytes).EntryPoint.Invoke($null, @())
}}
'''
        return script

    def load_and_execute_exe(self, local_exe_path: str, parameters: Optional[str] = None) -> None:
        with open(local_exe_path, "rb") as exe_file:
            exe_data = exe_file.read()

        encoded_exe = base64.b64encode(exe_data).decode("utf-8")

        encoded_parameters = ""
        if parameters is not None:
            encoded_parameters = base64.b64encode(parameters.encode("utf-8")).decode("utf-8")

        script = EvilWinRM.build_script(encoded_exe, encoded_parameters)
        encoded_ps = EvilWinRM.encode_powershell_command(script)
        self.run_script(encoded_ps)

    @staticmethod
    def get_local_working_path(current_directory: str, new_directory: str) -> str:
        new_dir_path = os.path.join(current_directory, new_directory)
        if os.path.exists(new_dir_path) and os.path.isdir(new_dir_path):
            return os.path.abspath(new_dir_path)
        else:
            return os.path.abspath(current_directory)

    @staticmethod
    def list_directory_contents(directory: str) -> None:
        print(f"Contents of {os.path.abspath(directory)}:\n")
        contents = os.listdir(directory)
        contents = sorted(contents, key=lambda x: os.path.getmtime(os.path.join(directory, x)))
        for item in contents:
            item_path = os.path.join(directory, item)
            stat_info = os.stat(item_path)
            mod_time = datetime.datetime.fromtimestamp(stat_info.st_mtime)
            print(
                f"{stat_info.st_mode:10o} {stat_info.st_nlink:4d} {stat_info.st_uid:6d} {stat_info.st_gid:6d} {stat_info.st_size:8d} {mod_time.strftime('%b %d %H:%M')} {item}")

    def get_system_info(self) -> None:
        hostname = self.session.run_cmd("echo %COMPUTERNAME%.%USERDNSDOMAIN%").std_out.decode("utf-8").rstrip()
        path = self.session.run_cmd("echo %cd%").std_out.decode("utf-8").rstrip()
        print(f"\nConnected to {hostname} ({self.ip}) as {self.domain}/{self.username}\nCurrent directory: {path}")

    def get_session(self) -> None:
        if not self.session:
            if self.password:
                self.session = self.get_password_session()
            elif self.krb5_ccache:
                print("HI")
                self.session = self.get_kerberos_session()
            else:
                self.session = self.get_ntlm_session()

        if not self.protocol:
            self.protocol = self.session.protocol
        if not self.shell_id:
            self.shell_id = self.protocol.open_shell()

    def get_password_session(self) -> Session:
        return Session(self.ip, auth=(self.username, self.password), transport='ntlm')

    def get_kerberos_session(self) -> Session:
        return Session(self.ip, auth=(f"{self.username}@{self.domain}", None), transport='kerberos',
                       server_cert_validation="ignore")

    def get_ntlm_session(self) -> Session:
        return Session(self.ip, auth=(self.username, self.ntlm_hash), transport='ntlm')

    @staticmethod
    def display_help() -> None:
        help_text = """Available commands:
    powershell <command>    - Execute a PowerShell command
    cmd <command>           - Execute a cmd.exe command

    exec <local exe>        - Execute a local .exe file on the remote system

    get <remote_file>       - Download a file from the remote system
    put <local_file>        - Upload a file to the remote system

    lls <directory>         - Get local directory listing
    lcd <directory>         - Change the local directory
    cd <directory>          - Change directory on the remote system

    services                - Get a list of running services

    help, menu, ?           - Show this help menu
    exit, quit              - Exit the shell
        """
        print(help_text)

    @staticmethod
    def encode_powershell_command(cmd: str) -> str:
        encoded_ps = base64.b64encode(cmd.encode('utf-16le')).decode('ascii')
        return f'powershell -EncodedCommand {encoded_ps}'

    def run_ps_command(self, cmd: str) -> None:
        ps_cmd = f"cd {self.working_directory} ; {cmd} ; $pwd.Path"
        encoded_ps = base64.b64encode(ps_cmd.encode('utf_16_le')).decode('ascii')
        encoded_ps_command = 'powershell -encodedcommand {0}'.format(encoded_ps)
        command_id = self.protocol.run_command(self.shell_id, encoded_ps_command)
        std_out, std_err, status_code = self.protocol.get_command_output(
            self.shell_id, command_id)
        if status_code != 0:
            print(f"Error: {std_err.decode('utf-8')}")
        else:
            self.working_directory = std_out.decode('utf-8').strip().split('\n')[-1]
            output = "\n".join(std_out.decode('utf-8').strip().split('\r\n')[:-1])

            print(output)
        self.protocol.cleanup_command(self.shell_id, command_id)

    @staticmethod
    def encode_command(cmd: str) -> Tuple[str, List[str]]:
        words = cmd.split()
        if len(words) > 0:
            first_word = words[0]
            other_words = words[1:]
        else:
            first_word = ""
            other_words = []

        return first_word, other_words

    def run_cmd_command(self, cmd: str) -> None:
        cd_cmd = f"cd {self.working_directory} && {cmd} && cd"
        encoded_cmd, args = EvilWinRM.encode_command(cd_cmd)
        command_id = self.protocol.run_command(self.shell_id, encoded_cmd, args)
        std_out, std_err, status_code = self.protocol.get_command_output(
            self.shell_id, command_id)
        if status_code != 0 and std_err:
            print(f"Error: {std_err.decode('utf-8')}")
        else:
            if status_code == 0:
                self.working_directory = std_out.decode('utf-8').strip().split('\n')[-1]
            output = "\n".join(std_out.decode('utf-8').strip().split('\r\n')[:-1])
            print(output)
        self.protocol.cleanup_command(self.shell_id, command_id)

    def put_file(self, local_file: str, remote_file: str, chunk_size: int = 2048) -> None:
        local_file = os.path.join(self.local_working_directory, local_file)
        remote_file = os.path.join(self.working_directory, remote_file)

        # Create the remote file with empty content
        create_cmd = f"New-Item -ItemType file -Path '{remote_file}' -Force"
        self.protocol.run_command(self.shell_id, create_cmd)

        # Upload the file in chunks
        with open(local_file, 'rb') as f:
            while True:
                file_data = f.read(chunk_size)
                if not file_data:
                    break

                base64_data = base64.b64encode(file_data).decode('utf-8')

                ps_cmd = f"$fileData = [System.Convert]::FromBase64String('{base64_data}');"
                ps_cmd += f"$fileStream = [System.IO.File]::OpenWrite('{remote_file}');"
                ps_cmd += f"$fileStream.Seek(0, [System.IO.SeekOrigin]::End);"
                ps_cmd += f"$fileStream.Write($fileData, 0, $fileData.Length);"
                ps_cmd += f"$fileStream.Close();"

                encoded_ps = base64.b64encode(ps_cmd.encode('utf_16_le')).decode('ascii')
                encoded_ps_command = 'powershell -encodedcommand {0}'.format(encoded_ps)

                command_id = self.protocol.run_command(self.shell_id, encoded_ps_command)
                std_out, std_err, status_code = self.protocol.get_command_output(
                    self.shell_id, command_id)

                if status_code != 0:
                    print(f"Error uploading chunk of {local_file}: {std_err.decode('utf-8')}")
                    return

        print(f"Uploaded {local_file} to {remote_file}")

    def get_file(self, remote_file: str, local_file: str) -> None:
        remote_file = os.path.join(self.working_directory, remote_file)
        local_file = os.path.abspath(os.path.join(self.local_working_directory, local_file))

        # Download the file using a PowerShell command
        ps_cmd = f"$fileData = Get-Content -Path '{remote_file}' -Encoding Byte;"
        ps_cmd += "[System.Convert]::ToBase64String($fileData)"
        encoded_ps = base64.b64encode(ps_cmd.encode('utf_16_le')).decode('ascii')
        encoded_ps_command = f'powershell -encodedcommand {encoded_ps}'

        command_id = self.protocol.run_command(self.shell_id, encoded_ps_command)
        std_out, std_err, status_code = self.protocol.get_command_output(self.shell_id, command_id)

        if status_code == 0:
            file_data = base64.b64decode(std_out.decode('utf-8').strip())
            with open(local_file, 'wb') as f:
                f.write(file_data)
            print(f"Downloaded {remote_file} to {local_file}")
        else:
            print(f"Error downloading {remote_file}: {std_err.decode('utf-8')}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Evil-WinRM Python implementation")
    parser.add_argument("-i", "--ip", type=str, required=True, help="Remote computer IP or hostname")
    parser.add_argument("-u", "--user", type=str, required=True, help="Username")
    parser.add_argument("-p", "--password", type=str, help="Password")
    parser.add_argument("-H", "--hash", type=str, help="NTLM hash")
    parser.add_argument('-d', '--domain', type=str, default="", help="Domain (default: '')")
    parser.add_argument('-k', '--krb5-ccache', action="store_true",
                        help="KRB5CCNAME environment variable for Kerberos authentication")
    parser.add_argument("-P", "--port", type=int, default=5985, help="WinRM port (default: 5985)")
    # parser.add_argument("-n", "--no-ssl", action="store_true", help="No SSL")
    # parser.add_argument("-s", "--script", type=str, help="Execute script on target")
    # parser.add_argument("-e", "--exec", type=str, help="Execute command on target")

    args = parser.parse_args()

    if not args.password and not args.krb5_ccache and not args.ntlm_hash:
        args.password = getpass("Enter password: ")

    evil_winrm = EvilWinRM(args.ip, args.user, args.password, args.domain, args.krb5_ccache, args.hash)
    evil_winrm.execute()

if __name__ == "__main__":
    main()
