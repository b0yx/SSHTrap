import logging
import platform
import socket
import threading
import paramiko
from cmd import Cmd
from abc import ABC, abstractmethod
import yaml
import os
from datetime import datetime
from getpass import getuser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("ssh_server.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class Shell(Cmd):
    """Professional Interactive Shell Interface for Secure Sessions"""

    intro = "\n[+] Welcome to Professional Shell\n[+] Type 'help' or '?' to list commands\n"
    use_rawinput = False
    prompt = "\033[1;32mShell> \033[0m"  # Green-colored prompt

    def __init__(self, stdin=None, stdout=None):
        super(Shell, self).__init__(completekey="tab", stdin=stdin, stdout=stdout)

    def safe_print(self, value):
        """Safe print to stdout."""
        if self.stdout and not self.stdout.closed:
            try:
                self.stdout.write(value + "\n")
                self.stdout.flush()
            except IOError:
                pass  # Handle broken pipe errors silently

    def do_echo(self, arg):
        """Repeats the user input."""
        self.safe_print(arg if arg else "Usage: echo <message>")

    def do_time(self, arg):
        """Displays the current system time."""
        self.safe_print("[*] Current Time: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def do_whoami(self, arg):
        """Displays the current user."""
        self.safe_print(f"[*] Current User: {getuser()}")

    def do_sysinfo(self, arg):
        """Displays system information."""
        sys_info = f"""
        [+] System: {platform.system()} {platform.release()}
        [+] Node Name: {platform.node()}
        [+] Machine: {platform.machine()}
        [+] Processor: {platform.processor()}
        [+] Python Version: {platform.python_version()}
        """
        self.safe_print(sys_info.strip())

    def do_clear(self, arg):
        """Clears the terminal screen."""
        os.system("cls" if os.name == "nt" else "clear")

    def do_ipconfig(self, arg):
        """Displays network configuration (Windows) or interfaces (Linux)."""
        cmd = "ipconfig" if os.name == "nt" else "ip a"
        os.system(cmd)

    def do_netstat(self, arg):
        """Displays active network connections."""
        os.system("netstat -tulnp" if os.name != "nt" else "netstat -ano")

    def do_ping(self, arg):
        """Pings a specified host (Usage: ping <host>)."""
        if not arg:
            self.safe_print("Usage: ping <host>")
            return
        os.system(f"ping -c 4 {arg}" if os.name != "nt" else f"ping {arg}")

    def do_traceroute(self, arg):
        """Traces the route to a host (Usage: traceroute <host>)."""
        if not arg:
            self.safe_print("Usage: traceroute <host>")
            return
        os.system(f"traceroute {arg}" if os.name != "nt" else f"tracert {arg}")

    def do_hostname(self, arg):
        """Displays the hostname and local IP."""
        os.system("hostname -I" if os.name != "nt" else "ipconfig | findstr IPv4")

    def do_df(self, arg):
        """Displays disk space usage."""
        os.system("df -h" if os.name != "nt" else "wmic logicaldisk get size,freespace,caption")

    def do_free(self, arg):
        """Displays memory usage."""
        os.system("free -m" if os.name != "nt" else "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize")

    def do_uptime(self, arg):
        """Displays system uptime and load."""
        os.system("uptime" if os.name != "nt" else "wmic os get lastbootuptime")

    def do_ps(self, arg):
        """Displays currently running processes."""
        os.system("ps aux" if os.name != "nt" else "tasklist")

    def do_top(self, arg):
        """Displays system resource usage."""
        os.system("top" if os.name != "nt" else "wmic process get name,executablepath,processid")

    def do_bye(self, arg):
        """Exits the shell."""
        self.safe_print("[+] Exiting... See you next time!")
        return True  # Exits the loop

    def emptyline(self):
        """Handles empty input (prevents repeating last command)."""
        pass

class ServerBase(ABC):
    """Base class for server implementations."""

    def __init__(self):
        self._is_running = threading.Event()
        self._socket = None
        self._listen_thread = None
        self.client_shells = {}  # Store shells by client address

    def start(self, address="0.0.0.0", port=22, timeout=1):
        """Start the server."""
        if not self._is_running.is_set():
            self._is_running.set()

            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            if platform.system().lower() in ["linux", "linux2"]:
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, True)

            self._socket.settimeout(timeout)
            self._socket.bind((address, port))

            self._listen_thread = threading.Thread(target=self._listen)
            self._listen_thread.start()
            logger.info(f"Server started on {address}:{port}")

    def stop(self):
        """Stop the server."""
        if self._is_running.is_set():
            self._is_running.clear()
            self._listen_thread.join()
            self._socket.close()
            logger.info("Server stopped.")

    def _listen(self):
        """Listen for incoming connections."""
        while self._is_running.is_set():
            try:
                self._socket.listen()
                client, addr = self._socket.accept()
                logger.info(f"Connection from {addr[0]}:{addr[1]}")
                threading.Thread(target=self.connection_function, args=(client,)).start()
            except socket.timeout:
                pass

    @abstractmethod
    def connection_function(self, client):
        """Handle client connections."""
        pass


class SshServerInterface(paramiko.ServerInterface):
    """SSH server interface for handling authentication and sessions."""

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_auth_password(self, username, password):
        if (username == self.username) and (password == self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_banner(self):
        return ("Welcome to SSH Server Interface", "en-US \n")

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        # Handle terminal resizing
        logger.info(f"Terminal resized to {width}x{height}")
        return True

class SshServer(ServerBase):
    """SSH server implementation."""

    def __init__(self, host_key_file, username, password):
        super(SshServer, self).__init__()
        self._host_key = paramiko.RSAKey.from_private_key_file(host_key_file)
        self.username = username
        self.password = password

    def connection_function(self, client):
        """Handle SSH client connections."""
        try:
            session = paramiko.Transport(client)
            session.add_server_key(self._host_key)

            server = SshServerInterface(self.username, self.password)
            try:
                session.start_server(server=server)
            except paramiko.SSHException as e:
                logger.error(f"SSH negotiation failed: {e}")
                return

            channel = session.accept()
            if channel is None:
                logger.error("Channel creation failed.")
                return

            stdio = channel.makefile("rwU")
            shell = Shell(stdio, stdio)
            self.client_shells[client.getpeername()] = shell
            shell.cmdloop()

            session.close()
        except Exception as e:
            logger.error(f"An error occurred: {e}")
        finally:
            if client.getpeername() in self.client_shells:
                del self.client_shells[client.getpeername()]


# Load configuration from YAML file
def load_config(config_file="config.yaml"):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file {config_file} not found.")

    with open(config_file, "r") as f:
        return yaml.safe_load(f)


# Main function
if __name__ == "__main__":
    try:
        config = load_config()
        ssh_server = SshServer(
            host_key_file=config["host_key_file"],
            username=config["username"],
            password=config["password"],
        )
        ssh_server.start(address=config["address"], port=config["port"])
    except Exception as e:
        logger.error(f"Failed to start server: {e}")