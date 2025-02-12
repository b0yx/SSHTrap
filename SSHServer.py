import logging
import platform
import socket
import threading
import paramiko
from cmd import Cmd
from abc import ABC, abstractmethod
import yaml
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("ssh_server.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class Shell(Cmd):
    """Custom shell interface for authenticated SSH clients."""

    intro = "Welcome to My Shell. Type help or ? to list commands.\n"
    use_rawinput = False
    prompt = "Shell> "

    def __init__(self, stdin=None, stdout=None):
        super(Shell, self).__init__(completekey="tab", stdin=stdin, stdout=stdout)

    def print(self, value):
        """Write output to the client."""
        if self.stdout and not self.stdout.closed:
            self.stdout.write(value)
            self.stdout.flush()

    def printline(self, value):
        """Write a line of output to the client."""
        self.print(value + "\r\n")

    def do_greet(self, arg):
        """Greet the user."""
        if arg:
            self.printline(f"Hey {arg}! Nice to see you!")
        else:
            self.printline("Hello there!")

    def do_bye(self, arg):
        """Exit the shell."""
        self.printline("See you later!")
        return True

    def emptyline(self):
        """Handle empty input."""
        self.print("\r\n")


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

            if platform == "linux" or platform == "linux2":
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
        return ("Welcome to SSH Server Interface", "en-US \r\n")


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