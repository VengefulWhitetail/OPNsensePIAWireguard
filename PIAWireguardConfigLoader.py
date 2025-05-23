import base64
import os
import requests
import ssl
import sys
import tempfile
import urllib3

from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from enum import Enum
from logging import Logger
from socket import create_connection
from urllib.parse import urlparse
from xml.etree import ElementTree as ElementTree
from OpenSSL.SSL import Context, Connection, SysCallError, TLS_CLIENT_METHOD


class ConfigLoaderType(Enum):
    """Enum class defining types of configuration loaders.

    Stored in PIAWireguardLoader.json under the key "loaderType". May be stored as an integer or name."""
    LocalFile = 0
    """Reads configuration from a locally stored file."""

    ClientAuthenticatedNetworkDomain = 1
    """Reads configuration from a network domain authenticated using an X.509 client certificate."""

    # --- more type enum entries go here ---


class PIAWireguardConfigLoader(ABC):
    """Abstract base class of configuration loaders."""

    @abstractmethod
    def __init__(self, logger: Logger, loader_args: list[str]):
        """
        When implemented in subclasses, initializes the loader.

        Arguments:
            logger: The logger to write logs to.
            loader_args: The string array "arguments" found in PIAWireguardLoader.json. The subclass is free to use these arguments however it wishes. For ease of use in writing the corresponding loader config file, specify the arguments expected and what each one is supposed to be.
        """
        pass

    @abstractmethod
    def get_loader_type(self) -> ConfigLoaderType:
        """
        When implemented in subclasses, returns the ConfigLoaderType enum value associated with this class.
        """
        pass

    @abstractmethod
    def is_data_valid(self) -> bool:
        """
        When implemented in subclasses, determines if the data can be used to successfully attempt a configuration retrieval.
        Use this to stop execution if the loader's data would cause a fatal error on attempting a read (e.g. it points to a file that doesn't exist).
        Do NOT use this method to validate the JSON configuration output.
        """
        pass

    @abstractmethod
    def get_json_config(self) -> str:
        """When implemented in subclasses, gets the JSON configuration data in string form as specified by PIAWireguard.json"""
        pass


class PIAWireguardConfigFileLoader(PIAWireguardConfigLoader):
    """Configuration loader which reads from a local file"""

    def __init__(self, logger: Logger, loader_args: list[str]):
        """
        Arguments expected:
            0: File name relative to sys.path[0]
        """
        self.path = os.path.join(sys.path[0], loader_args[0])

    def get_loader_type(self) -> ConfigLoaderType:
        return ConfigLoaderType.LocalFile

    def is_data_valid(self) -> bool:
        return os.path.isfile(self.path)

    def get_json_config(self) -> str:
        with open(self.path, 'r') as f:
            return f.read()


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def rfc4514_to_dict(rfc4514: str) -> dict[str, str]:
    entries = rfc4514.split(',')
    return {k.strip(): v.strip() for k, v in (entry.split('=', 1) for entry in entries)}


class PIAWireguardConfigClientAuthenticatedDomainLoader(PIAWireguardConfigLoader):
    """Configuration loader which pulls a config from a domain using an X.509 client certificate in OPNSense"""

    def __init__(self, logger: Logger, loader_args: list[str]):
        """
        Arguments expected:
            0: OPNSense firewall URI
            1: OPNSense API key
            2: OPNSense API secret
            3: Identifier of client certificate to use. You may use the certificate's common name, description, OPNSense UUID, or OPNSense Ref ID
            4: URL of destination
        """
        self.logger = logger
        opnsense_uri = loader_args[0]
        self.logger.debug(f"{self.__class__.__name__} Argument 0 (OPNSense Firewall URI): {opnsense_uri}")
        api_key = loader_args[1]
        self.logger.debug(f"{self.__class__.__name__} Argument 1 (OPNSense API key): {api_key}")
        api_secret = loader_args[2]
        self.logger.debug(
            f"{self.__class__.__name__} Argument 2 (OPNSense API secret): [Not logging value for security purposes].")
        client_cert_identifier = loader_args[3]
        self.logger.debug(
            f"{self.__class__.__name__} Argument 3 (X.509 Client Certificate Identifier): {client_cert_identifier}")
        self.destination = loader_args[4]
        self.logger.debug(f"{self.__class__.__name__} Argument 4 (Destination): {self.destination}")

        session = requests.Session()
        session.auth = (api_key, api_secret)
        session.headers.update({'User-Agent': 'Github: VengefulWhitetail/OPNsensePIAWireguard'})
        session.verify = False  # As we're connecting via local loopback we don't really need to check the certificate.
        urllib3.disable_warnings()  # stop the warnings

        try:
            r = session.get(f"{opnsense_uri}/api/trust/cert/search", params=None, timeout=10)
            if r.status_code == 403:
                self.logger.critical(
                    "Access to certificates denied by OPNSense API (does your user not have System: Certificate Manager privileges?)")
                sys.exit(1)
            if r.status_code == 401:
                raise ValueError("unauthorized")
            if r.status_code != 200:
                raise ValueError(f"returned non 200 status code - {r.text}")
            api_certs_request = r
        except ValueError as e:
            raise ValueError(f"GET Request: Failed {str(e)}")

        try:
            api_certs = api_certs_request.json()['rows']
        except ValueError:
            self.logger.critical(
                "Unable to retrieve certificate records from OPNSense API (are the URL, API key, and API secret correct?)")
            sys.exit(1)

        self.logger.debug(
            "Successfully retrieved X.509 certificate records from OPNSense API. Searching for match to identifier...")
        client_cert_ids = {}
        for api_cert in api_certs:
            if (api_cert['uuid'] == client_cert_identifier or api_cert['refid'] == client_cert_identifier or
                    api_cert['descr'] == client_cert_identifier or api_cert['commonname'] == client_cert_identifier):
                client_cert_ids['uuid'] = api_cert['uuid']
                client_cert_ids['refid'] = api_cert['refid']
                client_cert_ids['descr'] = api_cert['descr']
                self.logger.debug(f"Successfully matched certificate to identifier \"{client_cert_identifier}\"")
                break

        if len(client_cert_ids) == 0:
            self.logger.critical(
                f"No match to identifier \"{client_cert_identifier}\" found in certificate records (is the identifier correct?)")
            sys.exit(1)

        self.logger.debug("Reading local config file...")
        with open("/conf/config.xml", 'r') as f:
            root = ElementTree.fromstring(f.read())

            self.logger.debug("Searching certificates...")
            cert_elements = root.findall("cert")

            for cert_element in cert_elements:
                if cert_element.attrib['uuid'] != client_cert_ids['uuid']:
                    continue

                ref_id_element = cert_element.find('refid')
                if ref_id_element is None or ref_id_element.text != client_cert_ids['refid']:
                    continue

                description_element = cert_element.find('descr')
                if description_element is None or description_element.text != client_cert_ids['descr']:
                    continue

                self.logger.debug("Certificate identifier match found.")
                cert_text_element = cert_element.find('crt')
                if cert_text_element is None:
                    self.logger.critical(
                        "Could not find certificate in OPNSense configuration. This should not happen!")
                    sys.exit(1)

                self.logger.debug("Decoding Base64 certificate data...")
                try:
                    cert_chain = base64.b64decode(cert_text_element.text)
                    self.logger.debug("Base64 certificate decoding successful.")

                except TypeError:
                    self.logger.critical(
                        "Invalid Base-64 certificate data. The certificate cannot be loaded. This should not happen!")
                    sys.exit(1)

                key_element = cert_element.find('prv')
                if key_element is None:
                    self.logger.critical(
                        "Could not find certificate private key in OPNSense configuration. This should not happen!")
                    sys.exit(1)

                self.logger.debug("Decoding Base64 key data...")
                try:
                    self.key = base64.b64decode(key_element.text)
                    self.logger.debug("Base64 key decoding successful.")

                except TypeError:
                    self.logger.critical(
                        "Invalid Base-64 key data. The key cannot be loaded. This should not happen!")
                    sys.exit(1)

                cert_footer = b"-----END CERTIFICATE-----"
                certificates = cert_chain.split(cert_footer + b"\n")

                for i in range(len(certificates)):
                    cert = certificates[i]
                    if not cert.endswith(cert_footer):
                        certificates[i] = cert + cert_footer

                self.certificates = certificates
                break

        result = urlparse(self.destination)
        try:
            with create_connection((result.hostname, result.port)) as s:
                context = Context(TLS_CLIENT_METHOD)
                connection = Connection(context, s)
                connection.set_connect_state()
                connection.do_handshake()
                server_certs = connection.get_peer_cert_chain()
                try:
                    connection.shutdown()
                except SysCallError:
                    self.logger.warning("Unable to close SSL connection: Connection was already closed.")
        except ConnectionRefusedError:
            self.logger.critical(
                f"Connection to destination {self.destination} was refused (is your firewall rejecting the connection?)")
            sys.exit(1)
        except PermissionError:
            self.logger.critical(
                f"Permission denied to access destination {self.destination} (is your firewall blocking the connection?)")
            sys.exit(1)

        highest_common_ca_rindex = 0  # As root certs are at the end of lists, we must go by a rear index
        for i in range(len(self.certificates)):
            my_cert = x509.load_pem_x509_certificate(self.certificates[~i])
            server_cert = server_certs[~i].to_cryptography()

            if not is_ca(my_cert) or not is_ca(server_cert):
                continue

            my_cert_subject = rfc4514_to_dict(my_cert.subject.rfc4514_string())
            server_cert_subject = rfc4514_to_dict(server_cert.subject.rfc4514_string())
            if my_cert_subject != server_cert_subject:
                highest_common_ca_rindex = max(0, i - 1)
                break

        self.ca_index = len(self.certificates) - highest_common_ca_rindex - 1

    def get_loader_type(self) -> ConfigLoaderType:
        return ConfigLoaderType.ClientAuthenticatedNetworkDomain

    def is_data_valid(self) -> bool:
        self.logger.debug(f"Validating data in {self.__class__.__name__}...")

        if len(self.certificates) == 0 and self.key is None:
            self.logger.error("No X.509 certificate or private key data loaded. The loader data is not valid.")
            return False

        if len(self.certificates) == 0 or self.key is None:
            self.logger.critical(
                "Only one of X.509 certificate or private key data is loaded. The loader data is not valid. This should not happen!")
            return False

        try:
            cert_bytes = self.certificates[0]
            self.logger.debug("Loading certificate...")
            cert = x509.load_pem_x509_certificate(cert_bytes)

        except ValueError:
            self.logger.critical(
                "Unable to load Base64 data as certificate. The loader data is not valid. This should not happen!")
            return False

        self.logger.debug("Certificate loaded successfully. Checking for client authentication extension...")
        try:
            if x509.OID_CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                self.logger.error(
                    "Currently loaded certificate is not a client certificate. The loader data is not valid.")
                return False
        except x509.ExtensionNotFound:
            self.logger.error("Currently loaded certificate is not a client certificate. The loader data is not valid.")
            return False

        self.logger.debug("Client authentication found in certificate extensions.")
        try:
            self.logger.debug("Loading private key, this may take a few seconds...")
            key = load_pem_private_key(self.key, password=None)

        except ValueError:
            self.logger.critical(
                "Unable to load Base64 data as private key. The loader data is not valid. This should not happen!")
            return False

        self.logger.debug("Private key loaded successfully. Comparing to certificate...")
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            self.logger.critical(
                "Currently loaded private key is not the signer of currently loaded certificate. The loader data is not valid. This should not happen!")
            return False

        self.logger.debug("Private key matches certificate.")
        return True

    def get_json_config(self) -> str:
        certs = bytes()
        for i in reversed(range(self.ca_index, len(self.certificates))):
            cert = self.certificates[i]
            certs += cert
            certs += b'\n'

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=certs.decode())
        with tempfile.NamedTemporaryFile(mode="wb", delete=True) as cert_file, \
                tempfile.NamedTemporaryFile(mode="wb", delete=True) as key_file:
            cert_file.write(self.certificates[0])
            cert_file.flush()
            key_file.write(self.key)
            key_file.flush()
            context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
            http = urllib3.PoolManager(ssl_context=context)
            response = http.request("GET", self.destination)

            if response.status == 200:
                return response.data.decode()

            return ""
