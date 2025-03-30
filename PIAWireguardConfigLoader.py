import base64
import os
import sys
import requests
import urllib3

from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from enum import Enum
from logging import Logger
from xml.etree import ElementTree as ElementTree


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


def load_cert_chain_from_bytes(cert_chain: bytes) -> list[x509.Certificate]:
    cert_delimiter = b"-----END CERTIFICATE-----"
    cert_list = []
    split_certs = cert_chain.split(cert_delimiter + b"\n")
    for cert_bytes in split_certs:
        if not cert_bytes.endswith(cert_delimiter):
            cert_bytes += cert_delimiter
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        except ValueError:
            continue
        cert_list.append(cert)
    return cert_list


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
            self.logger.error(
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
            self.logger.error(
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

                self.logger.debug("Certificate located.")
                cert_text_element = cert_element.find('crt')
                if cert_text_element is not None:
                    self.logger.debug("Decoding Base64 data...")
                    try:
                        self.certificate = base64.b64decode(cert_text_element.text)
                        self.logger.debug("Base64 data decoding successful.")

                    except TypeError:
                        self.logger.critical(
                            "Invalid Base-64 certificate data. The certificate cannot be loaded. This should not happen!")
                        sys.exit(1)

                else:
                    self.logger.critical(
                        "Could not find certificate in OPNSense configuration. This should not happen!")
                    sys.exit(1)

                key_element = cert_element.find('prv')
                if key_element is not None:
                    self.logger.debug("Decoding Base64 data...")
                    try:
                        self.key = base64.b64decode(key_element.text)
                        self.logger.debug("Base64 data decoding successful.")

                    except TypeError:
                        self.logger.critical(
                            "Invalid Base-64 key data. The key cannot be loaded. This should not happen!")
                        sys.exit(1)

                else:
                    self.logger.critical(
                        "Could not find certificate private key in OPNSense configuration. This should not happen!")
                    sys.exit(1)

                break

    def get_loader_type(self) -> ConfigLoaderType:
        return ConfigLoaderType.ClientAuthenticatedNetworkDomain

    def is_data_valid(self) -> bool:
        self.logger.debug(f"Validating data in {self.__class__.__name__}...")

        if self.certificate is None:
            self.logger.error("No X.509 certificate loaded.")
            return False

        if self.key is None:
            self.logger.error("No private key loaded.")
            return False

        try:
            cert = x509.load_pem_x509_certificate(self.certificate)

        except ValueError:
            self.logger.critical("Unable to load Base64 data as certificate. This should not happen!")
            return False

        try:
            if x509.OID_CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                self.logger.error("Currently loaded certificate is not a client certificate.")
                return False
        except x509.ExtensionNotFound:
            self.logger.error("Currently loaded certificate has no EKU extension.")
            return False

        try:
            key = load_pem_private_key(self.key, password=None)

        except ValueError:
            self.logger.critical("Unable to load Base64 data as private key. This should not happen!")
            return False

        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            self.logger.critical(
                "Currently loaded private key does not match currently loaded certificate. This should not happen!")
            return False

        self.logger.debug("Data successfully validated.")
        return True

    def get_json_config(self) -> str:
        return ""
