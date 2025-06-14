import click
import logging
from eke.client.rsa_client import RSAClient
from eke.client.dh_client import DHClient
from eke.client.dh_client_vuln1 import DHClient as DHVuln1Client
from eke.client.dh_client_vuln2 import DHClient as DHVuln2Client

logger = logging.getLogger(__name__)

@click.command(name="client")
@click.option("--host", default="localhost", help="Host ip address to connect to.", required=True)
@click.option("--port", default=8888, help="Host port to connect to.", required=True)
@click.option("--protocol", type=click.Choice(['rsa', 'dh', 'dh-vuln1', 'dh-vuln2'], case_sensitive=False), default='rsa', help="Protocol to use for MITM (default: rsa).")
def run_client(host, port, protocol):
    match protocol.lower():
        case 'rsa':
            logger.info("Using RSA protocol for client.")
            client = RSAClient(host, port)
        case 'dh':
            logger.info("Using DH protocol for client.")
            client = DHClient(host, port)
        case 'dh-vuln1':
            logger.info("Using DH protocol for client.")
            client = DHVuln1Client(host, port)
        case 'dh-vuln2':
            logger.info("Using DH protocol for client.")
            client = DHVuln2Client(host, port)

    client.interact()
