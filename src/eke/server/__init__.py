import click
from eke.server.server import Server
from eke.server.rsa_server import RSARequestHandler
from eke.server.dh_server import DHRequestHandler
import logging

logger = logging.getLogger(__name__)

@click.command(name="server")
@click.option("--host", default="localhost", help="Host IP address to listen on.", required=True)
@click.option("--port", default=9999, help="Port to listen on.", required=True)
@click.option("--protocol", type=click.Choice(['rsa', 'dh'], case_sensitive=False), default='rsa', help="Protocol to use for MITM (default: rsa).")
def run_server(host, port, protocol):
    logging.basicConfig(level=logging.INFO)
    logger.info(f"Starting server on {host}:{port}")

    if protocol == 'rsa':
        logger.info("Using RSA protocol for MITM.")
        mitm_server = Server(host, port, RSARequestHandler)
    else:
        logger.info("Using DH protocol for MITM.")
        mitm_server = Server(host, port, DHRequestHandler)

    mitm_server.serve_forever()