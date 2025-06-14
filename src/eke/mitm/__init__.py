import click
from eke.mitm.rsa_mitm import RSAMITMRequestHandler
from eke.mitm.dh_mitm import DHMITMRequestHandler
from eke.mitm.dh_mitm_vuln1 import DHMITMRequestHandler as DH1
from eke.mitm.dh_mitm_vuln2 import DHMITMRequestHandler as DH2
from eke.mitm.mitm import MITMServer, MITMRequestHandler
import logging

logger = logging.getLogger(__name__)

@click.command(name="mitm")
@click.option("--host", default="localhost", help="Host IP address to listen on.", required=True)
@click.option("--port", default=8888, help="Port to listen on.", required=True)
@click.option("--server-host", default="localhost", help="Host IP address of the main server.", required=True)
@click.option("--server-port", default=9999, help="Port of the main server to connect to.", required=True)
@click.option("--protocol", type=click.Choice(['rsa', 'dh', 'dh-vuln1', 'dh-vuln2'], case_sensitive=False), default='rsa', help="Protocol to use for MITM (default: rsa).")
def run_mitm(host, port, server_host, server_port, protocol):
    logging.basicConfig(level=logging.INFO)
    logger.info(f"Starting MITM server on {host}:{port} "
                f"to forward to {server_host}:{server_port}")
    
    MITMRequestHandler.SERVER_HOST = server_host
    MITMRequestHandler.SERVER_PORT = server_port

    match protocol.lower():
        case 'rsa':
            logger.info("Using RSA protocol for MITM.")
            mitm_server = MITMServer(host, port, RSAMITMRequestHandler)
        case 'dh':
            logger.info("Using DH protocol for MITM.")
            mitm_server = MITMServer(host, port, DHMITMRequestHandler)
        case 'dh-vuln1':
            logger.info("Using DH protocol for MITM.")
            mitm_server = MITMServer(host, port, DH1)
        case 'dh-vuln2':
            logger.info("Using DH protocol for MITM.")
            mitm_server = MITMServer(host, port, DH2)
        case _:
            raise ValueError(f"Unsupported protocol: {protocol}")

    mitm_server.serve_forever()