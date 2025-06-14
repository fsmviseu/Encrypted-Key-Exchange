from eke.mitm.mitm import MITMRequestHandler
import logging

logger = logging.getLogger(__name__)

class DHMITMRequestHandler(MITMRequestHandler):
    def handle_client_data(self, data):
        logger.info(f"Forwarding DH data from client to server: {data}")
        return data

    def handle_server_data(self, data):
        logger.info(f"Forwarding DH data from server to client: {data}")
        return data
