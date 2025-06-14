import click
import eke.client
import eke.server
import eke.mitm
import logging

@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging.")
def cli(debug):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
        for name in logging.root.manager.loggerDict:
            logging.getLogger(name).setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
for cmd in [
    eke.client.run_client,
    eke.server.run_server,
    eke.mitm.run_mitm,
]:
    cli.add_command(cmd)

if __name__ == "__main__":
    cli()