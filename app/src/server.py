import connexion

import logging
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(filename)s: %(funcName)s:%(lineno)d: %(message)s', stream=sys.stdout)
# Create the application instance
app = connexion.AsyncApp(__name__)

app.add_api('authz_openapi.yaml')

if __name__ == '__main__':
    app.run(port=1235)
