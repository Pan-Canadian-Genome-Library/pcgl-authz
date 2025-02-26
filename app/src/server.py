import connexion


# Create the application instance
app = connexion.AsyncApp(__name__)

app.add_api('authz_openapi.yaml')

if __name__ == '__main__':
    app.run(port=1235)
