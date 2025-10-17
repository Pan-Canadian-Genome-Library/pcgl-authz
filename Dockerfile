ARG venv_python=3.12
FROM python:${venv_python}

LABEL Maintainer="PCGL Project"

USER root

RUN groupadd -r pcgl && useradd -rm pcgl -g pcgl

RUN apt-get update && apt-get -y install \
	bash \
	expect \
	jq \
	curl \
	vim \
	git

COPY app/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/

WORKDIR /vault/
RUN mkdir -p /vault/config
RUN mkdir -p /vault/data
RUN chmod 777 /vault/data

WORKDIR /app/
RUN chown -R pcgl:pcgl /app

RUN mkdir -p /permissions-engine
RUN chown -R pcgl:pcgl /permissions-engine

USER pcgl

RUN curl -L -o opa https://openpolicyagent.org/downloads/v1.1.0/opa_linux_amd64_static

RUN chmod 755 ./opa

RUN touch /app/initial_setup

ENTRYPOINT pytest
EXPOSE 1235
