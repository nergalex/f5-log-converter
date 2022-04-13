# syntax=docker/dockerfile:1.3

############################################# Base image for Python #############################################
FROM nginx/unit:1.26.1-python3.10

# port used by the listener in config.json
EXPOSE 8080
EXPOSE 8443

RUN apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y tcpdump git curl net-tools iproute2 \
    && mkdir -p /var/log/unit/ \
    && touch /var/log/unit/access.log \
    && chown -R unit:0 /var/log/unit/ \
    && mkdir /etc/faas-apps/ \
    && chown -R unit:unit /etc/faas-apps/ \
    && python3 -m venv /etc/faas-apps/venv

############################################# Create App's virtual environment #############################################
ARG FAAS_APP_NAME=logstream-xc
ARG GITHUB_BASE_REF=master
ARG GITHUB_REPOSITORY

RUN mkdir -p /etc/faas-apps/${FAAS_APP_NAME}/
ADD https://api.github.com/repos/${GITHUB_REPOSITORY}/git/refs/heads/${GITHUB_BASE_REF} version.json
RUN git clone -b ${GITHUB_BASE_REF} https://github.com/${GITHUB_REPOSITORY}.git /etc/faas-apps/${FAAS_APP_NAME} \
    && /etc/faas-apps/venv/bin/pip install -r /etc/faas-apps/${FAAS_APP_NAME}/requirements.txt
RUN touch /etc/faas-apps/logstream-xc/logstream-app.log \
    chown unit:unit /etc/faas-apps/logstream-xc/logstream-app.log

############################################# Prepare Unit #############################################

COPY ./build/*.pem  /docker-entrypoint.d/
COPY ./build/*.json /docker-entrypoint.d/
COPY ./build/*.sh   /docker-entrypoint.d/
RUN chown unit:unit /docker-entrypoint.d/*.pem \
    && chown unit:unit /docker-entrypoint.d/*.json \
    && chown unit:unit /docker-entrypoint.d/*.sh \
    && chmod 444 /docker-entrypoint.d/*.pem \
    && chmod 444 /docker-entrypoint.d/*.json \
    && chmod 555 /docker-entrypoint.d/*.sh

############################################# Clean Unit in order to launch entrypoints at startup #############################################
RUN rm -rf /var/lib/unit/*

############################################# Launch Unit #############################################
CMD ["unitd", \
    "--no-daemon", \
    "--control", "0.0.0.0:8000", \
    "--pid", "/unit/unit.pid"]


