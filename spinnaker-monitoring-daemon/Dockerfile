# This Dockerfile places the python server in /opt/spinnaker-monitoring/bin, and expects
# config to be mounted in /opt/spinnaker-monitoring/config, which includes the
# spinnaker-monitoring.yml file.
FROM python:2.7.14-alpine3.7

COPY spinnaker-monitoring /opt/spinnaker-monitoring/bin

COPY requirements.txt /opt/spinnaker-monitoring/requirements.txt

WORKDIR /opt/spinnaker-monitoring

RUN sed -ie 's/#@ //g' requirements.txt

RUN pip install -r requirements.txt

ENV PYTHONWARNINGS "once"

RUN addgroup spinnaker
RUN adduser spinnaker -D -G spinnaker
USER spinnaker

ENTRYPOINT ["python", "/opt/spinnaker-monitoring/bin"]
CMD ["--config", "/opt/spinnaker-monitoring/config/spinnaker-monitoring.yml", "monitor"]
