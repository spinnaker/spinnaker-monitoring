FROM python:2.7

COPY spinnaker-monitoring /opt/spinnaker-monitoring/bin

COPY requirements.txt /opt/spinnaker-monitoring/requirements.txt

WORKDIR /opt/spinnaker-monitoring

RUN pip install -r requirements.txt

ENV PYTHONWARNINGS "once"

CMD ["python", "/opt/spinnaker-monitoring/bin", "--config_dir", "/opt/spinnaker-monitoring/config", "monitor"]
