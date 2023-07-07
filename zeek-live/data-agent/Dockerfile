FROM python:3-slim as builder
RUN adduser --system --no-create-home nonroot
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM builder
WORKDIR /usr/src/app
COPY receiver.py  .

USER nonroot
EXPOSE 4000
CMD [ "gunicorn", "--bind", "0.0.0.0:4000", "receiver:app"]
