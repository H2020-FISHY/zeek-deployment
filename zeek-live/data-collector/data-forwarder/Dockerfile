FROM python:3-slim as builder
RUN adduser --system --no-create-home nonroot
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM builder
WORKDIR /usr/src/app
COPY main.py  .

USER nonroot
CMD [ "gunicorn", "--bind", "0.0.0.0:5000", "main:app"]
