FROM docker.elastic.co/logstash/logstash-oss:8.6.2

COPY --chown=root:logstash logstash.conf /usr/share/logstash/pipeline/logstash.conf

COPY --chown=root:logstash logstash.yml /usr/share/logstash/config/logstash.yml
