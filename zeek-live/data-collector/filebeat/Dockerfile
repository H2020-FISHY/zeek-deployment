FROM docker.elastic.co/beats/filebeat:8.6.2

COPY --chown=root:filebeat filebeat.yml /usr/share/filebeat/filebeat.yml 
CMD ["--modules", "zeek", "-e", "-environment", "container"]
