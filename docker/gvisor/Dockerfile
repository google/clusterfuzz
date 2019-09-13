FROM gcr.io/clusterfuzz-images/base

COPY start_gvisor.sh /data/start.sh
RUN cp /bin/true /bin/mount
RUN cp /bin/true /bin/chown

CMD ["bash", "-ex", "/data/start.sh"]
