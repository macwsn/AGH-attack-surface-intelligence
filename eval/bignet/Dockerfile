FROM python:3.13-alpine
RUN apk add --no-cache iproute2 iptables
COPY responder.py /responder.py
ENTRYPOINT ["python3", "/responder.py"]
CMD ["serve"]
