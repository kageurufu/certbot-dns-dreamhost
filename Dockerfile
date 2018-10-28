FROM certbot/certbot

COPY . src/certbot-dns-dreamhost

RUN pip install --no-cache-dir --editable src/certbot-dns-dreamhost
