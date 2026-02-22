FROM python:3.13-bookworm

# BCC dependencies + py-spy
RUN apt-get update && apt-get install -y \
    bpfcc-tools python3-bpfcc linux-headers-generic \
    && pip install py-spy \
    && rm -rf /var/lib/apt/lists/*

# Make system-installed bcc visible to Python 3.13
ENV PYTHONPATH="/usr/lib/python3/dist-packages:${PYTHONPATH}"

WORKDIR /app
COPY . .
RUN pip install -e ".[dev]"

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
