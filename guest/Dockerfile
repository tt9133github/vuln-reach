FROM ghcr.io/chaitin/agent-compose-guest:v2607.10.0

COPY requirements.txt /tmp/vuln-reach-requirements.txt
RUN python3 -m pip install \
      --break-system-packages \
      --no-cache-dir \
      --requirement /tmp/vuln-reach-requirements.txt \
    && rm -f /tmp/vuln-reach-requirements.txt
