# mcpsweep vulnlab — intentionally-vulnerable MCP server (lab use only)
FROM python:3.12-slim

LABEL org.opencontainers.image.title="mcpsweep-vulnlab" \
      org.opencontainers.image.description="Deliberately-vulnerable MCP server for testing mcpsweep. Isolated lab use only." \
      org.opencontainers.image.source="https://github.com/krishnareddypadala/mcpsweep"

WORKDIR /app
COPY . /app/vulnlab/

EXPOSE 9100
ENV VULNLAB_HOST=0.0.0.0 VULNLAB_PORT=9100
# Flip these to demonstrate specific scenarios:
#   VULNLAB_OAUTH_SSRF=1   -> OAuth metadata points at link-local (SSRF)
#   MCPSWEEP_RUGPULL=1     -> /mcp/rugpull serves the poisoned tool definition
CMD ["python", "-m", "vulnlab"]
