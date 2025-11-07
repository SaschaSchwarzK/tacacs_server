FROM mcr.microsoft.com/azure-storage/azurite:latest

LABEL org.opencontainers.image.title="tacacs-azurite" \
      org.opencontainers.image.description="Azurite (Azure Storage emulator) for TACACS E2E tests" \
      org.opencontainers.image.source="https://github.com/Azure/Azurite"

USER root

RUN mkdir -p /workspace /var/log/azurite && \
    chmod -R 0777 /workspace /var/log/azurite

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 10000 10001 10002
VOLUME ["/workspace"]

ENTRYPOINT ["/entrypoint.sh"]

