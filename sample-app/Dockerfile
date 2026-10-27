# Base image pinned by tag and digest. The CI gate fails on fixable CRITICAL
# CVEs in this layer, so bumping the base is the fix.
FROM python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /app
COPY app.py .
USER 65532:65532
EXPOSE 8080
CMD ["python", "app.py"]
