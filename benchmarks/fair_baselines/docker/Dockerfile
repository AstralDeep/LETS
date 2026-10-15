# Experiment-only image for one E1 site: the LETS package plus pysyncobj, iptables, and iproute2
# so the controller can inject real kernel-level partitions and netem delay with docker exec.
# This is not the production LETS image in the repository root.
FROM python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
RUN apk add --no-cache iptables iproute2 \
    && pip install --no-cache-dir --no-compile PyNaCl==1.6.2 pysyncobj==0.3.17
WORKDIR /app
COPY src/lets /app/src/lets
COPY benchmarks/__init__.py /app/benchmarks/__init__.py
COPY benchmarks/fair_baselines /app/benchmarks/fair_baselines
ENV PYTHONPATH=/app/src:/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
VOLUME ["/state"]
ENTRYPOINT ["python", "-m", "benchmarks.fair_baselines.site_agent"]
