# Image every run_python call executes in. No extra packages on purpose.
FROM python:3.11-slim
RUN useradd --uid 65534 --no-create-home --shell /usr/sbin/nologin sandbox 2>/dev/null || true
WORKDIR /tmp
USER 65534:65534
CMD ["python", "-I", "-"]
