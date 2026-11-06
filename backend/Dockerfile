FROM docker:27-cli AS dockercli

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

# docker CLI only: the backend asks the host daemon to start sandbox containers.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend backend
COPY agents agents
COPY contracts contracts
RUN mkdir -p /srv/results /srv/data

WORKDIR /srv/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
