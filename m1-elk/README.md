# Member 1: ELK Infrastructure & Environment Setup

This directory contains the Docker Compose environment for the TraceHunt ELK stack.

## Services & Ports
- **Elasticsearch:** http://localhost:9200 (Single-node, security disabled for local dev)
- **Kibana:** http://localhost:5601
- **Logstash:**
  - Beats (Push): Port `5044`
  - TCP Stream: Port `5000` (JSON lines)

Logstash reads its pipeline from `pipeline/logstash.conf`. Right now the pipeline just accepts events and writes them to a daily raw index (`tracehunt-raw-YYYY.MM.DD`); M2 will extend it per log source.

## Quick Start
1. Ensure Docker Desktop is running.
2. Start the stack:
   ```bash
   docker compose up -d
   ```
3. Wait until Elasticsearch reports healthy (about 1 minute on first start):
   ```bash
   docker compose ps
   ```
4. Verify the stack:
   - On Windows: `.\health_check.ps1`
   - Anywhere: `curl http://localhost:9200/_cluster/health` and open http://localhost:5601
5. Send a test event through the TCP input:
   ```bash
   echo '{"test":"hello tracehunt"}' | nc localhost 5000
   curl 'http://localhost:9200/tracehunt-raw-*/_search?pretty'
   ```

## Rebuild & Reset
- Stop the stack and keep data: `docker compose down`
- Stop and delete all data (fresh start): `docker compose down -v`
- After editing `docker-compose.yml` or the pipeline: `docker compose up -d --force-recreate logstash` (or the service you changed)
- Full rebuild from scratch: `docker compose down -v && docker compose up -d`

## Notes
- Elasticsearch runs with security disabled for local dev. Access control is a later M1 task; do not expose these ports outside localhost.
- `ES_JAVA_OPTS` is capped at 1 GB heap. Raise it only if your machine has the RAM to spare.
