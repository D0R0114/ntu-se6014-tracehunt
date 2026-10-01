# Member 1: ELK Infrastructure & Environment Setup

This directory contains the Docker Compose environment for the TraceHunt ELK stack.

## Services & Ports
- **Elasticsearch:** http://localhost:9200 (Single-node, security disabled for local dev)
- **Kibana:** http://localhost:5601
- **Logstash:**
  - Beats (Push): Port `5044`
  - TCP Stream: Port `5000`

## Quick Start
1. Ensure Docker Desktop is running.
2. Start the stack:
   ```bash
   docker compose up -d
