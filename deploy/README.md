# Deploying Sentari

Sentari's core is a single-host CLI (stdlib only). These files are for running it
as a **distributed service**: a Celery worker pool that executes scans and a
read-only dashboard, backed by Redis (broker) and Postgres (shared run store).

> Use Sentari only against systems you are authorized to test. `--authorized`
> and scope are still enforced inside the worker.

## Local stack (Docker Compose)

```bash
docker compose up --build          # redis + worker + dashboard
# enqueue a scan into the worker:
docker compose run --rm worker-cli example.com --scope example.com \
    --authorized --enqueue --db /data/sentari.db
open http://localhost:8600         # dashboard (read-only)
```

## Kubernetes

```bash
# 1) build and push the image
docker build -t <registry>/sentari:latest .
docker push <registry>/sentari:latest
#    then set image: <registry>/sentari:latest in 30-worker.yaml / 40-dashboard.yaml

# 2) EDIT deploy/k8s/00-namespace-config.yaml: change all change-me secrets

# 3) apply (files are ordered by prefix)
kubectl apply -f deploy/k8s/

# 4) scale the worker pool as needed
kubectl -n sentari scale deployment/sentari-worker --replicas=5

# 5) reach the dashboard (ClusterIP by default: front with an Ingress, or:)
kubectl -n sentari port-forward svc/sentari-dashboard 8600:80
```

Components: `redis` (broker/result backend), `postgres` (shared run store),
`sentari-worker` (Celery workers, scale horizontally), `sentari-dashboard`
(read-only viewer). The dashboard is internal (ClusterIP): expose it
deliberately via an Ingress with auth, never open the scan tooling to the public.
