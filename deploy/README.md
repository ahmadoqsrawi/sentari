# Deploying Sentari

Sentari's core is a single-host CLI (standard library only). These files run it as a distributed service instead: a pool of Celery workers that execute scans, and a read-only dashboard, backed by Redis (the broker) and Postgres (the shared run store).

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

The components are `redis` (broker and result backend), `postgres` (shared run store), `sentari-worker` (the Celery workers, which you scale horizontally), and `sentari-dashboard` (the read-only viewer). The dashboard is internal (ClusterIP). Expose it deliberately through an Ingress with authentication, and never open the scan tooling to the public.
