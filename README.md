# Self-Hosted Zero Trust Architecture

This project implements a full self-hosted infrastructure stack with containerization, secure gateway routing, Keycloak authentication, VPN access, RBAC enforcement, file sharing, monitoring, logging, and an optional AI security layer.

## What is included

- Traefik reverse proxy with HTTPS routing
- Keycloak identity provider with SSO, MFA-ready setup, OAuth2/OpenID Connect support
- Nextcloud secure file sharing
- WireGuard VPN for remote access
- RBAC application demonstrating role-based authorization
- Prometheus and Grafana monitoring
- Wazuh security monitoring and dashboard
- Fail2ban / SSH hardening helper scripts
- AI security layer for anomalous login and traffic detection

## Requirements

- Docker
- Docker Compose (or Docker Compose plugin)
- Ubuntu Server or another Linux host for production
- Optional: local DNS entries for mapped hostnames

- Docker Desktop must be running before starting the stack.

## Setup steps

1. Copy `.env.example` to `.env` and update hostnames.
2. Add each hostname to your `/etc/hosts` (or DNS) pointing to your server IP.
   - `keycloak.local`
   - `nextcloud.local`
   - `app.local`
   - `grafana.local`
   - `prometheus.local`
   - `wazuh.local`
   - `traefik.local`
4. Run `docker compose up -d`.
5. Open the service URLs in your browser:
   - `https://${KEYCLOAK_HOST}` for Keycloak
   - `https://${NEXTCLOUD_HOST}` for Nextcloud
   - `https://${APP_HOST}` for the RBAC demo app
   - `https://${GRAFANA_HOST}` for Grafana
   - `https://${PROMETHEUS_HOST}` for Prometheus
   - `https://${WAZUH_HOST}` for Wazuh Dashboard
   - `https://traefik.local` for the Traefik dashboard

## Host hardening

Run the helper scripts in `scripts/` on your Ubuntu host to enable firewall rules and SSH hardening.

## Notes

- Traefik is configured for Let's Encrypt TLS. For local testing, use proper DNS and/or replace with self-signed certs.
- The Keycloak realm import file seeds roles and test users for Admin, Security Analyst, Developer, and Guest roles.
- The RBAC app validates JWTs from Keycloak and enforces role-based access to `/dashboard`, `/logs`, `/storage`, and `/admin`.
- The AI security service ingests application logs and writes anomaly alerts into `monitoring/ai/alerts/`.
