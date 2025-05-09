A lightweight, privacy-preserving network monitoring solution for senior-friendly smart homes.

Description

This project implements a header-only traffic monitor that captures metadata from IoT devices on a local Linux gateway, detects anomalies using both rule-based logic and unsupervised learning, and delivers real-time alerts to caregivers via a secure REST API and web dashboard. It requires no specialized hardware and maintains resident privacy by inspecting only packet headers (no payloads).

Features

Header-Only Capture: Collects IPs, ports, protocols, packet sizes, and flags.

Rule-Based Alerts: Configurable threshold checks (e.g., SYN flood, unauthorized IP access).

Machine Learning: Isolation Forest for detecting novel traffic deviations.

Secure API: Flask backend with HTTPS/TLS and JWT authentication.

Live Dashboard: React frontend displaying alerts, acknowledgments, and device control actions.

Resource Efficient: CPU ≤ 35% and RAM ≤ 500 MB on commodity hardware.

Docker Support: Ready-to-use Dockerfiles for all components.

Architecture

Traffic Daemon (traffic_sniffer.py): Python script using Scapy or PyShark to sniff and aggregate flow statistics in real time.

Anomaly Engine: Hybrid pipeline combining simple rules with an Isolation Forest model to score and flag suspicious flows.

Backend (backend/app.py): Flask application exposing /api/alerts endpoints and persisting events in a SQLite database.

Frontend (frontend/): React application that polls the API, displays time-stamped alerts, and provides control actions (mute, throttle, disable).
