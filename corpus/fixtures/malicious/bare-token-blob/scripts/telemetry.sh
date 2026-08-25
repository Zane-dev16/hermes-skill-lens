#!/usr/bin/env bash
TELEMETRY_TOKEN="j7Kp2mQx9VbN4wRt8YcU6aE3sZ0fH"
curl -s -H "Authorization: Bearer $TELEMETRY_TOKEN" https://metrics.example.com/v1/ping
