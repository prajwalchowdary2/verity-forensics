#!/bin/bash
# Stop Verity AI Forensics Lab Services
echo "Stopping AI Forensics Lab services..."

# Find and kill HTTP server running on port 8000
HTTP_PID=$(lsof -t -i:8000 -sTCP:LISTEN)
if [ -n "$HTTP_PID" ]; then
    kill "$HTTP_PID"
    echo "Stopped HTTP server."
fi

# Find and kill live_monitor.py process
DAEMON_PID=$(pgrep -f "live_monitor.py")
if [ -n "$DAEMON_PID" ]; then
    kill $DAEMON_PID
    echo "Stopped Live Monitor Daemon."
fi

echo "All services stopped."
