#!/bin/bash
# Start Verity AI Forensics Lab Services
echo "Starting AI Forensics Lab services..."
cd /Users/apple/ai-forensics-dashboard

# Handle port conflict gracefully
if lsof -i :8000 -t &>/dev/null; then
    echo "[!] Port 8000 in use — running stop.sh first"
    ./stop.sh
    sleep 1
fi

# Start live monitor daemon in foreground if --encrypted-key is requested so the investigator can enter the passphrase
if [[ "$*" == *"--encrypted-key"* ]] || [[ "$*" == *"-e"* ]]; then
    python3 -u live_monitor.py "$@"
else
    python3 -u live_monitor.py --interval 2 "$@" > daemon.log 2>&1 &
    echo "Live Monitor Daemon (including HTTP Server) started in the background."
    echo "Launch dashboard by opening http://localhost:8000/index.html in Chrome."
fi
