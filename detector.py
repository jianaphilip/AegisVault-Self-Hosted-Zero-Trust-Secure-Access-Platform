import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta

LOG_FILE = '/data/logs/access.log'
ALERT_FILE = '/data/alerts/alerts.json'
SCAN_INTERVAL = 30

ip_pattern = re.compile(r'user=(?P<user>\w+) roles=\[(?P<roles>[^\]]*)\] path=(?P<path>[^ ]+)')


def parse_line(line):
    match = ip_pattern.search(line)
    if not match:
        return None
    user = match.group('user')
    roles = [role.strip() for role in match.group('roles').split(',') if role.strip()]
    path = match.group('path')
    return {'user': user, 'roles': roles, 'path': path}


def read_events():
    if not os.path.exists(LOG_FILE):
        return []
    events = []
    with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            event = parse_line(line)
            if event:
                events.append({'timestamp': line[:19], **event})
    return events


def find_anomalies(events):
    now = datetime.utcnow()
    alerts = []
    counts = defaultdict(int)
    for event in events:
        user = event['user']
        path = event['path']
        counts[(user, path)] += 1
    for (user, path), count in counts.items():
        if count >= 10:
            alerts.append({
                'user': user,
                'path': path,
                'severity': 'high',
                'message': f'High frequency access detected: {count} hits for {path}'
            })
    return alerts


def write_alerts(alerts):
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)
    payload = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'alerts': alerts,
    }
    with open(ALERT_FILE, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, indent=2)


if __name__ == '__main__':
    while True:
        events = read_events()
        alerts = find_anomalies(events)
        write_alerts(alerts)
        time.sleep(SCAN_INTERVAL)
