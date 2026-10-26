#!/usr/bin/env python3
"""Send one fleet/work-queue event under phantom exec; never read an API key."""

import argparse
import datetime
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def capture(event, distinct_id, properties):
    base = os.environ.get("POSTHOG_BASE_URL", "")
    url = urllib.parse.urlsplit(base)
    # Fail closed outside the exec-exported loopback route. Its URL and proxy
    # bearer are sensitive session metadata and must not enter diagnostics.
    if (
        url.scheme != "http"
        or url.hostname != "127.0.0.1"
        or not url.port
        or url.username
        or url.password
        or url.query
        or url.fragment
        or not re.fullmatch(r"/posthog_fleet(?:/_phantom/[0-9a-f]+)?/?", url.path)
    ):
        raise ValueError("run under phantom exec")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_id = str(uuid.uuid4())
    body = {
        "created_at": now,
        "batch": [
            {
                "uuid": event_id,
                "event": event,
                "distinct_id": distinct_id,
                "timestamp": now,
                "properties": properties,
            }
        ],
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "phantom-fleet/1.0.0",
        "PostHog-Sdk-Info": "phantom-fleet/1.0.0",
        "PostHog-Attempt": "1",
        "PostHog-Request-Id": str(uuid.uuid4()),
        "PostHog-Request-Timestamp": now,
        "x-phantom-proxy-token": os.environ["PHANTOM_PROXY_TOKEN"],
    }
    request = urllib.request.Request(
        base.rstrip("/") + "/i/v1/analytics/events",
        method="POST",
        data=json.dumps(body).encode(),
        headers=headers,
    )
    # Ignore ambient proxy configuration and never follow redirects carrying
    # session auth. Phantom independently pins the HTTPS provider destination.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=30) as response:
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError("capture failed")
        payload = json.loads(raw)
    results = payload.get("results") if isinstance(payload, dict) else None
    if (
        not isinstance(results, dict)
        or set(results) != {event_id}
        or not isinstance(results[event_id], dict)
        or results[event_id].get("result") not in ("ok", "warning")
    ):
        raise ValueError("event not accepted")
    print("PostHog capture: HTTP 200, event accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event")
    parser.add_argument("distinct_id")
    parser.add_argument(
        "--properties", default="{}", help="JSON object; never include credentials"
    )
    args = parser.parse_args()
    try:
        properties = json.loads(args.properties)
        if not isinstance(properties, dict):
            raise ValueError("properties must be an object")
        capture(args.event, args.distinct_id, properties)
    except (
        KeyError,
        ValueError,
        OSError,
        urllib.error.URLError,
        http.client.HTTPException,
    ):
        # Exception strings can carry the authenticated URL or provider body.
        print(
            "PostHog capture failed; check Phantom routing and provider status",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
