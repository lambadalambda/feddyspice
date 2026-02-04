import re
import os
import time
import html
from dataclasses import dataclass

import pytest
import requests


@dataclass(frozen=True)
class FedboxConfig:
    scheme: str
    pleroma_handle: str
    mastodon_handle: str
    feddyspice_handle: str
    password: str
    cacertfile: str


def cfg() -> FedboxConfig:
    return FedboxConfig(
        scheme=os.getenv("FEDTEST_SCHEME", "https"),
        pleroma_handle=os.getenv("FEDTEST_PLEROMA_HANDLE", "@bob@pleroma.test"),
        mastodon_handle=os.getenv("FEDTEST_MASTODON_HANDLE", "@carol@mastodon.test"),
        feddyspice_handle=os.getenv("FEDTEST_FEDDYSPICE_HANDLE", "@alice@feddyspice.test"),
        password=os.getenv("FEDTEST_PASSWORD", "password"),
        cacertfile=os.getenv("FEDTEST_CACERTFILE", "/caddy/pki/authorities/local/root.crt"),
    )


def verify_arg() -> str | bool:
    path = cfg().cacertfile
    return path if os.path.exists(path) else True


def wait_until(fn, *, desc: str, timeout_s: int = 180, interval_s: float = 1.0) -> None:
    deadline = time.time() + timeout_s
    last_exc: Exception | None = None

    while time.time() < deadline:
        try:
            if fn():
                return
        except Exception as exc:  # noqa: BLE001 - used for polling in tests
            last_exc = exc
        time.sleep(interval_s)

    if last_exc:
        raise AssertionError(f"timeout: {desc} (last error: {last_exc})")
    raise AssertionError(f"timeout: {desc}")


def parse_handle(handle: str) -> tuple[str, str]:
    h = handle.lstrip("@")
    username, domain = h.split("@", 1)
    return username, domain


def base_url_for(domain: str) -> str:
    return f"{cfg().scheme}://{domain}"


def webfinger_self_href(username: str, domain: str) -> str | None:
    resp = requests.get(
        f"{base_url_for(domain)}/.well-known/webfinger",
        params={"resource": f"acct:{username}@{domain}"},
        headers={"accept": "application/jrd+json"},
        verify=verify_arg(),
        timeout=10,
        allow_redirects=True,
    )

    if resp.status_code < 200 or resp.status_code >= 300:
        return None

    body = resp.json()
    for link in body.get("links", []):
        if link.get("rel") == "self" and isinstance(link.get("href"), str) and link["href"]:
            return link["href"]
    return None


def id_variants(uri: str) -> set[str]:
    if not uri:
        return set()
    base = uri.rstrip("/")
    return {base, f"{base}/"}


def fetch_ap_json(url: str) -> dict:
    resp = requests.get(
        url,
        headers={"accept": "application/activity+json"},
        verify=verify_arg(),
        timeout=10,
        allow_redirects=True,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise TypeError(f"expected object JSON from {url}")
    return data


def fetch_collection_items(url: str) -> list:
    data = fetch_ap_json(url)

    if isinstance(data.get("orderedItems"), list):
        return data["orderedItems"]
    if isinstance(data.get("items"), list):
        return data["items"]

    first = data.get("first")
    if isinstance(first, str) and first:
        data2 = fetch_ap_json(first)
        if isinstance(data2.get("orderedItems"), list):
            return data2["orderedItems"]
        if isinstance(data2.get("items"), list):
            return data2["items"]

    return []


def extract_ids(item) -> list[str]:
    if isinstance(item, str):
        return [item]
    if isinstance(item, dict) and isinstance(item.get("id"), str):
        return [item["id"]]
    return []


def follower_id_set(actor_id: str) -> set[str]:
    actor = fetch_ap_json(actor_id)
    followers = actor.get("followers")
    if not isinstance(followers, str) or not followers:
        return set()

    ids: set[str] = set()
    for item in fetch_collection_items(followers):
        for i in extract_ids(item):
            ids |= id_variants(i)
    return ids


def following_id_set(actor_id: str) -> set[str]:
    actor = fetch_ap_json(actor_id)
    following = actor.get("following")
    if not isinstance(following, str) or not following:
        return set()

    ids: set[str] = set()
    for item in fetch_collection_items(following):
        for i in extract_ids(item):
            ids |= id_variants(i)
    return ids


def create_pleroma_password_token(
    pleroma_base_url: str, username: str, password: str, scopes: str
) -> str:
    app = requests.post(
        f"{pleroma_base_url}/api/v1/apps",
        data={
            "client_name": "fedbox",
            "redirect_uris": "urn:ietf:wg:oauth:2.0:oob",
            "scopes": scopes,
            "website": "",
        },
        verify=verify_arg(),
        timeout=10,
    )
    app.raise_for_status()
    app_json = app.json()

    client_id = app_json["client_id"]
    client_secret = app_json["client_secret"]

    def try_username(u: str) -> str:
        token = requests.post(
            f"{pleroma_base_url}/oauth/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "password",
                "username": u,
                "password": password,
                "scope": scopes,
            },
            verify=verify_arg(),
            timeout=10,
        )
        token.raise_for_status()
        return token.json()["access_token"]

    try:
        return try_username(username)
    except requests.HTTPError:
        return try_username(f"{username}@{parse_handle(cfg().pleroma_handle)[1]}")


def follow_remote(pleroma_base_url: str, access_token: str, handle: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/follows",
        headers={"authorization": f"Bearer {access_token}"},
        data={"uri": handle},
        verify=verify_arg(),
        timeout=10,
    )

    if resp.status_code in (404, 405):
        acct = handle.lstrip("@")
        account_id = None

        # Some servers support /api/v1/accounts/lookup for remote accounts, some
        # don't (e.g. the Pleroma build used by fedbox).
        lookup = requests.get(
            f"{pleroma_base_url}/api/v1/accounts/lookup",
            headers={"authorization": f"Bearer {access_token}"},
            params={"acct": acct},
            verify=verify_arg(),
            timeout=10,
        )
        if lookup.status_code >= 200 and lookup.status_code < 300:
            account_id = lookup.json()["id"]

        # Fallback: use accounts/search with resolve=true.
        if account_id is None:
            search = requests.get(
                f"{pleroma_base_url}/api/v1/accounts/search",
                headers={"authorization": f"Bearer {access_token}"},
                params={"q": acct, "resolve": "true"},
                verify=verify_arg(),
                timeout=10,
            )
            search.raise_for_status()
            results = search.json()
            if not isinstance(results, list) or not results:
                raise AssertionError(f"accounts/search returned no results for {acct}")
            account_id = results[0]["id"]

        follow = requests.post(
            f"{pleroma_base_url}/api/v1/accounts/{account_id}/follow",
            headers={"authorization": f"Bearer {access_token}"},
            verify=verify_arg(),
            timeout=10,
        )
        follow.raise_for_status()
        return

    resp.raise_for_status()


def create_feddyspice_token(feddyspice_base_url: str, username: str, password: str, scopes: str) -> str:
    app = requests.post(
        f"{feddyspice_base_url}/api/v1/apps",
        data={
            "client_name": "fedbox",
            "redirect_uris": "urn:ietf:wg:oauth:2.0:oob",
            "scopes": scopes,
            "website": "",
        },
        verify=verify_arg(),
        timeout=10,
    )
    app.raise_for_status()
    app_json = app.json()

    client_id = app_json["client_id"]
    client_secret = app_json["client_secret"]

    session = requests.Session()

    login = session.post(
        f"{feddyspice_base_url}/login",
        data={
            "username": username,
            "password": password,
        },
        verify=verify_arg(),
        timeout=10,
        allow_redirects=False,
    )
    login.raise_for_status()

    auth = session.get(
        f"{feddyspice_base_url}/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "scope": scopes,
            "state": "xyz",
        },
        verify=verify_arg(),
        timeout=10,
        allow_redirects=True,
    )
    auth.raise_for_status()

    auth_post = session.post(
        f"{feddyspice_base_url}/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "scope": scopes,
            "state": "xyz",
            "approve": "1",
        },
        verify=verify_arg(),
        timeout=10,
        allow_redirects=True,
    )
    auth_post.raise_for_status()

    m = re.search(r'<pre id="code">([^<]+)</pre>', auth_post.text)
    if not m:
        raise AssertionError("missing auth code in feddyspice /oauth/authorize response")

    code = m.group(1).strip()

    token = requests.post(
        f"{feddyspice_base_url}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        },
        verify=verify_arg(),
        timeout=10,
    )
    token.raise_for_status()
    return token.json()["access_token"]


def feddyspice_follow(feddyspice_base_url: str, access_token: str, handle: str) -> None:
    resp = requests.post(
        f"{feddyspice_base_url}/api/v1/follows",
        headers={"authorization": f"Bearer {access_token}"},
        data={"uri": handle},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def feddyspice_post(feddyspice_base_url: str, access_token: str, text: str) -> None:
    resp = requests.post(
        f"{feddyspice_base_url}/api/v1/statuses",
        headers={"authorization": f"Bearer {access_token}"},
        data={"status": text, "visibility": "public"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def feddyspice_home_timeline(feddyspice_base_url: str, access_token: str) -> list[dict]:
    resp = requests.get(
        f"{feddyspice_base_url}/api/v1/timelines/home",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise TypeError("expected list timeline")
    return data


def feddyspice_conversations(feddyspice_base_url: str, access_token: str) -> list[dict]:
    resp = requests.get(
        f"{feddyspice_base_url}/api/v1/conversations",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise TypeError("expected list conversations")
    return data


def feddyspice_public_timeline(feddyspice_base_url: str) -> list[dict]:
    resp = requests.get(
        f"{feddyspice_base_url}/api/v1/timelines/public",
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise TypeError("expected list timeline")
    return data


def feddyspice_get_status(feddyspice_base_url: str, access_token: str, status_id: str) -> dict:
    resp = requests.get(
        f"{feddyspice_base_url}/api/v1/statuses/{status_id}",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise TypeError("expected object status")
    return data


def feddyspice_get_context(feddyspice_base_url: str, access_token: str, status_id: str) -> dict:
    resp = requests.get(
        f"{feddyspice_base_url}/api/v1/statuses/{status_id}/context",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise TypeError("expected object context")
    return data


def feddyspice_notifications(feddyspice_base_url: str, access_token: str) -> list[dict]:
    resp = requests.get(
        f"{feddyspice_base_url}/api/v1/notifications",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise TypeError("expected list notifications")
    return data


def pleroma_post(pleroma_base_url: str, access_token: str, text: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses",
        headers={"authorization": f"Bearer {access_token}"},
        data={"status": text, "visibility": "public"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_delete_status(pleroma_base_url: str, access_token: str, status_id: str) -> None:
    resp = requests.delete(
        f"{pleroma_base_url}/api/v1/statuses/{status_id}",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_post_direct(pleroma_base_url: str, access_token: str, to_handle: str, text: str) -> None:
    full_text = f"{to_handle} {text}"
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses",
        headers={"authorization": f"Bearer {access_token}"},
        data={"status": full_text, "visibility": "direct"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_post_reply(pleroma_base_url: str, access_token: str, in_reply_to_id: str, text: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses",
        headers={"authorization": f"Bearer {access_token}"},
        data={
            "status": text,
            "in_reply_to_id": in_reply_to_id,
            "visibility": "public",
        },
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def resolve_account_id(base_url: str, access_token: str, handle: str) -> str:
    acct = handle.lstrip("@")

    lookup = requests.get(
        f"{base_url}/api/v1/accounts/lookup",
        headers={"authorization": f"Bearer {access_token}"},
        params={"acct": acct},
        verify=verify_arg(),
        timeout=10,
    )
    if lookup.status_code >= 200 and lookup.status_code < 300:
        return lookup.json()["id"]

    search = requests.get(
        f"{base_url}/api/v1/accounts/search",
        headers={"authorization": f"Bearer {access_token}"},
        params={"q": acct, "resolve": "true"},
        verify=verify_arg(),
        timeout=10,
    )
    search.raise_for_status()
    results = search.json()
    if not isinstance(results, list) or not results:
        raise AssertionError(f"accounts/search returned no results for {acct}")
    return results[0]["id"]


def pleroma_unfollow(pleroma_base_url: str, access_token: str, handle: str) -> None:
    account_id = resolve_account_id(pleroma_base_url, access_token, handle)
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/accounts/{account_id}/unfollow",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_favourite(pleroma_base_url: str, access_token: str, status_id: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses/{status_id}/favourite",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_unfavourite(pleroma_base_url: str, access_token: str, status_id: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses/{status_id}/unfavourite",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_reblog(pleroma_base_url: str, access_token: str, status_id: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses/{status_id}/reblog",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def pleroma_unreblog(pleroma_base_url: str, access_token: str, status_id: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses/{status_id}/unreblog",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()


def dm_sender_send(inbox: str, to_actor: str, marker: str) -> dict:
    send = requests.post(
        "http://dm_sender:8000/send",
        json={"inbox": inbox, "to": to_actor, "marker": marker},
        timeout=10,
    )
    send.raise_for_status()
    data = send.json()
    assert data.get("inbox_status") in (200, 202)
    assert isinstance(data.get("note_id"), str) and data["note_id"]
    assert isinstance(data.get("activity_id"), str) and data["activity_id"]
    return data


def dm_sender_update(inbox: str, to_actor: str, note_id: str, marker: str) -> dict:
    send = requests.post(
        "http://dm_sender:8000/update",
        json={"inbox": inbox, "to": to_actor, "note_id": note_id, "marker": marker},
        timeout=10,
    )
    send.raise_for_status()
    data = send.json()
    assert data.get("inbox_status") in (200, 202)
    return data


def pleroma_home_timeline(pleroma_base_url: str, access_token: str) -> list[dict]:
    resp = requests.get(
        f"{pleroma_base_url}/api/v1/timelines/home",
        headers={"authorization": f"Bearer {access_token}"},
        verify=verify_arg(),
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise TypeError("expected list timeline")
    return data


def test_webfinger_is_ready_for_seeded_accounts():
    c = cfg()

    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)
    mastodon_user, mastodon_domain = parse_handle(c.mastodon_handle)
    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)

    wait_until(
        lambda: webfinger_self_href(pleroma_user, pleroma_domain) is not None,
        desc=f"webfinger ready {c.pleroma_handle}",
        timeout_s=180,
    )

    wait_until(
        lambda: webfinger_self_href(mastodon_user, mastodon_domain) is not None,
        desc=f"webfinger ready {c.mastodon_handle}",
        timeout_s=240,
    )

    wait_until(
        lambda: webfinger_self_href(feddy_user, feddy_domain) is not None,
        desc=f"webfinger ready {c.feddyspice_handle}",
        timeout_s=60,
    )


def test_pleroma_follow_to_mastodon_is_accepted():
    c = cfg()

    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)
    mastodon_user, mastodon_domain = parse_handle(c.mastodon_handle)

    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    access_token = create_pleroma_password_token(pleroma_base_url, pleroma_user, c.password, scopes)

    follow_remote(pleroma_base_url, access_token, c.mastodon_handle)

    pleroma_actor_id = webfinger_self_href(pleroma_user, pleroma_domain)
    mastodon_actor_id = webfinger_self_href(mastodon_user, mastodon_domain)

    assert pleroma_actor_id
    assert mastodon_actor_id

    pleroma_actor_id_variants = id_variants(pleroma_actor_id)

    wait_until(
        lambda: any(
            v in follower_id_set(mastodon_actor_id) for v in pleroma_actor_id_variants
        ),
        desc=f"follow accepted {c.pleroma_handle} -> {c.mastodon_handle}",
        timeout_s=240,
    )


def test_feddyspice_follow_to_mastodon_is_accepted():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    mastodon_user, mastodon_domain = parse_handle(c.mastodon_handle)

    feddy_base_url = base_url_for(feddy_domain)
    scopes = "read write follow"

    access_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)

    feddyspice_follow(feddy_base_url, access_token, c.mastodon_handle)

    feddy_actor_id = webfinger_self_href(feddy_user, feddy_domain)
    mastodon_actor_id = webfinger_self_href(mastodon_user, mastodon_domain)

    assert feddy_actor_id
    assert mastodon_actor_id

    feddy_actor_id_variants = id_variants(feddy_actor_id)

    wait_until(
        lambda: any(v in follower_id_set(mastodon_actor_id) for v in feddy_actor_id_variants),
        desc=f"follow accepted {c.feddyspice_handle} -> {c.mastodon_handle}",
        timeout_s=240,
    )


def test_feddyspice_follow_to_pleroma_receives_post():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)
    pleroma_token = create_pleroma_password_token(pleroma_base_url, pleroma_user, c.password, scopes)

    feddyspice_follow(feddy_base_url, feddy_token, c.pleroma_handle)

    feddy_actor_id = webfinger_self_href(feddy_user, feddy_domain)
    pleroma_actor_id = webfinger_self_href(pleroma_user, pleroma_domain)

    assert feddy_actor_id
    assert pleroma_actor_id

    pleroma_actor_id_variants = id_variants(pleroma_actor_id)

    wait_until(
        lambda: any(v in following_id_set(feddy_actor_id) for v in pleroma_actor_id_variants),
        desc=f"follow accepted {c.feddyspice_handle} -> {c.pleroma_handle}",
        timeout_s=240,
    )

    marker = f"[fedbox] pleroma -> feddyspice {time.time()}"
    pleroma_post(pleroma_base_url, pleroma_token, marker)

    wait_until(
        lambda: any(
            marker in html.unescape(item.get("content", ""))
            for item in feddyspice_home_timeline(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received remote post from pleroma",
        timeout_s=240,
        interval_s=2.0,
    )


def test_feddyspice_post_reaches_pleroma_follower():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)
    pleroma_token = create_pleroma_password_token(pleroma_base_url, pleroma_user, c.password, scopes)

    follow_remote(pleroma_base_url, pleroma_token, c.feddyspice_handle)

    feddy_actor_id = webfinger_self_href(feddy_user, feddy_domain)
    pleroma_actor_id = webfinger_self_href(pleroma_user, pleroma_domain)

    assert feddy_actor_id
    assert pleroma_actor_id

    pleroma_actor_id_variants = id_variants(pleroma_actor_id)

    wait_until(
        lambda: any(v in follower_id_set(feddy_actor_id) for v in pleroma_actor_id_variants),
        desc=f"follow accepted {c.pleroma_handle} -> {c.feddyspice_handle}",
        timeout_s=240,
    )

    marker = f"[fedbox] feddyspice -> pleroma {time.time()}"
    feddyspice_post(feddy_base_url, feddy_token, marker)

    wait_until(
        lambda: any(
            marker in html.unescape(item.get("content", ""))
            for item in pleroma_home_timeline(pleroma_base_url, pleroma_token)
        ),
        desc="pleroma received remote post from feddyspice",
        timeout_s=240,
        interval_s=2.0,
    )


def test_signed_direct_to_feddyspice_is_received_and_not_public():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)

    feddy_base_url = base_url_for(feddy_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)

    feddy_actor_id = webfinger_self_href(feddy_user, feddy_domain)
    assert feddy_actor_id

    # The seeded inbox URL is `https://...`, but the DM sender uses plain HTTP to
    # avoid extra TLS/CA plumbing in the test harness.
    actor = fetch_ap_json(feddy_actor_id)
    inbox = actor.get("inbox")
    assert isinstance(inbox, str) and inbox
    inbox_http = inbox.replace("https://", "http://", 1)

    marker = f"[fedbox] signed direct -> feddyspice {time.time()}"

    dm_sender_send(inbox_http, feddy_actor_id, marker)

    wait_until(
        lambda: any(
            marker in html.unescape(
                conv.get("last_status", {}).get("content", "")
                if isinstance(conv, dict)
                else ""
            )
            for conv in feddyspice_conversations(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received signed direct message",
        timeout_s=240,
        interval_s=2.0,
    )

    convs = feddyspice_conversations(feddy_base_url, feddy_token)
    conv = next(
        c
        for c in convs
        if marker in html.unescape(c.get("last_status", {}).get("content", ""))
    )
    dm = conv.get("last_status", {})
    assert dm.get("visibility") == "direct"

    assert not any(
        marker in html.unescape(item.get("content", ""))
        for item in feddyspice_public_timeline(feddy_base_url)
    )


def test_pleroma_direct_to_feddyspice_is_received_and_not_public():
    if os.getenv("FEDTEST_ENABLE_PLEROMA_DIRECT", "").lower() not in ("1", "true", "yes"):
        pytest.skip("Pleroma direct-message federation is flaky in fedbox; enable with FEDTEST_ENABLE_PLEROMA_DIRECT=1")

    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_domain = parse_handle(c.pleroma_handle)[1]

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)
    pleroma_token = create_pleroma_password_token(pleroma_base_url, "dave", c.password, scopes)

    follow_remote(pleroma_base_url, pleroma_token, c.feddyspice_handle)

    marker = f"[fedbox] pleroma direct -> feddyspice {time.time()}"
    pleroma_post_direct(pleroma_base_url, pleroma_token, c.feddyspice_handle, marker)

    wait_until(
        lambda: any(
            marker in html.unescape(
                conv.get("last_status", {}).get("content", "")
                if isinstance(conv, dict)
                else ""
            )
            for conv in feddyspice_conversations(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received direct message from pleroma",
        timeout_s=240,
        interval_s=2.0,
    )

    convs = feddyspice_conversations(feddy_base_url, feddy_token)
    conv = next(
        c
        for c in convs
        if marker in html.unescape(c.get("last_status", {}).get("content", ""))
    )
    dm = conv.get("last_status", {})
    assert dm.get("visibility") == "direct"

    assert not any(
        marker in html.unescape(item.get("content", ""))
        for item in feddyspice_public_timeline(feddy_base_url)
    )


def test_signed_update_note_edits_are_applied():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)

    feddy_base_url = base_url_for(feddy_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)

    feddy_actor_id = webfinger_self_href(feddy_user, feddy_domain)
    assert feddy_actor_id

    actor = fetch_ap_json(feddy_actor_id)
    inbox = actor.get("inbox")
    assert isinstance(inbox, str) and inbox
    inbox_http = inbox.replace("https://", "http://", 1)

    marker1 = f"[fedbox] signed create -> feddyspice {time.time()}"
    send_json = dm_sender_send(inbox_http, feddy_actor_id, marker1)
    note_id = send_json["note_id"]

    wait_until(
        lambda: any(
            marker1 in html.unescape(
                conv.get("last_status", {}).get("content", "")
                if isinstance(conv, dict)
                else ""
            )
            for conv in feddyspice_conversations(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received initial signed note",
        timeout_s=240,
        interval_s=2.0,
    )

    marker2 = f"[fedbox] signed update -> feddyspice {time.time()}"
    dm_sender_update(inbox_http, feddy_actor_id, note_id, marker2)

    wait_until(
        lambda: any(
            marker2 in html.unescape(
                conv.get("last_status", {}).get("content", "")
                if isinstance(conv, dict)
                else ""
            )
            for conv in feddyspice_conversations(feddy_base_url, feddy_token)
        ),
        desc="feddyspice applied signed Update(Note)",
        timeout_s=240,
        interval_s=2.0,
    )

    convs = feddyspice_conversations(feddy_base_url, feddy_token)
    conv = next(
        c
        for c in convs
        if marker2 in html.unescape(c.get("last_status", {}).get("content", ""))
    )
    dm = conv.get("last_status", {})
    assert dm.get("visibility") == "direct"

    assert not any(
        marker2 in html.unescape(item.get("content", ""))
        for item in feddyspice_public_timeline(feddy_base_url)
    )


def test_pleroma_unfollow_to_feddyspice_removes_follower():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_domain = parse_handle(c.pleroma_handle)[1]

    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    pleroma_token = create_pleroma_password_token(pleroma_base_url, "dave", c.password, scopes)
    follow_remote(pleroma_base_url, pleroma_token, c.feddyspice_handle)

    feddy_actor_id = webfinger_self_href(feddy_user, feddy_domain)
    pleroma_actor_id = webfinger_self_href("dave", pleroma_domain)
    assert feddy_actor_id
    assert pleroma_actor_id

    pleroma_actor_id_variants = id_variants(pleroma_actor_id)

    wait_until(
        lambda: any(v in follower_id_set(feddy_actor_id) for v in pleroma_actor_id_variants),
        desc=f"follow accepted @dave@{pleroma_domain} -> {c.feddyspice_handle}",
        timeout_s=240,
        interval_s=2.0,
    )

    pleroma_unfollow(pleroma_base_url, pleroma_token, c.feddyspice_handle)

    wait_until(
        lambda: all(v not in follower_id_set(feddy_actor_id) for v in pleroma_actor_id_variants),
        desc=f"unfollow processed @dave@{pleroma_domain} -> {c.feddyspice_handle}",
        timeout_s=240,
        interval_s=2.0,
    )


def test_pleroma_reacts_to_feddyspice_status_and_undo_updates_counts():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)
    pleroma_token = create_pleroma_password_token(pleroma_base_url, pleroma_user, c.password, scopes)

    follow_remote(pleroma_base_url, pleroma_token, c.feddyspice_handle)

    marker = f"[fedbox] reactions {time.time()}"
    feddyspice_post(feddy_base_url, feddy_token, marker)

    def local_status_id() -> str | None:
        for item in feddyspice_home_timeline(feddy_base_url, feddy_token):
            if marker in html.unescape(item.get("content", "")):
                return item.get("id")
        return None

    wait_until(lambda: local_status_id() is not None, desc="feddyspice created local status", timeout_s=60)
    feddy_status_id = local_status_id()
    assert feddy_status_id

    def pleroma_status_id() -> str | None:
        for item in pleroma_home_timeline(pleroma_base_url, pleroma_token):
            if marker in html.unescape(item.get("content", "")):
                return item.get("id")
        return None

    wait_until(
        lambda: pleroma_status_id() is not None,
        desc="pleroma received remote post from feddyspice",
        timeout_s=240,
        interval_s=2.0,
    )
    pleroma_status_id_val = pleroma_status_id()
    assert pleroma_status_id_val

    pleroma_favourite(pleroma_base_url, pleroma_token, pleroma_status_id_val)
    wait_until(
        lambda: feddyspice_get_status(feddy_base_url, feddy_token, feddy_status_id).get("favourites_count") == 1,
        desc="feddyspice received Like",
        timeout_s=240,
        interval_s=2.0,
    )

    pleroma_unfavourite(pleroma_base_url, pleroma_token, pleroma_status_id_val)
    wait_until(
        lambda: feddyspice_get_status(feddy_base_url, feddy_token, feddy_status_id).get("favourites_count") == 0,
        desc="feddyspice received Undo(Like)",
        timeout_s=240,
        interval_s=2.0,
    )

    pleroma_reblog(pleroma_base_url, pleroma_token, pleroma_status_id_val)
    wait_until(
        lambda: feddyspice_get_status(feddy_base_url, feddy_token, feddy_status_id).get("reblogs_count") == 1,
        desc="feddyspice received Announce",
        timeout_s=240,
        interval_s=2.0,
    )

    pleroma_unreblog(pleroma_base_url, pleroma_token, pleroma_status_id_val)
    wait_until(
        lambda: feddyspice_get_status(feddy_base_url, feddy_token, feddy_status_id).get("reblogs_count") == 0,
        desc="feddyspice received Undo(Announce)",
        timeout_s=240,
        interval_s=2.0,
    )


def test_pleroma_reply_to_feddyspice_status_appears_in_context():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)
    pleroma_token = create_pleroma_password_token(pleroma_base_url, pleroma_user, c.password, scopes)

    follow_remote(pleroma_base_url, pleroma_token, c.feddyspice_handle)

    root_marker = f"[fedbox] root {time.time()}"
    feddyspice_post(feddy_base_url, feddy_token, root_marker)

    def local_root_id() -> str | None:
        for item in feddyspice_home_timeline(feddy_base_url, feddy_token):
            if root_marker in html.unescape(item.get("content", "")):
                return item.get("id")
        return None

    wait_until(lambda: local_root_id() is not None, desc="feddyspice created root status", timeout_s=60)
    feddy_root_id = local_root_id()
    assert feddy_root_id

    def pleroma_root_id() -> str | None:
        for item in pleroma_home_timeline(pleroma_base_url, pleroma_token):
            if root_marker in html.unescape(item.get("content", "")):
                return item.get("id")
        return None

    wait_until(
        lambda: pleroma_root_id() is not None,
        desc="pleroma received root post from feddyspice",
        timeout_s=240,
        interval_s=2.0,
    )
    pleroma_root_id_val = pleroma_root_id()
    assert pleroma_root_id_val

    reply_marker = f"[fedbox] reply {time.time()}"
    pleroma_post_reply(pleroma_base_url, pleroma_token, pleroma_root_id_val, reply_marker)

    wait_until(
        lambda: any(
            reply_marker in html.unescape(item.get("content", ""))
            for item in feddyspice_home_timeline(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received reply Create",
        timeout_s=240,
        interval_s=2.0,
    )

    wait_until(
        lambda: any(
            reply_marker
            in html.unescape(item.get("content", ""))
            for item in feddyspice_get_context(feddy_base_url, feddy_token, feddy_root_id).get(
                "descendants", []
            )
            if isinstance(item, dict)
        ),
        desc="reply is present in feddyspice context descendants",
        timeout_s=240,
        interval_s=2.0,
    )


def test_pleroma_delete_is_applied_in_feddyspice_timeline():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)
    pleroma_token = create_pleroma_password_token(pleroma_base_url, pleroma_user, c.password, scopes)

    feddyspice_follow(feddy_base_url, feddy_token, c.pleroma_handle)

    marker = f"[fedbox] delete {time.time()}"
    pleroma_post(pleroma_base_url, pleroma_token, marker)

    def pleroma_status_id() -> str | None:
        for item in pleroma_home_timeline(pleroma_base_url, pleroma_token):
            if marker in html.unescape(item.get("content", "")):
                return item.get("id")
        return None

    wait_until(lambda: pleroma_status_id() is not None, desc="pleroma created status", timeout_s=60)
    pleroma_status_id_val = pleroma_status_id()
    assert pleroma_status_id_val

    wait_until(
        lambda: any(
            marker in html.unescape(item.get("content", ""))
            for item in feddyspice_home_timeline(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received remote post from pleroma",
        timeout_s=240,
        interval_s=2.0,
    )

    pleroma_delete_status(pleroma_base_url, pleroma_token, pleroma_status_id_val)

    wait_until(
        lambda: not any(
            marker in html.unescape(item.get("content", ""))
            for item in feddyspice_home_timeline(feddy_base_url, feddy_token)
        ),
        desc="feddyspice applied Delete",
        timeout_s=240,
        interval_s=2.0,
    )
