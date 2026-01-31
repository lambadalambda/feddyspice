import os
import time
from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class FedboxConfig:
    scheme: str
    pleroma_handle: str
    mastodon_handle: str
    password: str
    cacertfile: str


def cfg() -> FedboxConfig:
    return FedboxConfig(
        scheme=os.getenv("FEDTEST_SCHEME", "https"),
        pleroma_handle=os.getenv("FEDTEST_PLEROMA_HANDLE", "@bob@pleroma.test"),
        mastodon_handle=os.getenv("FEDTEST_MASTODON_HANDLE", "@carol@mastodon.test"),
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

    # Mastodon v4.5+ no longer exposes POST /api/v1/follows; keep the fallback
    # here for future re-use when fedbox grows to include more servers.
    if resp.status_code in (404, 405):
        acct = handle.lstrip("@")
        lookup = requests.get(
            f"{pleroma_base_url}/api/v1/accounts/lookup",
            headers={"authorization": f"Bearer {access_token}"},
            params={"acct": acct},
            verify=verify_arg(),
            timeout=10,
        )
        lookup.raise_for_status()
        account_id = lookup.json()["id"]

        follow = requests.post(
            f"{pleroma_base_url}/api/v1/accounts/{account_id}/follow",
            headers={"authorization": f"Bearer {access_token}"},
            verify=verify_arg(),
            timeout=10,
        )
        follow.raise_for_status()
        return

    resp.raise_for_status()


def test_webfinger_is_ready_for_seeded_accounts():
    c = cfg()

    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)
    mastodon_user, mastodon_domain = parse_handle(c.mastodon_handle)

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

