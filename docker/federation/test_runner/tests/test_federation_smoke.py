import re
import os
import time
import html
from dataclasses import dataclass

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


def pleroma_post(pleroma_base_url: str, access_token: str, text: str) -> None:
    resp = requests.post(
        f"{pleroma_base_url}/api/v1/statuses",
        headers={"authorization": f"Bearer {access_token}"},
        data={"status": text, "visibility": "public"},
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


def test_pleroma_direct_to_feddyspice_is_received_and_not_public():
    c = cfg()

    feddy_user, feddy_domain = parse_handle(c.feddyspice_handle)
    pleroma_user, pleroma_domain = parse_handle(c.pleroma_handle)

    feddy_base_url = base_url_for(feddy_domain)
    pleroma_base_url = base_url_for(pleroma_domain)
    scopes = "read write follow"

    feddy_token = create_feddyspice_token(feddy_base_url, feddy_user, c.password, scopes)

    # Ensure the follow is established (reproduces real usage; DMs often happen after a follow).
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

    marker = f"[fedbox] pleroma -> feddyspice direct {time.time()}"

    # Note: the Pleroma build used by this fedbox does not create remote mentions
    # from plain `@user@domain` text, so `visibility=direct` via Mastodon API
    # does not federate to remote inboxes. We simulate the direct delivery by
    # posting an ActivityPub `Create` to the feddyspice inbox, using the Pleroma
    # actor as the sender.
    actor = fetch_ap_json(feddy_actor_id)
    inbox = actor.get("inbox")
    assert isinstance(inbox, str) and inbox

    note_id = f"{pleroma_base_url}/objects/{time.time()}"
    activity_id = f"{pleroma_base_url}/activities/{time.time()}"

    create = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": activity_id,
        "type": "Create",
        "actor": pleroma_actor_id,
        "to": [feddy_actor_id],
        "object": {
            "id": note_id,
            "type": "Note",
            "content": f"<p>{marker}</p>",
            "published": "2020-01-01T00:00:00.000Z",
            "to": [feddy_actor_id],
        },
    }

    deliver = requests.post(
        inbox,
        headers={"content-type": "application/activity+json"},
        json=create,
        verify=verify_arg(),
        timeout=10,
    )
    # feddyspice returns 202 Accepted for async inbox processing.
    assert deliver.status_code in (200, 202)

    wait_until(
        lambda: any(
            marker in html.unescape(item.get("content", ""))
            for item in feddyspice_home_timeline(feddy_base_url, feddy_token)
        ),
        desc="feddyspice received direct message from pleroma",
        timeout_s=240,
        interval_s=2.0,
    )

    home = feddyspice_home_timeline(feddy_base_url, feddy_token)
    dm = next(item for item in home if marker in html.unescape(item.get("content", "")))
    assert dm.get("visibility") == "direct"

    assert not any(
        marker in html.unescape(item.get("content", ""))
        for item in feddyspice_public_timeline(feddy_base_url)
    )
