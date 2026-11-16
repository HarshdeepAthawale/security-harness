# crAPI: the practice target

[OWASP crAPI](https://github.com/OWASP/crAPI) is a deliberately vulnerable API.
It is the first real target for the harness: it has known access-control bugs
(BOLA/IDOR), and it runs on your own machine, so nothing here touches anyone
else's system.

**It is vulnerable on purpose. It listens on `127.0.0.1` only. Don't change
that, and don't expose it to a network.**

## Start it

Needs Docker Desktop running. From the repo root:

```bash
git clone --depth 1 https://github.com/OWASP/crAPI crapi/upstream     # once; crapi/upstream/ is gitignored
```

```bash
cd crapi/upstream/deploy/docker
TLS_ENABLED=false docker compose -p crapi -f docker-compose.yml -f ../../../compose.override.yml up -d crapi-identity crapi-community crapi-workshop crapi-web mailhog postgresdb mongodb api.mypremiumdealership.com
```

- Only the services the harness needs are started. The AI chatbot and its
  vector database are skipped (they need an LLM key, and the vector database
  clashes with the workshop on port 8000).
- `crapi/compose.override.yml` is needed because of that: crAPI's nginx won't
  start unless the host `crapi-chatbot` resolves, so the override gives it a
  placeholder. Without it `crapi-web` exits straight away with "host not found
  in upstream".
- The first start downloads about 1.5 GB of images; later starts take a minute.
- Plain HTTP on purpose: the harness's broker rejects self-signed TLS
  certificates, and a local practice target doesn't need them.
- `ENABLE_SHELL_INJECTION` and `ENABLE_LOG4J` stay `false`.

The web UI is at <http://127.0.0.1:8888>. Stop it with
`docker compose -p crapi down` (add `-v` to wipe its data).

## Create the test accounts

```bash
python crapi/seed.py
```

Creates two disposable accounts (`user_A`, `user_B`) with generated passwords,
and one order each. Passwords go to `crapi/.env.local` and the order ids to
`crapi/state.json`; both are gitignored. It refuses to run against anything
that isn't this machine.

## Run the harness

```bash
python crapi/run_harness.py
```

- Scope: **GET only**, on `/workshop/api/shop/orders/<id>` only.
- Logs in twice per user. The second login is the "fresh" credential the judge
  replays with. Tokens reach the broker through the environment and are never
  printed or stored.
- The judge only confirms a bug when the signed contract says the access is
  forbidden (here: "an order is private to the user who placed it"), both
  users' own orders still work as a control, and the proof replays with the
  fresh credentials.
- Output: the report, and `crapi/run.db` (every request, evidence and thread).
  `--llm` also asks the configured model (`LLM_PROVIDER=ollama|openrouter`) for
  hypotheses; without it, no model is used.

## Endpoint discovery and coverage

`run_harness.py` no longer needs the endpoints typed in. It reads crAPI's own
OpenAPI spec (`crapi/upstream/openapi-spec/crapi-openapi-spec.json`, 44
operations) with `brains/openapi.py` and prints, for every operation, whether
it was tested and why not:

```
Coverage: 44 operations discovered, 1 tested
  tested 1 | needs_object_ids 3 | id_in_query 2 | not_read_only 20 | public 9 | no_object_id 9
```

Discovery only says what exists. What is *sent* is still decided by the signed
contract (GET on `/workshop/api/shop/orders/*`) and by which object ids the run
has, so reading the spec widens nothing: the run still sends the same 12
requests to the same 2 paths. Write methods (POST/PUT/PATCH/DELETE) are never
attacked unless `IdorBrains(..., allow_write=True)`.

Not covered yet, and shown as such in every report: endpoints that need an
object id nobody supplied (videos, vehicle location, community posts) and
endpoints whose id is a query parameter (`mechanic_report?report_id=`). Options:
`--spec PATH` for another spec, `--no-discovery` for the single hand-listed
endpoint.

## Result of the first real run

On a fresh crAPI the harness reported **2 confirmed findings**: user B can read
user A's order (6) and A can read B's (7). Both were checked: the other user
received the same response body as the owner, each user's own-order control
differed from the other's, and the proof replayed with fresh logins. No
password or token is stored in `run.db`.

Not yet covered: confirmed findings carry no severity (the judge doesn't set
one), only this one endpoint is tested, and object ids come from `seed.py`
rather than being discovered (the endpoints themselves are, see above).

## The bug it is looking for

crAPI challenge 3: *"Access details of another user's order"*. `GET
/workshop/api/shop/orders/{order_id}` returns any user's order to any logged-in
user. That is BOLA, OWASP API1.
