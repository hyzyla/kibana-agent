---
name: kibana-agent
description: Query Elasticsearch and Kibana via the Kibana console proxy API. Use this skill whenever the user asks to search logs, query Elasticsearch indices, list indices, view dashboards, check Kibana status, or investigate production issues in the Elastic stack. Also use when the user mentions Kibana, Elasticsearch, ES, logs, indices, or dashboards.
---

# Kibana / Elasticsearch Access

Use the `kibana-agent` CLI for all Elasticsearch queries. **Never use raw curl commands** — the CLI handles auth, caching, read-only guards, and output formatting.

## ALWAYS: Record facts you had to work out

The cluster cannot tell you which index serves which application, or which field carries a value
whose name is not obvious. You work that out once, by trial and error. Write it down so the next
session does not repeat the work.

**Write a note the moment you confirm:**

- which index pattern holds a given application's logs;
- which field carries a value whose name you had to hunt for (a status code, a user id, a request
  path);
- a cluster behaviour that no mapping shows, such as a rejected timezone name.

**The strongest signal is a corrected guess.** When the CLI warns `field '<x>' is not in the
mapping` and your next query finds the right field, you have just learned a fact. Record it then —
that exact moment is the one that repeats across sessions.

Write notes **silently**, as background bookkeeping. Do not ask permission and do not interrupt the
user's task. The notes live in a local config file and any of them can be removed later.

```bash
kibana-agent profile note <profile> app-logs="<pattern>" status-field="<field>"
```

Set several in one call. To read them, never ask for keys one at a time — `context` prints every
note at the top of its output, and `profile note <profile>` dumps them all.

Do **not** note a copy of the mapping (it goes stale and then lies — point at fields by role
instead), the findings of an investigation (that is session output, not configuration), or anything
secret (the config file is plain text).

## CRITICAL: Read-Only Access

The CLI enforces read-only access automatically. All write operations are blocked.

## Usage

For the full reference, run:

```bash
kibana-agent agent-help
```

## Typical Workflow

1. **Get context first** — read the notes, then learn what indices and fields exist:
   ```bash
   kibana-agent context
   ```

   `context` is the orientation call. It returns, in order:

   - `notes` — what the cluster cannot tell you. **Trust a note over a guess.**
   - `scope` — the profile, space, default index, and any restriction in force.
   - `cluster` — the ES version, which decides what query syntax the cluster accepts.
   - `indices` — per pattern: field count, how many are aggregatable, the detected
     `time_field`, total docs, `first`/`last` document time, and docs in the last hour.
   - `mappings` — field types per pattern. A narrow index is listed in full. A wide one is
     summarised by namespace instead:

     ```json
     "logs.message": "text +keyword",
     "logs.exception.*": "6 fields",
     "logs.ctx.*": "1307 fields",
     "…": "1439 fields in total — run: fields <pattern> '<glob>'"
     ```

     A key ending in `.*` is a **namespace, not a field** — never put it in a query. It tells you
     where to look: `fields <pattern> 'logs.ctx.*user*'` lists what is inside. `text +keyword`
     means the field is analyzed **and** has a `.keyword` sibling, so `match_phrase` works on the
     name as written and `term` works on `<name>.keyword`.

   `indices` and `mappings` cover five patterns, not all of them. **The patterns named in your
   notes come first**, so a note like `edo-logs="k8s-edo-*"` puts that mapping in the first call.
   Without notes you get the first five patterns alphabetically, which is a sample, not a choice —
   so on an unfamiliar cluster write the note as soon as you find the right index, and the next
   `context` will describe it. `context --indices '<a>,<b>'` asks for specific ones.

   Read `first`/`last` before you trust a zero: an index whose last document is days old will
   return nothing for `--last 1h` no matter how good the query is. Read `time_field` too — not
   every index uses `@timestamp`, and `--time-field` overrides it.

2. **Sample recent docs**:
   ```bash
   kibana-agent search <index-pattern> --last 1h -n 3
   ```

3. **Refine** — add query filters, field selection, aggregations:
   ```bash
   kibana-agent search <index-pattern> --last 1h -n 20 \
     -q '{"match":{"level":"ERROR"}}' \
     -f "@timestamp,level,message"
   ```

   `-f` takes dotted paths for nested fields and returns each one as a flat key, so
   `-f "@timestamp,a.b.c"` gives `{"@timestamp":"...","a.b.c":"..."}`. A path that the document
   does not contain is left out. Without `-f` you get the whole document, truncated at
   `--max-source-len` characters (default 1000) — raise it when a long document gets cut.

   `--sort <field>:<order>` changes the order — `--sort @timestamp:asc` gives the oldest documents
   first. The order must be `asc` or `desc`, and both parts are required: a bare `--sort asc` is
   an error, not a sort on the time field.

   Applications often log a whole JSON document into one string field. A traceback inside such a
   field arrives escaped several layers deep and is unreadable. `--expand-json` parses those
   strings back into objects and splits multi-line strings into a list of lines:

   ```bash
   kibana-agent search <index-pattern> --last 1h -n 1 -q '<query>' \
     --expand-json --format pretty --max-source-len 6000
   ```

   Use it whenever you need to read an exception. Without it, do not try to unescape the output by
   hand.

4. **Spot trends**:
   ```bash
   kibana-agent histogram <index-pattern> --last 6h --interval 10m
   ```

5. **Count issues**:
   ```bash
   kibana-agent count <index-pattern> --last 1h -q '{"match":{"level":"ERROR"}}'
   ```

6. **Stream live logs**:
   ```bash
   kibana-agent tail <index-pattern> -f "@timestamp,level,message"
   ```

## Never Trust a Zero

An empty result is more often a wrong query than an absence of data. This is the main way this
tool produces a wrong answer: you report "no errors found" when the query never had a chance to
match.

**The CLI diagnoses this for you. Read stderr.** `search`, `count`, and `histogram` check the
request against the mapping before sending it, then explain any empty result afterwards:

```
Warning: field 'http.response_status_int' is not in the mapping — this query cannot match.
         Did you mean: http.response_code?
Warning: 'term' on analyzed text field 'level' matches nothing — use 'level.keyword'
Warning: time field 'created_at' is not in the mapping — this index uses '@timestamp'
Warning: sort field 'timestamp' is not in the mapping. Did you mean: @timestamp?
Warning: index pattern 'ghost-*' matches no index, so every query returns 0.
Note: 0 hits, but the last 1h holds 8,412 documents. The filter is the problem, not the window.
Note: 0 hits, and the last 1h is empty. The pattern holds 91,234 documents overall — widen --last.
```

A warning or note means **the zero is not an answer**. Fix what it names and run again.
`--no-hints` turns the checks off.

The checks cannot catch everything, so before you report a zero that came with no note, confirm:

1. **Right index pattern?** Run `kibana-agent aliases`. Different applications often write to
   different patterns.
2. **Right field name?** Run `kibana-agent fields <index-pattern> '<glob>'`. Never guess a field
   name — a guessed name always returns 0.
3. **Right query type for the field type?** See the next section.

Treat any `security_exception`, non-zero exit, or error on stderr as a **hard failure**. Never
report it as "no matching documents". The CLI exits non-zero on an auth error, an ES error, and an
unreachable host, so a zero that comes with a clean exit is a real zero — as long as no warning
was printed.

A partial result also prints a warning: `N of M shards failed, so the result is incomplete:
<reason>`. Do not report its counts as totals. The reason names the broken part of the request —
`No mapping found for [level] in order to sort on` means the sort field does not exist in that
index. No zero-note follows such a warning, because the request failed, not the filter.

## Never Trust a `total` of 10000 Either

Elasticsearch stops counting matches at 10,000. When it does, `search` and `histogram` return
`"total_is_lower_bound": true` and warn on stderr. The value means "at least 10,000", so a
`total` of exactly 10000 is almost never the real number.

```
Warning: total=10000 is a floor, not the real count: Elasticsearch stops counting at 10,000.
#{"total":10000,"n":3,"total_is_lower_bound":true}
```

Reporting that as "10,000 errors" is a wrong answer, not a visible failure. For an exact number:

- `kibana-agent count <index-pattern>` — uses the `_count` API, which always counts everything;
- or sum the `histogram` buckets — aggregation counts are exact at any size.

`context` marks the same case per pattern with `"docs_is_lower_bound": true`.

## Match the Query to the Field Type

Run `kibana-agent mapping <index-pattern>` or `fields` first. The field type decides the query:

- **`text` fields are analyzed.** `term` and `terms` compare against whole untouched values, so
  they return **0** on a text field. Use `match_phrase` (or `match`) instead.
- **`keyword`, numeric, boolean, and date fields** work with `term`, `terms`, and `range`.
- **Punctuation breaks phrases.** The analyzer drops characters like `:`, `/`, and `=`. If a
  `match_phrase` that contains punctuation returns 0, retry with a shorter fragment that has none.
- **A `.keyword` subfield is not guaranteed.** Some indices define one next to a text field, some
  do not. `mapping` and `fields` list the subfields that exist, so check there instead of guessing.

## Aggregations

A `terms` aggregation needs a field with doc values. On an analyzed `text` field it fails, and the
failure is easy to miss:

- Some clusters raise `Fielddata is disabled`.
- Others return `{"total":0,"n":0}` and **silently drop the sibling aggregations too**.

So if an aggregation comes back empty, suspect the field type before you suspect the data.
Aggregate on `keyword`, numeric, boolean, or date fields. When only a text field exists, either
pull documents with `-f` and group them yourself, or run repeated `count` calls with
`match_phrase`.

An aggregation on a correct `keyword` field can still return no buckets while `total` is not zero.
That means the matching documents do not carry the field at all. The CLI checks for this and
warns:

```
Warning: aggregation 'lvl' is empty: none of the 3,667 matching documents has 'level.keyword'.
```

The common cause is `must_not`: a clause such as `must_not term level.keyword=info` also matches
every document that has no `level` field, such as an unparsed startup banner. Read those documents
with `-f` before you conclude anything from the empty buckets, or add
`{"exists":{"field":"level.keyword"}}` to `-q` to keep only documents that have the field.

In `date_histogram`, prefer a numeric UTC offset (`"+02:00"`) over an IANA name. Older clusters
carry an older timezone database and reject newer zone names.

## Time Windows

`search` has **no `--from` / `--to`**. Use `--last <N><unit>` for a relative window.

The window applies to `@timestamp` by default. Not every index uses that name — `context` reports
the real one per pattern as `time_field`, and `--time-field <name>` overrides it. On an index with
a different date field, `count` and `histogram` return 0 and empty buckets with no error, so check
`time_field` before trusting either.

`--last` is always applied **and** combined with `-q` by AND. For an absolute window, put a range
filter in `-q` and widen `--last` so it covers that window:

```bash
kibana-agent search <index-pattern> --last 7d \
  -q '{"range":{"@timestamp":{"gte":"2026-08-07T09:00:00Z","lte":"2026-08-07T09:30:00Z"}}}'
```

## Remembering Facts

The cache holds what the cluster can tell you: which indices exist, which fields they have, how
many documents. It expires and `cache-clear` throws it away, which is safe — one API call rebuilds
it.

Notes hold what the cluster **cannot** tell you. `aliases` lists forty patterns and never says
which one holds the logs you want. Store that:

```bash
kibana-agent profile note <profile>                              # dump every note
kibana-agent profile note <profile> app-logs="<pattern>"         # set one
kibana-agent profile note <profile> a="<x>" b="<y>"              # set many in one call
kibana-agent profile note <profile> --delete app-logs            # remove one
```

Notes live in the config file, not the cache, so `cache-clear` never removes them. They appear at
the top of `context`.

Reading always returns every note at once. There is no way to read a single key, by design — one
call gives you the whole set.

See "ALWAYS: Record facts you had to work out" above for when to write one.

## Working With More Than One Profile

Do not carry index patterns, field names, or timezone strings from one cluster to another — they
differ. Re-run `aliases`, `fields`, and `mapping` for each profile.

Caches are keyed per profile, so `--profile X` never returns data or credentials belonging to
profile Y. If credentials look stale, run `cache-clear --creds-only` and retry — that
re-authenticates without discarding the cached mappings, which can be several MB per cluster.

## Other Commands

- `aliases` — list index aliases
- `mapping <index-pattern>` — flat field:type mapping
- `fields <index-pattern> [glob]` — field names matching glob
- `discover <index-pattern>` — generate Kibana Discover URL (--kql, --lucene)
- `raw GET|POST <es-path> [--body <json>]` — arbitrary read-only ES request. Prints the whole
  response body; add `--format pretty` when you need it indented.
- `profile note <profile> [<key>] [<value>]` — store or list facts the cluster cannot tell you.
  `--delete` removes one. See "Remembering Facts" below.
- `cache-clear` — wipe cached data and credentials for the active profile. `--profile <name>`
  targets another, `--all` covers every profile, `--creds-only` re-authenticates but keeps the
  cached mappings, `--data-only` does the opposite.
- `cred-cache-ttl [<seconds>]` — show or set the 1Password/keychain credential cache TTL
  (default 24h). `0` disables; `unset` removes the override. Env override:
  `KIBANA_AGENT_CRED_CACHE_TTL`.

## Profile Space & Index Scoping

Profiles can optionally pin a **Kibana Space** and/or a **default index pattern**:

```bash
kibana-agent profile create prd --url https://kibana.example.com \
  --auth 1password \
  --op-username "op://vault/item/username" \
  --op-password "op://vault/item/password" \
  --space backend --index logs-* --restrict-index --use
```

- `--space <id>` — route all API calls through `/s/<space>/...`
- `--index <pattern>` — default index when omitted from commands (e.g. `kibana-agent count --last 1h`)
- `--restrict-space` / `--restrict-index` — reject commands that try to use a different space/index

Update with `profile update <name> --space X` / `--no-space` / `--restrict-index` / `--no-restrict-index`.

## Shared Options

These are **per-command** options, not group options. Put them **after** the subcommand:

```bash
kibana-agent context --profile prd     # correct
kibana-agent --profile prd context     # fails: "No such option: --profile"
```

```
--profile <name>   Override active profile (env: KIBANA_AGENT_PROFILE)
--timeout <sec>    Request timeout (default: 30)
--dry-run          Print curl command instead of executing
--explain          Print the query body to stderr
--filter-path      ES filter_path parameter
--format compact|pretty   Output format (default: compact)
--no-cache         Bypass cache
```
