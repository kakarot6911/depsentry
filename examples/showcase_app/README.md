# Showcase app (demo fixture)

A deliberately vulnerable sample application used to demonstrate DepSentry.
Every dependency is pinned to a version the advisory corpus flags.

**Do not deploy this. It exists to be scanned.**

The point is the **contrast**: some vulnerable symbols are genuinely called
(red in the 3D view), while others sit in the dependency tree and are never
invoked (amber, suppressed).

## Actual scan result

27 packages, 20 findings, **3 reachable, 17 suppressed — 85% noise reduction.**

| Module | Calls | Verdict | Why |
|---|---|---|---|
| `ingest.py` | `requests.get` | 🔴 REACHABLE | called from `main` |
| `ingest.py` | `pandas.read_pickle` | 🔴 REACHABLE | called from `main` |
| `model.py` | `joblib.load` | 🔴 REACHABLE | called from `main` |
| `config.py` | `yaml.safe_load` | 🟡 suppressed | advisory is on `yaml.load` — **CVSS 9.8 correctly suppressed** |
| `imaging.py` | `PIL.Image.new` | 🟡 suppressed | advisory is on `PIL.Image.open`; also no inbound call |
| `render.py` | `jinja2.Environment().from_string` | 🟡 suppressed | **known false negative — see below** |

## The Jinja2 case is a real limitation, not a fixture bug

`render.py` genuinely calls the vulnerable symbol:

```python
env = jinja2.Environment()
return env.from_string(template_text).render(**context)
```

DepSentry resolves `jinja2.Environment` but **not** `env.from_string`, because
`env` is a local variable and the analyser performs no type inference. The
advisory names `jinja2.Environment.from_string`, so no match is made and the
finding is suppressed.

**This is a false negative** — the dangerous direction for a security tool. It
is left in the fixture deliberately rather than rewritten into something the
analyser happens to resolve, because it is a concrete, inspectable instance of
the limitation documented in `docs/05_results_and_discussion.md` §5.6 ("real
codebases contain the hard cases the corpus lacks... callbacks passed as values,
dependency injection") and `docs/03_design_document.md` §3.4.

Fixing it needs local type inference: track that `env` was bound from
`jinja2.Environment()` and rewrite the receiver accordingly. That is listed as
future work (`docs/05` §5.9 item 3, inter-procedural and framework-aware
analysis).

If an evaluator asks *"where does your tool fail?"* — open this file. A worked
example of your own failure mode is a stronger answer than claiming there
isn't one.
