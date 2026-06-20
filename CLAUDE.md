# Anti-Venom — CLAUDE.md

## Git Commit & Versioning Rules (MANDATORY)

### Commit message format
Every commit MUST follow this format:
```
[v0.1] short description (imperative, ≤72 chars)

Optional body explaining why (not what).
```

### Version tracking
- Each file-level change gets tagged with the version it belongs to: `[v0.1]`, `[v0.2]`, `[v0.3]`
- When starting a new version sprint (e.g., v0.2), first commit bumps `__version__` in `antivenom/__init__.py` and `pyproject.toml`:
  ```
  [v0.2] bump version to 0.2.0
  ```
- When a version is COMPLETE (all features for that version done and tests pass), tag it:
  ```bash
  git tag -a v0.1.0 -m "Anti-Venom v0.1.0 — Pattern, Structural, Canary layers"
  git push origin v0.1.0
  ```

### What to commit together
- One logical change per commit (feature, fix, or test) — don't batch unrelated changes
- Always include test file in the same commit as the feature it tests
- Never commit: `.env`, `*.db`, `*.jsonl` (audit logs), `tests/benchmarks/datasets/`, `.venv/`

### Commit examples
```
[v0.1] add PatternLayer with 22 injection regex patterns
[v0.1] fix canary layer missing extract+passwords pattern
[v0.1] add LangChain AntiVenomDocumentTransformer with filter/raise/tag modes
[v0.2] add SemanticLayer with sentence-transformers cosine similarity
[v0.2] add CrossChunkLayer for split-payload boundary detection
[v0.3] add DistilBERT ClassifierLayer (74% → 91% recall)
```

---

## What This Project Is
A pre-embedding RAG corpus poisoning detector. It scans document chunks for adversarial prompt injections BEFORE they are stored in a vector database. Installable as `pip install antivenom`.

## Package Name
- PyPI / import: `antivenom` (no hyphen)
- CLI entry point: `antivenom`
- Repo name stays Anti-Venom (GitHub)

## Tech Stack
- Python >= 3.10
- Package manager: **uv** (never pip/poetry directly)
- Formatting/linting: **ruff**
- Type checking: **mypy**
- Testing: **pytest** + **pytest-asyncio**
- CLI: **typer[all]** + **rich**
- Config/validation: **pydantic v2**

## Key Commands
```bash
uv venv                                  # create .venv (first time)
uv pip install -e ".[langchain,dev]"     # install editable with extras
uv pip install ruff mypy pytest pytest-asyncio pytest-cov
ruff check antivenom/                    # lint
mypy antivenom/ --ignore-missing-imports # type check
pytest tests/unit/ tests/integration/   # run tests
python -m antivenom.benchmark            # run detection benchmark
antivenom scan <file>                    # CLI smoke test
```

## Architecture Rules
1. **Execution order lives in `pipeline.py`** — layers have no numbers in their names or files. Order is defined by `FAST_LAYERS`, `MEDIUM_LAYERS`, `SLOW_LAYERS` lists.
2. **Short-circuit**: any layer with confidence >= 0.95 → stop pipeline, return MALICIOUS immediately.
3. **FAST_LAYERS run in parallel** via `asyncio.gather()`. MEDIUM_LAYERS also parallel. SLOW_LAYERS sequential.
4. **No spaCy in core** — structural layer uses pure Python IMPERATIVE_VERBS density. spaCy only when `[structural-nlp]` extra is installed (detected via `importlib.util.find_spec`).
5. **No aiofiles in v0.1** — audit log uses sync SQLite writes. Add aiofiles in v0.2.
6. **`on_detection="tag"` is MONITORING ONLY** — always emit `UserWarning` when this mode is used without `monitoring_mode=True`.

## Versioning / Scope
- **v0.1** (current): Pattern + Structural + Canary layers, LangChain integration, CLI scan/audit, SQLite quarantine, benchmark harness, CI
- **v0.2**: Semantic layer, CrossChunk layer, cache, LlamaIndex, webhook proxy, YAML rules
- **v0.3**: DistilBERT classifier, Haystack, LLM Judge, published model

## Extras Map
```
[semantic]        sentence-transformers
[structural-nlp]  spacy
[classifier]      transformers, torch
[serve]           fastapi, uvicorn
[langchain]       langchain-core
[llamaindex]      llama-index-core
[haystack]        haystack-ai
[redis]           redis
[dev]             pytest, pytest-asyncio, pytest-cov, ruff, mypy, datasets, faker
[all]             everything above
```

## Directory Layout (v0.1 scope)
```
antivenom/
  core/          scanner, pipeline, result, chunk, config, exceptions
  layers/        base, pattern, structural, canary  (+ semantic/cross_chunk/classifier/llm_judge later)
  rules/         registry, base_rule, builtin/
  audit/         quarantine, audit_log, events
  integrations/
    langchain/   transformer (v0.1)
  cli/
    main.py
    commands/    scan.py, audit.py
  py.typed

scripts/
  build_benchmark_dataset.py   (run once → outputs test JSONL files)

tests/
  unit/
  integration/
  benchmarks/
    run_benchmark.py
    datasets/    known_attacks.jsonl, benign_docs.jsonl

.github/workflows/ci.yml
```

## Detection Layer Reference
| Layer | File | Stage | Ships |
|---|---|---|---|
| Pattern | `layers/pattern.py` | FAST | v0.1 |
| Structural | `layers/structural.py` | FAST | v0.1 |
| Canary | `layers/canary.py` | FAST | v0.1 |
| Semantic | `layers/semantic.py` | MEDIUM | v0.2 |
| CrossChunk | `layers/cross_chunk.py` | MEDIUM | v0.2 |
| Classifier | `layers/classifier.py` | SLOW | v0.3 |
| LLMJudge | `layers/llm_judge.py` | SLOW | v0.3 |

## Benchmark Targets
- Recall >= 90% (enforced by CI: `--fail-below-recall 0.90`)
- Median latency < 10ms for FAST_LAYERS combined
- False positive rate < 5% on benign corpus

## MCP Tools
None required for v0.1. When v0.2 webhook proxy is built, a Chroma/Qdrant MCP server helps for integration testing (optional).
