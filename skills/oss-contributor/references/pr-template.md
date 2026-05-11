# PR Description Template

Use this as a starting point. Always adapt to the project's existing PR style.

---

## What

[One-line summary of the change]

## Why

[Problem statement. Link the issue: `Fixes #N` or `Closes #N`]

## How

[Technical approach in 2–3 sentences. What changed and why this approach was chosen.]

## Testing

```bash
# Exact commands to verify the fix
go test ./... -run TestFunctionName
pytest tests/test_module.py -v
cargo test --test integration
```

## Breaking Changes

None. / [Describe if any API or behavior changes.]

## Security Impact

None. / [Describe if this change has security implications — e.g., fixes a path traversal, hardens input validation.]

---

## Checklist (adapt to project)

- [ ] Tests added/updated
- [ ] Linter passes (`make lint` / `cargo clippy` / `ruff check`)
- [ ] CHANGELOG updated (if required)
- [ ] DCO signed (`git commit -s`) / CLA signed
