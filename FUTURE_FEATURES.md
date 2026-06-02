# Future Features

## Read / Export Mode

Query the APIC for an existing tenant and generate a build file from it.

Useful for:
- Documenting existing configs
- Migrating tenants between fabrics
- Bootstrapping a build file from a brownfield deployment

Implementation notes:
- New `--export` flag with `--tenant` and `--url` args
- Use Cobra `lookupByClass` / DN queries to walk the tenant MO tree
- Reverse-map Cobra objects to the semicolon-delimited build file format
- Should produce output parseable by the builder with no modifications

## Idempotency / Diff Mode

Before committing, compare the planned MO tree against the current APIC state and report what would change.

New flags:
- `--diff` — show a before/after summary, do not commit
- `--overwrite` — explicit opt-in to overwrite existing objects (default: skip unchanged)

Implementation notes:
- Query existing DNs from the APIC after login, before building the MO tree
- Diff at the attribute level where possible
- Objects unchanged on the APIC should be excluded from the commit payload
- Particularly important for large deployments where partial re-runs are common
