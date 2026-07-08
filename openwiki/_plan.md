# OpenWiki Documentation Plan

## Intended Wiki Pages

1. **openwiki/quickstart.md**
   - Purpose: Entry point with repository overview, key features, directory structure, and quick start instructions.
   - Source evidence: README.md (features, installation, usage), main.py (server start), docker files.

2. **openwiki/architecture/overview.md**
   - Purpose: High-level architecture diagram and explanation of Resolver, Rule system, QueryContext, and utility modules.
   - Source evidence: main.py (Resolver class, Rule list), utils/*.py (module responsibilities).

3. **openwiki/features/feature-overview.md**
   - Purpose: Summary of core DNS service features (CIDR calculations, Time services, IP services, Base64 utilities) and their use cases.
   - Source evidence: README.md (Feature sections), main.py (list of supported domains and handlers).

4. **openwiki/usage/usage.md**
   - Purpose: How to run the server, basic query examples, and explanation of DNS query naming conventions.
   - Source evidence: README.md (Usage section), main.py (resolve method and documentation).

5. **openwiki/deployment/deployment.md**
   - Purpose: Docker deployment instructions, configuration, and startup message details.
   - Source evidence: Dockerfile, docker-compose.yml, README.md (Docker instructions).

6. **openwiki/testing/testing.md**
   - Purpose: Overview of test suite, testing goals, and where tests are located.
   - Source evidence: tests/test_resolver.py, pyproject.toml/uv.lock (test configurations).

## Remaining Questions

- Exact naming of section directories (e.g., features vs utilities).
- Determining granularity of separate pages for each utility (CIDR, Time, IP, Base64) vs combined.
- Verification of latest commit changes affecting documentation.