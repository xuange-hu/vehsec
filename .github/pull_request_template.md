## What / 改了什么

<!-- One paragraph. Link the issue if there is one: Closes #123 -->

## Surfaces touched / 涉及入口

- [ ] Core library
- [ ] CLI
- [ ] TUI
- [ ] MCP server (new/changed tools?)
- [ ] Lab(s)
- [ ] Docs only

## Checklist / 提交前检查

- [ ] `pytest -q` passes (220 tests, including all 5 labs and the demo script)
- [ ] `ruff check src tests --select=E9,F63,F7,F82` passes
- [ ] New capability is exposed on **all three** surfaces (core + CLI + MCP)
- [ ] New MCP tool has a docstring (agents read it to decide when to call)
- [ ] Optional third-party imports are guarded (`try/except ImportError`)
- [ ] Docs updated (README / playbook / ROADMAP as appropriate)
- [ ] Contribution is for authorized research / education / owned equipment

## How to verify / 怎么验证

```bash
# commands a reviewer can run
```
