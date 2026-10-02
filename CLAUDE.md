# CLAUDE.md

Read `AGENTS.md` first. It is authoritative for agent behaviour.

For any non-trivial task:
1. identify the relevant PRD section;
2. identify architecture/security constraints;
3. define acceptance criteria;
4. implement the smallest correct vertical change;
5. run tests/security checks;
6. request review.

Never make production network changes. Do not store credentials in prompts or code.
