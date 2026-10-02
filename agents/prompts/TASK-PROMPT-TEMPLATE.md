# Agent Task Prompt Template

ROLE: <role>
ISSUE: <ID>

OBJECTIVE:
<single bounded outcome>

READ FIRST:
- <files>

ALLOWED DIRECTORIES:
- <paths>

DO NOT MODIFY:
- <paths>

CONTRACTS:
- <schemas/openapi>

ACCEPTANCE CRITERIA:
1.
2.

SECURITY REQUIREMENTS:
- ...

TESTS TO RUN:
- ...

DELIVER:
- code/docs/tests;
- exact files changed;
- test results;
- security findings/limitations;
- rollback/migration notes.

Do not merge or deploy.
