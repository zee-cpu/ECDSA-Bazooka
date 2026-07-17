# Documentation Refresh Design

**Date:** 2026-07-18

## Goal

Make the project documentation clean, easy to scan, and easier for a new user
to follow without losing the existing technical coverage.

## Document responsibilities

### `README.md`

The README is the project landing page. It will explain what the project does,
summarize its supported input patterns and practical limits, and provide one
short build-and-run path. Detailed command variants will link to `COMMANDS.md`
instead of being repeated.

Planned sections:

1. Project purpose and CI status
2. Key capabilities
3. Quick start
4. Supported patterns and practical limits
5. Testing overview
6. Source layout
7. Additional documentation and license

### `COMMANDS.md`

The command reference is the operational handbook. It will contain the full
set of prerequisites, build and test commands, generated-fixture recipes,
runtime examples, flags, input annotations, cleanup commands, and
troubleshooting notes.

Planned sections:

1. Prerequisites
2. Build
3. Test
4. Generate fixtures
5. Run the program
6. CLI options
7. Optional input annotations
8. Expected behavior
9. Clean and rebuild
10. Troubleshooting

## Editorial rules

- Use short paragraphs, descriptive headings, compact tables, and focused code
  blocks.
- Use repository-relative commands instead of machine-specific absolute paths.
- Remove numbered headings, stale phase labels, repeated explanations, and
  claims that are not useful to operating the current code.
- Keep terminology and examples consistent between the two documents.
- Preserve the existing technical meaning and command coverage.
- Do not inspect or modify generated files under `data/`.

## Implementation and validation order

1. Rewrite `README.md` and validate its Markdown links, referenced paths, and
   displayed commands.
2. Only after the README validation succeeds, rewrite `COMMANDS.md`.
3. Validate headings, links, referenced paths, command-line options, and CMake
   preset names across both documents.
4. Run the fast regression suite after the documentation changes to confirm
   that the repository remains healthy.

This sequence follows the requirement to complete and test one improvement
before moving to the next.
