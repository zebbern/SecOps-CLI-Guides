# Claude AI SKILLS.md Best Practices Guide (2025)

## Executive Summary

This document provides comprehensive best practices for creating Claude AI SKILLS.md files, based on official Anthropic documentation and the Claude Code plugin system as of 2025.

---

## 1. What is the Purpose of SKILLS.md Files?

SKILLS.md files are knowledge modules that extend Claude's capabilities with specialized domain expertise. They serve four primary purposes:

1. **Specialized Workflows** - Multi-step procedures for specific domains
2. **Tool Integrations** - Instructions for working with specific file formats or APIs
3. **Domain Expertise** - Company-specific knowledge, schemas, business logic
4. **Bundled Resources** - Scripts, references, and assets for complex and repetitive tasks

### When Skills Are Loaded

Skills use a **progressive disclosure design** - they are loaded into Claude's context only when relevant based on:
- User request keywords matching trigger phrases in the description
- Task context matching the skill's domain
- Explicit user invocation

---

## 2. Recommended Structure and Format

### Directory Structure

```
skill-name/
├── SKILL.md (required)
│   ├── YAML frontmatter metadata (required)
│   │   ├── name: (required)
│   │   └── description: (required)
│   └── Markdown instructions (required)
└── Bundled Resources (optional)
    ├── scripts/          - Executable code (Python/Bash/etc.)
    ├── references/       - Documentation loaded as needed
    ├── examples/         - Working code samples
    └── assets/           - Templates, icons, fonts, etc.
```

### Skill Complexity Levels

#### Minimal Skill
```
skill-name/
└── SKILL.md
```
Good for: Simple knowledge, no complex resources needed

#### Standard Skill (Recommended)
```
skill-name/
├── SKILL.md
├── references/
│   └── detailed-guide.md
└── examples/
    └── working-example.sh
```
Good for: Most skills with detailed documentation

#### Complete Skill
```
skill-name/
├── SKILL.md
├── references/
│   ├── patterns.md
│   └── advanced.md
├── examples/
│   ├── example1.sh
│   └── example2.json
└── scripts/
    └── validate.sh
```
Good for: Complex domains with validation utilities

---

## 3. YAML Frontmatter Best Practices

### Required Fields

```yaml
---
name: Skill Name
description: This skill should be used when the user asks to "specific phrase 1", "specific phrase 2", "specific phrase 3". Include exact phrases users would say that should trigger this skill. Be concrete and specific.
---
```

### Recommended Fields

```yaml
---
name: Skill Name
description: This skill should be used when the user asks to "create X", "configure Y", "troubleshoot Z", or needs guidance on [specific domain]. Concrete trigger scenarios help Claude determine when to load this skill.
version: 0.1.0
---
```

### Description Best Practices

**✅ DO:**
- Use **third person** format: "This skill should be used when..."
- Include **specific trigger phrases** users would say
- Be **concrete and specific** about when to activate
- List multiple scenarios ("create X", "configure Y", "troubleshoot Z")
- Keep length between 50-500 characters

**❌ DON'T:**
- Use first/second person: "Use this skill when..." or "You should use this..."
- Be vague: "This skill helps with general tasks"
- Omit trigger phrases
- Make it too short (<50 chars) or too long (>500 chars)

### Example Descriptions

**Good:**
```yaml
description: This skill should be used when the user asks to "create a plugin", "scaffold a plugin", "understand plugin structure", "organize plugin components", "set up plugin.json", "use ${CLAUDE_PLUGIN_ROOT}", "add commands/agents/skills/hooks", "configure auto-discovery", or needs guidance on plugin directory layout, manifest configuration, component organization, file naming conventions, or Claude Code plugin architecture best practices.
```

**Bad:**
```yaml
description: Helps with plugin stuff.
```

---

## 4. Writing Style for Skill Body

### Use Imperative/Infinitive Form

Write the entire skill using **verb-first instructions**, not second person.

**✅ Correct (Imperative/Infinitive):**
```markdown
To configure the database:
1. Create a connection string with the following format...
2. Initialize the client with appropriate timeout settings...
3. Implement error handling for connection failures...
```

**❌ Incorrect (Second Person):**
```markdown
You should configure the database:
1. You need to create a connection string...
2. You should initialize the client...
3. You will want to implement error handling...
```

### Objective, Instructional Language

- "To accomplish X, do Y" ✅
- "You should do X" ❌
- "If you need to do X" ❌

---

## 5. Progressive Disclosure (Context Management)

Skills use a **three-level loading system** to manage context efficiently:

| Level | Content | Size | When Loaded |
|-------|---------|------|-------------|
| 1. Metadata | `name` + `description` | ~100 words | Always in context |
| 2. SKILL.md body | Core instructions | <5,000 words | When skill triggers |
| 3. Bundled resources | Scripts, references, examples | Unlimited* | As needed by Claude |

*Scripts can be executed without reading into context window.

### What Goes Where

#### In SKILL.md (Always Loaded When Triggered)
- Core concepts and overview
- Essential procedures and workflows
- Quick reference tables
- Pointers to references/examples/scripts
- Most common use cases

**Target: 1,500-2,000 words (max 3,000 words)**

#### In references/ (Loaded As Needed)
- Detailed patterns and advanced techniques
- Comprehensive API documentation
- Migration guides
- Edge cases and troubleshooting
- Extensive examples and walkthroughs

**Each file: 2,000-5,000+ words**

#### In examples/ (Copy-Paste Ready)
- Complete, runnable scripts
- Configuration files
- Template files
- Real-world usage examples

#### In scripts/ (Executable)
- Validation tools
- Testing helpers
- Parsing utilities
- Automation scripts

**Should be executable and documented**

### Avoiding Context Overflow

1. **Keep SKILL.md lean** - Move detailed content to references/
2. **Avoid duplication** - Information should live in either SKILL.md OR references, not both
3. **For large files (>10k words)** - Include grep search patterns in SKILL.md so Claude can find specific sections
4. **Reference supporting files clearly** - Tell Claude where to find detailed information

---

## 6. Step-by-Step Workflows

### Structure Pattern

```markdown
## Workflow: [Name]

### Prerequisites
- [Requirement 1]
- [Requirement 2]

### Steps

1. **Step Name:**
   - Action description
   - Expected outcome
   - Validation check

2. **Step Name:**
   - Action description
   - Code example if needed
   - Notes or warnings

### Success Criteria
- [Criterion 1]
- [Criterion 2]

### Troubleshooting
- Issue → Solution
- Issue → Solution
```

### Example Workflow

```markdown
## Skill Creation Process

### Step 1: Plan the Skill
Identify:
- Use cases the skill addresses
- Trigger phrases users would say
- Resources needed (scripts, references, examples)

### Step 2: Create Directory Structure
```bash
mkdir -p skills/skill-name/{references,examples,scripts}
```

### Step 3: Write SKILL.md
- Create frontmatter with name and third-person description
- Write lean body (1,500-2,000 words) in imperative form
- Reference supporting files

### Step 4: Add Resources
Create as needed:
- `references/` - Detailed documentation
- `examples/` - Working code samples
- `scripts/` - Utility scripts

### Step 5: Validate
- [ ] Description uses third person
- [ ] Includes specific trigger phrases
- [ ] Body uses imperative form
- [ ] All referenced files exist
```

---

## 7. Handling Constraints and Examples

### Documenting Constraints

```markdown
## Constraints

**Must:**
- [Required behavior 1]
- [Required behavior 2]

**Must Not:**
- [Prohibited behavior 1]
- [Prohibited behavior 2]

**Should:**
- [Recommended behavior]

**May:**
- [Optional behavior]
```

### Including Examples

#### Inline Examples (for simple cases)
```markdown
**Example:**
```python
# Simple usage
result = function_name(param1, param2)
```
```

#### Reference Examples (for complex cases)
```markdown
## Examples

Working examples available in `examples/`:
- **`basic-usage.py`** - Simple initialization
- **`advanced-config.py`** - Full configuration options
- **`error-handling.py`** - Robust error management
```

### Example Block Format (for agent descriptions)

```yaml
description: Use this agent when [conditions]. Examples:

<example>
Context: [Scenario description]
user: "[What user says]"
assistant: "[How Claude should respond]"
<commentary>
[Why this agent is appropriate]
</commentary>
</example>
```

---

## 8. Modular Design Principles

### Separation of Concerns

| Component | Purpose | Location |
|-----------|---------|----------|
| Core concepts | Always needed | SKILL.md |
| Detailed docs | Reference as needed | references/ |
| Working code | Copy and adapt | examples/ |
| Utilities | Execute directly | scripts/ |

### File Organization

```
skills/
└── api-testing/
    ├── SKILL.md              # Core skill (1500 words max)
    ├── references/
    │   ├── rest-api-guide.md     # REST patterns
    │   ├── graphql-guide.md      # GraphQL patterns
    │   └── authentication.md     # Auth patterns
    ├── examples/
    │   ├── basic-test.js         # Simple test
    │   ├── authenticated-test.js # With auth
    │   └── integration-test.js   # Full integration
    ├── scripts/
    │   ├── run-tests.sh          # Test runner
    │   └── generate-report.py    # Report generator
    └── assets/
        └── test-template.json    # Template file
```

### Cross-Referencing in SKILL.md

```markdown
## Additional Resources

### Reference Files
For detailed patterns and techniques, consult:
- **`references/patterns.md`** - Common patterns
- **`references/advanced.md`** - Advanced use cases

### Example Files
Working examples in `examples/`:
- **`example-script.sh`** - Working example with comments

### Utility Scripts
Development tools in `scripts/`:
- **`validate.sh`** - Validate configuration
- **`parse-data.py`** - Parse input files
```

---

## 9. File Naming Conventions

### Skill Directories
- Use **kebab-case**: `api-testing/`, `database-migrations/`, `error-handling/`

### Documentation Files
- Use **kebab-case markdown**: `api-reference.md`, `migration-guide.md`, `best-practices.md`

### Scripts
- Use **descriptive kebab-case with extensions**: `validate-input.sh`, `generate-report.py`, `process-data.js`

---

## 10. Validation Checklist

Before finalizing a skill, verify:

### Structure
- [ ] SKILL.md file exists with valid YAML frontmatter
- [ ] Frontmatter has `name` and `description` fields
- [ ] Markdown body is present and substantial
- [ ] Referenced files actually exist

### Description Quality
- [ ] Uses third person ("This skill should be used when...")
- [ ] Includes specific trigger phrases users would say
- [ ] Lists concrete scenarios ("create X", "configure Y")
- [ ] Not vague or generic
- [ ] Length between 50-500 characters

### Content Quality
- [ ] SKILL.md body uses imperative/infinitive form
- [ ] Body is focused and lean (1,500-2,000 words ideal, <5k max)
- [ ] Detailed content moved to references/
- [ ] Examples are complete and working
- [ ] Scripts are executable and documented

### Progressive Disclosure
- [ ] Core concepts in SKILL.md
- [ ] Detailed docs in references/
- [ ] Working code in examples/
- [ ] Utility tools in scripts/

---

## 11. Best Practices Summary

### ✅ DO:
- Use third-person in description ("This skill should be used when...")
- Include specific trigger phrases ("create X", "configure Y")
- Keep SKILL.md lean (1,500-2,000 words)
- Use progressive disclosure (move details to references/)
- Write in imperative/infinitive form
- Reference supporting files clearly
- Provide working examples
- Create utility scripts for common operations

### ❌ DON'T:
- Use second person anywhere
- Have vague trigger conditions
- Put everything in SKILL.md (>3,000 words without references/)
- Write in second person ("You should...")
- Leave resources unreferenced
- Include broken or incomplete examples
- Skip validation

---

## 12. Quick Reference Templates

### Minimal SKILL.md Template

```markdown
---
name: My Skill
description: This skill should be used when the user asks to "do X", "configure Y", or needs guidance on Z topic.
version: 0.1.0
---

# My Skill

## Overview

Brief description of what this skill provides.

## Core Concepts

Key concepts and definitions.

## Workflow

1. **Step 1:** Description
2. **Step 2:** Description
3. **Step 3:** Description

## Quick Reference

Essential reference tables or commands.

## Troubleshooting

Common issues and solutions.
```

### Standard SKILL.md with Resources

```markdown
---
name: My Skill
description: This skill should be used when the user asks to "specific action 1", "specific action 2", "troubleshoot X", or needs guidance on Y domain with Z requirements.
version: 0.1.0
---

# My Skill

## Overview

Brief description with key characteristics.

**Key concepts:**
- Concept 1
- Concept 2
- Concept 3

## Core Workflow

### Step 1: Name
Description of action...

### Step 2: Name
Description of action...

## Quick Reference

| Item | Description |
|------|-------------|
| A | Description A |
| B | Description B |

## Additional Resources

### Reference Files
For detailed patterns:
- **`references/detailed-guide.md`** - Comprehensive documentation

### Example Files
Working examples in `examples/`:
- **`basic-example.sh`** - Simple usage pattern

### Utility Scripts
Tools in `scripts/`:
- **`validate.sh`** - Validation utility
```

---

## Sources

This guide is based on:
- Official Anthropic Claude Code repository (`anthropics/claude-code`)
- Claude Code Plugin Development documentation
- Skill Development SKILL.md and skill-creator methodology
- Real-world plugin examples from Anthropic

---

*Last updated: January 2025*
