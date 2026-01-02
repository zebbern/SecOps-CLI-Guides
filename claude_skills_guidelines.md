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
```

---

## 5. Progressive Disclosure (Context Management)

Skills use a **three-level loading system** to manage context efficiently:

| Level | Content | Size | When Loaded |
|-------|---------|------|-------------|
| 1. Metadata | `name` + `description` | ~100 words | Always in context |
| 2. SKILL.md body | Core instructions | <5,000 words | When skill triggers |
| 3. Bundled resources | Scripts, references, examples | Unlimited* | As needed by Claude |

**Target: 1,500-2,000 words (max 3,000 words)**

---

## 6. Required SKILLS.md Sections

For each SKILLS.md file, include:

1. **Metadata**: Name, description, and relevant tags (YAML frontmatter)
2. **Purpose**: Why the skill is relevant and its practical applications
3. **Inputs**: Requirements or dependencies Claude needs
4. **Outputs**: Expected results or deliverables when the skill is executed
5. **Step-by-Step Workflow**: Detailed, actionable steps broken down for implementation
6. **Constraints**: Limitations and context for using the skill effectively
7. **Examples**: Provide practical examples with correct syntax or workflows

---

## 7. Validation Checklist

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
- [ ] Examples are complete and working

---

## 8. Template

```markdown
---
name: [Skill Name]
description: This skill should be used when the user asks to "[trigger phrase 1]", "[trigger phrase 2]", "[trigger phrase 3]", or needs guidance on [specific domain].
version: 0.1.0
tags: [tag1, tag2, tag3]
---

# [Skill Name]

## Purpose

Brief description of the skill's purpose and practical applications in security operations.

## Inputs/Prerequisites

- [Requirement 1]
- [Requirement 2]
- [Tool/Software dependency]

## Outputs/Deliverables

- [Expected result 1]
- [Expected result 2]

## Core Workflow

### Step 1: [Step Name]
Description of the step with actionable instructions.

### Step 2: [Step Name]
Description with code examples if applicable.

## Quick Reference

| Command/Technique | Description |
|-------------------|-------------|
| `command` | What it does |

## Constraints

**Must:**
- [Required behavior]

**Must Not:**
- [Prohibited behavior]

## Examples

### Example 1: [Scenario]
```bash
# Example code or command
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Problem | Resolution |
```

---

*Last updated: January 2025*
