# Safe Source Library

The `safe_source.lib.sh` library provides a robust and reusable mechanism to temporarily source Bash scripts and fully revert any changes made to the shell environment. This includes environment variables, functions, aliases, and exported variables.

---

## Features

- **Full Environment Snapshot**: Captures variables, functions, aliases, and exports before sourcing.
- **Safe Sourcing and Reversion**: All changes are isolated and reversible.
- **Nested Support**: Multiple scripts can be sourced and unsourced independently (stack-based).
- **Minimal Side Effects**: Reverts exactly what changed—nothing more, nothing less.
- **Reusable as a Library**: Designed to be included in any Bash script.

---

## Usage

### 1. Include the Library

```bash
source /path/to/safe_source.lib.sh
```

### 2. `safe_source <script_path>`

Safely source another script, taking a snapshot of your current shell environment.

```bash
safe_source ./config.sh
```

### 3. `safe_unsource`

Revert changes made by the last script sourced using `safe_source`.

```bash
safe_unsource
```

---

## Example

### Subscripts

**`a.sh`**:
```bash
export VAR_A="from A"
alias hello_a='echo Hello from A'
function greet_a() { echo "Greet from A"; }
```

**`b.sh`**:
```bash
export VAR_B="from B"
alias hello_b='echo Hello from B'
function greet_b() { echo "Greet from B"; }
```

### Main Script

```bash
#!/usr/bin/env bash
source ./safe_source.lib.sh

safe_source ./a.sh
safe_source ./b.sh

echo "${VAR_A}"
echo "${VAR_B}"
hello_a
hello_b
greet_a
greet_b

safe_unsource  # removes b.sh effects
safe_unsource  # removes a.sh effects
```

---

## Behavior

- After sourcing `a.sh` and `b.sh`, all functions, aliases, and variables are available.
- After calling `safe_unsource` twice, none of the sourced script elements remain.

---

## Error Handling

- Invalid paths produce:
  ```
  Error: Script './missing.sh' does not exist.
  ```

- Calling `safe_unsource` with no stack:
  ```
  Error: No environment snapshot to unsource.
  ```

---

## Notes

- **Temporary Files**:
  - Used in `/tmp` to snapshot the environment. Auto-cleaned during unsourcing.
- **Safe to Source Multiple Times**:
  - Guards prevent reloading and redefining the library or functions.
- **Fallback Logging**:
  - If `info`, `error`, `warn`, etc. are not defined, they’re created as basic echo-style functions.

---

## License

This script is provided under the [MIT License](../LICENSE). Feel free to use and modify it for your needs.

---

Happy Sourcing! 🚀
