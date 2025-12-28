# Logger Script (`logger.sh`)

`logger.sh` is a modular, instance-based logging utility for Bash scripts. It enables structured logging with configurable log levels, supports multiple independent logger instances, and allows flexible output to both console and files.

---

## 🚀 Features

- **Instance-based** — Initialize multiple logger instances with independent settings (log file, level, output destinations).
- **Configurable log levels** — Supports these levels (from most verbose to most severe): `vdebug`, `debug`, `info`, `pass`, `warn`, `fail`. Only messages at or above the configured level are logged.
- **Screen and File Output** — Each instance can log to the terminal, log file, or both.
- **Colorized Console Output** — Log levels are color-coded when output to terminal.
- **Timestamped Messages** — Each log entry is prefixed with `[YYYY‑MM‑DD HH:MM:SS]`.
- **Debug Metadata** —  
  - `debug` includes caller info: file, function, line.  
  - `vdebug` shows a stack trace (up to last 3 calls).
- **Robust Defaults & Validation** — Enforces valid instance names, log levels, boolean flags, and file paths.
- **Graceful Error Handling** — Logs errors if file writing fails, with error return codes.

---

## 📁 Script Details

- **Default instance name**: `default`  
- **Default log file**: `${HOME}/default.log`  
- **Default log level**: `info`  
- **Default behavior**: log to screen and file enabled  

---

## ⚙️ Setup & Usage

### 1. Include the logger script

```bash
source /path/to/logger.sh
```

### 2. Initialize a logger

```bash
Logger_Init "mylogger" "/path/to/my.log" "debug" "true" "true"
```

Parameters:
- `instance_name` — Alphanumeric/underscore only, must start with letter or underscore.
- `log_file` — Path to the logfile.
- `log_level` — One of `vdebug`, `debug`, `info`, `pass`, `warn`, `fail`.
- `log_to_screen` — `true` or `false`.
- `log_to_file` — `true` or `false`.

If omitted, defaults are used.

### 3. Use logger methods

After initialization, methods are available as:

```bash
mylogger.info "This is an informational message"
mylogger.debug "Debugging details"
mylogger.vdebug "Verbose stack-trace message"
mylogger.pass "Operation succeeded"
mylogger.warn "Warning — take note"
mylogger.fail "Error occurred" || exit 1
```

### 4. Adjust settings at runtime

```bash
mylogger.set_log_level "warn"
current_level=$(mylogger.get_log_level)
mylogger.set_log_to_screen "false"
mylogger.set_log_to_file "true"
```

---

## 🧠 Behavior Overview

- **Filtering by level**  
  Only messages whose numeric priority meets or exceeds the instance’s configured `log_level` are emitted. Priorities:  
  `vdebug=10`, `debug=20`, `info=30`, `pass=40`, `warn=50`, `fail=60`.

- **Console (screen) output**  
  - Enabled with `log_to_screen="true"`.  
  - Uses colors (if supported), e.g. blue for `info`, orange for `debug/vdebug`, green for `pass`, red for `fail`, yellow for `warn`.

- **File output**  
  - Enabled with `log_to_file="true"`.  
  - Entries are appended with timestamp and formatted prefix.

- **Error diagnostics**  
  - Attempts to validate log file paths and write access.  
  - If writing fails, logs an error and returns non-zero.

---

## 🔍 Examples

```bash
#!/usr/bin/env bash
source path/to/logger.sh

Logger_Init "app" "/tmp/app.log" "debug" "true" "true"

app.info "Starting app..."
app.debug "Connecting to database"
# Inside a function:
foo() {
  app.vdebug "Entered foo()"
  # ...
}
foo

app.warn "Disk space low"
app.fail "Fatal error" || exit 1
```

If log level is `debug`, `info`, `warn`, and `fail` messages are shown. A `vdebug` call inside `foo()` prints full stack trace.

---

## ✅ Summary of Instance Properties

| Property         | Description                                         |
|------------------|-----------------------------------------------------|
| `log_file`       | Path for writing log entries                        |
| `log_level`      | Minimum severity to log                             |
| `log_to_screen`  | `true`/`false` toggle for terminal output           |
| `log_to_file`    | `true`/`false` toggle for file output               |

Adjust via:
```bash
<instance>.set_log_level "level"
<instance>.set_log_to_screen "true|false"
<instance>.set_log_to_file "true|false"
```

---

## 🛠️ Error Handling

- Invalid instance names, levels, boolean values, or file paths trigger descriptive error messages.
- Logging methods return non-zero on invalid parameters or file write failures, so you can conditionally exit or handle errors.

---

## 📅 Authorship & Licensing

**Author**: Adam Compton  
**Date Created**: December 8, 2024  
This script is provided under the [MIT License](./LICENSE). Feel free to use and modify it for your needs.

---

## TL;DR

1. `source logger.sh`  
2. `Logger_Init "instance" "path/to.log" "level" "true" "true"`  
3. Call `instance.info/debug/vdebug/pass/warn/fail`  
4. Use setter/getter methods to adjust behavior.
