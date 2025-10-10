# One-Off Bash Scripts
# Project Badges

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://github.com/tatanus/scripts/actions/workflows/main.yml/badge.svg)](https://github.com/tatanus/scripts/actions/workflows/main.yml)
[![Last Commit](https://img.shields.io/github/last-commit/tatanus/BASH)](https://github.com/tatanus/scripts/commits/main)

![Bash >=4.0](https://img.shields.io/badge/Bash-%3E%3D4.0-4EAA25?logo=gnu-bash&logoColor=white)
![Python >=3.12](https://img.shields.io/badge/Python-%3E%3D3.12-3776AB?logo=python&logoColor=white)


This repository is a curated collection of standalone, single-purpose Bash utilities. Each script is self-contained and designed to solve a specific task securely and efficiently using best practices in Bash scripting.

---

## Repository Structure

```
.
├── LICENSE
├── docs/
│   ├── CAPTURE_TRAFFIC_README.md
│   ├── LOGGER_README.md
│   ├── SAFE_SOURCE_README.md
│   ├── LICENSE
├── scripts/
│   ├── capture_traffic.sh
│   ├── logger.sh
│   ├── safe_source.sh
```

---

## Included Scripts

### 1. [Capture Traffic](./docs/CAPTURE_TRAFFIC_README.md)
A utility for capturing bidirectional TCP traffic between two IPs and ports using `tshark`.

- Logs traffic with timestamps, IP addresses, ports, and application payloads.
- Useful for debugging or analyzing network communication in real-time.

### 2. [Logger](./docs/LOGGER_README.md)
A shell logging utility that provides structured, color-coded log output functions (e.g., `info`, `warn`, `error`).

- Designed for use in secure Bash scripts.
- Easily portable into any Bash project.

### 3. [Safe Source](./docs/SAFE_SOURCE_README.md)
A script and library to safely source other shell scripts and revert their changes to the environment.

- Tracks and undoes changes to variables, functions, aliases, and exports.
- Useful for modular scripting or testing.

---

## Usage

Each script is designed to be:
- Modular and easy to reuse.
- Secure, passing ShellCheck and formatting tools.
- Documented with a dedicated README in the `docs/` directory.

You can find usage, options, examples, and error handling behavior in each script’s linked README.

---

## License

This repository is licensed under the [MIT License](./docs/LICENSE). Each script may also include its own header-based licensing or author notes.

---

## Contributing

These scripts are meant to be lightweight and purpose-built. Feel free to fork and modify them for your own workflows or submit a PR for small fixes.

---

Happy scripting! 🐚
