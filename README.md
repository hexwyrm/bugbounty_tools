# Bug Bounty Recon Pipeline

A modular, extensible automation framework designed to streamline bug bounty reconnaissance workflows.
This repository contains tools focused on passive intelligence gathering, DNS resolution, port scanning, web probing, content discovery, and deep enumeration.

The project is built with portability and clarity in mind, using Bash and widely adopted open‑source recon utilities.

---

## Repository Contents

### Current Tools
- **bugbountyreconautomation.sh** — A full multi‑phase recon pipeline with tool checks, parallel execution, structured output, and modular enumeration stages.

### Future Additions
This repository is structured to grow over time. Planned expansions may include:
- Additional recon modules
- Wordlist generation utilities
- Screenshotting and reporting helpers
- Optional integrations with external scanners
- Standalone sub‑tools for specific phases

As new tools are added, they will appear in the list above.

---

## Features

- Automated multi‑phase reconnaissance
- Passive and active subdomain enumeration
- DNS resolution and port scanning
- Web probing with technology detection
- JavaScript and sensitive file discovery
- Parameter mining for XSS vectors
- Heavy enumeration modules for deep coverage
- Graceful handling of missing tools
- Organized output per‑target directory

---

## Installation

Clone the repository:
```
git clone https://github.com/hexwyrm/bugbounty_tools.git
```


Make the main script executable:
```
chmod +x bugbountyreconautomation.sh
```

---

## 🛠 Usage

Run the pipeline against a target domain:
```
./bugbountyreconautomation.sh example.com
```

All output will be stored in a directory named after the target.

---

## 📜 License

This project is licensed under the **Apache License 2.0**.

See the `LICENSE` file for the full license text.

---

## 🤝 Contributions

Contributions, improvements, and module additions are welcome.
All contributions are licensed under the terms of the Apache License 2.0.

---

## ⚠️ Disclaimer

This project is intended for **authorized security testing and educational use only**.
You are responsible for ensuring you have permission to test any target.

Unauthorized scanning or probing may violate laws or terms of service.
