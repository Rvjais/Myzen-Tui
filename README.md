# Myzen TUI

Terminal UI for WE360 MyZen employee monitoring.

## Prerequisites

- **Python 3.10+** and `pip`
- **A WE360 MyZen account** with a setup script from your organisation

## Installation

```bash
pip install myzen-tui
```

## First-time setup

1. Download your organisation's setup script (`.sh` file) from the WE360 portal
2. Run `myzen-tui` — it will detect that no agent is installed
3. Enter the path to the `.sh` file when prompted
4. The TUI downloads and installs the monitoring agent (admin password required)
5. Log in with your WE360 email and password

On subsequent runs, the session is restored automatically — no login needed.

## Usage

| Key | Action     |
|-----|------------|
| `p` | Punch in   |
| `o` | Punch out  |
| `b` | Start break|
| `e` | End break  |
| `r` | Refresh    |
| `h` | History    |
| `q` | Quit       |

## License

MIT
