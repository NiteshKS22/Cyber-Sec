# 👁️ View — AI-Powered Wazuh Command Center

A high-performance, completely original, AI-driven SOC dashboard and MCP (Model Context Protocol) server for Wazuh SIEM. **View** provides real-time security monitoring, interactive tool execution, and an AI Lead Security Analyst (integrated via Ollama) to interpret your logs and provide actionable threat remediation.

---

## 🚀 Key Features

*   **🛡️ Multi-Tool SOC Dashboard**: A modern, glassmorphism-style dashboard for real-time monitoring of Wazuh agents, manager health, and security alerts.
*   **🤖 Lead Security Analyst AI**: Integrated with local LLMs (designed for `phi4-mini`) via Ollama. It analyzes REAL Wazuh logs, detects patterns like brute force attempts, and gives expert-level recommendations without hallucinations.
*   **🔌 14 Multi-Context Tools**: Fully interactive MCP tools that can be executed directly from the UI or by any MCP-compliant AI client.
*   **📊 Smart Pattern Recognition**: Automatically aggregates log sources, groups errors/warnings, and detects repeated suspicious IPs.
*   **⚡ Async Performance**: Built with `FastMCP`, `Starlette`, and `httpx` for maximum responsiveness and non-blocking security operations.
*   **🔒 Zero-Copyright Code**: 100% custom-built, lightweight implementation with no legacy dependencies.

---

## 🛠️ Integrated MCP Tools

| Tool | Category | Description |
| :--- | :--- | :--- |
| `refresh_auth` | auth | Forces a JWT token refresh for the Wazuh session. |
| `list_agents` | agents | Retrieves the status and details of all registered endpoints. |
| `get_agent` | agents | Fetches deep details for a specific Agent ID. |
| `agent_vulnerabilities` | vuln | Returns CVE scan results for a specific endpoint. |
| `agent_ports` | recon | Scans open network ports on a monitored agent. |
| `agent_processes` | recon | Lists all running processes on a selected agent. |
| `agent_packages` | recon | Audits installed software packages across your fleet. |
| `agent_sca` | compliance | Checks Security Compliance Assessment (SCA) results. |
| `sca_policy_checks` | compliance | Drills down into specific SCA policy test failures. |
| `list_rules` | rules | Queries the manager for all detection rules. |
| `list_decoders` | rules | Displays active log decoders configuration. |
| `cluster_status` | cluster | Monitors manager cluster health and node synchronization. |
| `manager_info` | system | General engine information (version, path, UUID). |
| `manager_logs` | system | Streams the latest manager operational logs. |

---

## 📦 Installation & Setup

### 1. Prerequisites
- **Python 3.10+**
- **Wazuh Manager** (IP, credentials, and API port 55000 reachable)
- **Ollama** (locally running on port 11434 with `phi4-mini:latest` pulled)

### 2. Clone and Setup Environment
```bash
git clone https://github.com/yourusername/view-wazuh-sentinel
cd view-wazuh-sentinel

# Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows
source .venv/bin/activate # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy the `.env.example` file to `.env` and fill in your actual Wazuh Manager credentials:
```bash
cp .env.example .env
```
Update these values:
- `WAZUH_URL`: Your Wazuh Manager URL (e.g., `https://192.168.1.10:55000`)
- `WAZUH_USER` & `WAZUH_PASS`: API credentials
- `OLLAMA_MODEL`: `phi4-mini:latest`

### 4. Running the Server
```bash
python server.py
```
Open your browser to `http://127.0.0.1:8010` to access the Command Center.

---

## 📖 Usage Instructions

1.  **Dashboard**: Monitor the connection status of your Wazuh Manager and AI engine. View a summary table of registered agents and their current status (Active/Disconnected).
2.  **View AI**: Use the chat interface to ask technical security questions. The server fetches real-time logs and agent metrics to give the AI context, enabling it to explain actual events happening in your network.
3.  **MCP Hub**: Click on any of the 14 tool cards. If a tool requires parameters (like an Agent ID), a dialog will prompt you for input. All results are displayed as formatted JSON.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.

## ✍️ Credits
Original implementation by **Nitesh**.
Built with ❤️ for the cybersecurity community.
