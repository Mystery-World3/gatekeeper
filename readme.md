# GateKeeper 

GateKeeper is a simple but effective command-line tool designed to detect ARP spoofing attacks on a local network in real-time. It acts as a watchdog, constantly monitoring for malicious changes to the network's ARP table.

This tool is the "defensive" counterpart to the "offensive" NetReaper project.

## How It Works

The core principle of GateKeeper is to monitor the integrity of the network's gateway MAC address.

1.  **Establish Baseline:** On startup, GateKeeper determines the legitimate MAC address of the network's default gateway and saves it as a trusted baseline.
2.  **Continuous Monitoring:** The tool then enters a monitoring loop, periodically re-checking the gateway's current MAC address by sending its own ARP requests.
3.  **Trigger Alert:** If the currently observed MAC address ever differs from the original, trusted MAC address, GateKeeper immediately triggers a highly visible security alert on the console. This change is a classic indicator of a Man-in-the-Middle (MITM) attack via ARP spoofing.

## Features

-   **Real-time ARP Spoofing Detection:** Actively monitors the network for signs of an attack.
-   **Clear On-Screen Alerts:** Provides an immediate and easy-to-understand visual warning upon detecting an anomaly.
-   **Lightweight:** Runs in the background with minimal resource usage.
-   **Simple Configuration:** Only requires the gateway's IP address to be set.

## Requirements

-   Python 3.7+
-   Python packages: `scapy`, `rich`
-   **Windows:** [Npcap](https://npcap.com/) must be installed with "WinPcap API-compatible Mode" enabled.
-   **Linux/macOS:** The script must be run with `sudo` privileges.

## Setup & Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Mystery-World3/gatekeeper.git
    cd gatekeeper
    ```

2.  **Set up a virtual environment and install dependencies:**
    ```bash
    # Create and activate venv
    python -m venv venv
    .\venv\Scripts\Activate  # On Windows
    # source venv/bin/activate # On macOS/Linux

    # Install requirements from requirements.txt
    pip install scapy rich
    ```

3.  **Configure the Script:**
    Open `gatekeeper.py` and set the `gateway_ip` variable to match your network's default gateway. You can find this using `ipconfig` (on Windows) or `ip r` (on Linux).

4.  **Run the Tool:**
    The script must be run with elevated privileges.
    ```bash
    # On Windows, use a terminal that was "Run as administrator"
    python main.py

    # On Linux/macOS
    sudo python main.py
    ```
    GateKeeper will now be monitoring your network.

## How to Test GateKeeper

To see GateKeeper in action, you need to simulate an attack. You can use the **NetReaper** tool for this.

1.  In one terminal (as Administrator/root), run `gatekeeper.py`. It will start monitoring.
2.  In a **second** terminal (as Administrator/root), run `netreaper.py`.
3.  As soon as NetReaper begins its ARP spoofing attack, switch back to the GateKeeper terminal. You will see a red `SECURITY ALERT` panel appear, confirming that the attack was successfully detected.

   ---

*Created by Mystery-World3*
