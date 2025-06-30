# gatekeeper.py - v0.1
# An ARP spoofing detection tool for educational purposes.
# Coded by: [Your Name or Handle Here]

import sys
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from scapy.all import ARP, Ether, srp


console = Console()

def get_mac(ip_address: str) -> str | None:
    """
    Returns the MAC address for a given IP address by broadcasting an ARP request.
    """
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Using a slightly longer timeout to be more reliable
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def main():
    """Main function to run the ARP spoofing detector."""
    # --- CONFIGURATION ---
    # IMPORTANT: Set the gateway IP for the network you want to protect.
    gateway_ip = "192.168.43.65" # <-- SET YOUR GATEWAY/ROUTER'S IP HERE
    # --- END CONFIGURATION ---

    console.print(Panel("[bold cyan]GateKeeper v0.1[/bold cyan] - ARP Spoofing Detector", 
                subtitle="[dim]Press Ctrl+C to stop[/dim]"), justify="center")

    console.print(f"[yellow]Acquiring the legitimate MAC address for the gateway ({gateway_ip})...[/yellow]")
    
    try:
        real_gateway_mac = get_mac(gateway_ip)
    except Exception:
        console.print(f"[bold red]Error:[/bold red] Could not get MAC address. Run as root/administrator.")
        sys.exit()

    if not real_gateway_mac:
        console.print(f"[bold red]Error:[/bold red] Could not resolve gateway MAC. Is the IP correct and are you connected?")
        sys.exit()
    
    console.print(f"[green]✓[/green] Legitimate Gateway MAC Address is: [bold yellow]{real_gateway_mac.upper()}[/bold yellow]")
    console.print("\n[cyan]Monitoring started. All systems nominal.[/cyan]\n")

    try:
        while True:
            # Continuously check the current MAC address of the gateway
            current_mac = get_mac(gateway_ip)

            # If the MAC is found AND it's different from the real one, sound the alarm!
            if current_mac and current_mac != real_gateway_mac:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                alert_message = (
                    f"[bold red]!! WARNING: ARP SPOOFING DETECTED !![/bold red]\n\n"
                    f"Timestamp: {timestamp}\n"
                    f"The Gateway's MAC address has changed!\n\n"
                    f"  Original MAC: [green]{real_gateway_mac.upper()}[/green]\n"
                    f"  Suspicious MAC: [red]{current_mac.upper()}[/red]\n\n"
                    f"Your network traffic is likely being intercepted."
                )
                console.print(Panel(alert_message, title="[blink red]SECURITY ALERT[/blink red]", border_style="red"))
                
            # Wait for a few seconds before the next check
            time.sleep(3)

    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Monitoring stopped by user. Exiting.[/bold yellow]")
        sys.exit()

if __name__ == "__main__":
    main()