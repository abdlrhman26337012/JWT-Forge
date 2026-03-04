"""
JWTForge - Reporter
Handles all rich terminal output, tables, panels, and result display.
"""

import json
import time
from .._rich_compat import _ensure_rich  # noqa: F401 — ensure rich is on path
from datetime import datetime
from typing import Dict, Any, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

BANNER = r"""
     ██╗██╗    ██╗████████╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
     ██║██║    ██║╚══██╔══╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
     ██║██║ █╗ ██║   ██║       █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
██   ██║██║███╗██║   ██║       ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
╚█████╔╝╚███╔███╔╝   ██║       ██║     ╚██████╔╝██║  ██╗╚██████╔╝███████╗
 ╚════╝  ╚══╝╚══╝    ╚═╝       ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

SUBTITLE = "JWT Attack Suite  ·  Week 15  ·  All-in-one JWT Exploitation"


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(f"[bold yellow]           {SUBTITLE}[/bold yellow]")
    console.print()


def print_section(title: str, color: str = "cyan"):
    console.print()
    console.rule(f"[bold {color}]{title}[/bold {color}]", style=color)


def print_success(msg: str):
    console.print(f"  [bold green]✔[/bold green]  {msg}")


def print_fail(msg: str):
    console.print(f"  [bold red]✘[/bold red]  {msg}")


def print_info(msg: str):
    console.print(f"  [bold blue]ℹ[/bold blue]  {msg}")


def print_warn(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def print_token(label: str, token: str, color: str = "green"):
    console.print(f"\n  [bold {color}]{label}:[/bold {color}]")
    # Split token visually
    parts = token.split('.')
    if len(parts) == 3:
        header, payload, sig = parts
        console.print(
            f"  [cyan]{header}[/cyan]"
            f"[white].[/white]"
            f"[yellow]{payload}[/yellow]"
            f"[white].[/white]"
            f"[magenta]{sig if sig else '[dim](empty)[/dim]'}[/magenta]"
        )
    else:
        console.print(f"  [green]{token}[/green]")


def display_jwt_info(description: Dict[str, Any], token: str):
    """Display decoded JWT information in a rich panel."""
    print_section("JWT Analysis", "cyan")

    # Algorithm badge
    alg = description['algorithm']
    alg_color = "green" if alg.startswith('HS') else "yellow" if alg.startswith('RS') else "red"

    # Header table
    header_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    header_table.add_column("Key", style="bold cyan", width=14)
    header_table.add_column("Value", style="white")

    for k, v in description['header'].items():
        header_table.add_row(k, str(v))

    # Payload table
    payload_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    payload_table.add_column("Key", style="bold yellow", width=14)
    payload_table.add_column("Value", style="white")

    for k, v in description['payload'].items():
        display_val = str(v)
        # Format timestamps
        if k in ('exp', 'iat', 'nbf') and isinstance(v, (int, float)):
            try:
                dt = datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M:%S')
                display_val = f"{v} ({dt})"
            except Exception:
                pass
        payload_table.add_row(k, display_val)

    console.print(Panel(header_table, title="[bold cyan]Header[/bold cyan]", border_style="cyan"))
    console.print(Panel(payload_table, title="[bold yellow]Payload[/bold yellow]", border_style="yellow"))

    # Metadata
    meta = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    meta.add_column("Field", style="bold", width=18)
    meta.add_column("Value")

    meta.add_row("Algorithm", f"[{alg_color}]{alg}[/{alg_color}]")
    meta.add_row("Has Signature", "[green]Yes[/green]" if description['has_signature'] else "[red]No[/red]")
    meta.add_row("Expired", "[red]Yes[/red]" if description['is_expired'] else "[green]No[/green]")

    if description['kid']:
        meta.add_row("KID", f"[yellow]{description['kid']}[/yellow]")
    if description['jku']:
        meta.add_row("JKU", f"[magenta]{description['jku']}[/magenta]")
    if description['x5u']:
        meta.add_row("X5U", f"[magenta]{description['x5u']}[/magenta]")

    console.print(Panel(meta, title="[bold white]Metadata[/bold white]", border_style="white"))

    # Vulnerabilities hints
    vulns = []
    if alg.lower().startswith('hs') or alg.lower() == 'none':
        vulns.append("[yellow]⚠  Symmetric algorithm — brute-force may be possible[/yellow]")
    if alg.upper().startswith('RS'):
        vulns.append("[yellow]⚠  RSA algorithm — RS256→HS256 key confusion possible[/yellow]")
    if description['kid']:
        vulns.append("[yellow]⚠  KID header present — injection attacks possible[/yellow]")
    if description['jku']:
        vulns.append("[yellow]⚠  JKU header present — SSRF / JKU spoofing possible[/yellow]")
    if description['x5u']:
        vulns.append("[yellow]⚠  X5U header present — X5U spoofing possible[/yellow]")
    if description['is_expired']:
        vulns.append("[red]⚠  Token is expired — may indicate weak validation[/red]")

    if vulns:
        vuln_text = "\n".join(vulns)
        console.print(Panel(vuln_text, title="[bold red]Potential Weaknesses[/bold red]", border_style="red"))


def display_scan_results(results: List[Dict[str, Any]]):
    """Display the scan results table."""
    print_section("Scan Results", "green")

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("Attack", style="bold", width=22)
    table.add_column("Status", width=10)
    table.add_column("Details", style="white")

    successes = 0
    for i, r in enumerate(results, 1):
        status = r.get('status', 'unknown')
        if status == 'success':
            status_str = "[bold green]PWNED ✔[/bold green]"
            successes += 1
        elif status == 'skipped':
            status_str = "[dim]SKIPPED[/dim]"
        elif status == 'error':
            status_str = "[bold red]ERROR[/bold red]"
        else:
            status_str = "[yellow]NOT VULN[/yellow]"

        table.add_row(
            str(i),
            r.get('attack', ''),
            status_str,
            r.get('detail', '')
        )

    console.print(table)
    console.print()

    if successes > 0:
        console.print(Panel(
            f"[bold green]{successes} attack(s) succeeded![/bold green]\n"
            "Check forged tokens above — use them to bypass JWT validation.",
            title="[bold green]💀 VULNERABLE[/bold green]",
            border_style="green"
        ))
    else:
        console.print(Panel(
            "[dim]No attacks succeeded with current configuration.\n"
            "Try providing --pubkey for key confusion, --wordlist for brute force.[/dim]",
            title="[white]Not Vulnerable (with current inputs)[/white]",
            border_style="white"
        ))


def display_forged_tokens(tokens: List[Dict[str, Any]]):
    """Display all forged tokens."""
    for item in tokens:
        if item.get('token'):
            print_token(
                f"  [{item.get('attack', 'forged')}] Forged Token",
                item['token']
            )
            if item.get('note'):
                console.print(f"    [dim]{item['note']}[/dim]")
            console.print()


def display_brute_result(found: Optional[str], token: str, attempts: int, elapsed: float):
    """Display brute-force result."""
    if found:
        console.print(Panel(
            f"[bold green]Secret Found![/bold green]\n\n"
            f"  Secret : [bold yellow]{found}[/bold yellow]\n"
            f"  Tried  : {attempts:,} passwords in {elapsed:.2f}s",
            title="[bold green]✔ CRACKED[/bold green]",
            border_style="green"
        ))
        print_token("Verified Token (re-signed)", token, "green")
    else:
        console.print(Panel(
            f"[red]Secret not found in wordlist.[/red]\n"
            f"  Tried: {attempts:,} passwords in {elapsed:.2f}s",
            title="[red]✘ NOT CRACKED[/red]",
            border_style="red"
        ))


def display_kid_results(results: List[Dict[str, Any]]):
    """Display KID injection results."""
    print_section("KID Injection Payloads", "yellow")

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold yellow")
    table.add_column("Type", style="bold", width=20)
    table.add_column("Payload", style="cyan", width=40)
    table.add_column("Secret Used", style="magenta", width=20)

    for r in results:
        table.add_row(
            r.get('type', ''),
            r.get('kid_value', ''),
            r.get('secret', '')
        )

    console.print(table)
    console.print()

    for r in results:
        if r.get('token'):
            print_token(f"[{r['type']}]", r['token'], "yellow")
            console.print()
