from rich.console import Console

console = Console()

def show_banner():
    console.print("""[bold cyan]
 _     _       _     ____  _     _      _     _ 
| |   (_)_ __ | | __/ ___|| |__ (_) ___| | __| |
| |   | | '_ \| |/ /\___ \| '_ \| |/ _ \ |/ _` |
| |___| | | | |   <  ___) | | | | |  __/ | (_| |
|_____|_|_| |_|_|\_\|____/|_| |_|_|\___|_|\__,_|
[/bold cyan]""")

    console.print("[bold green]LinkShield v1.0[/bold green]")
    console.print("[yellow]Analyze Links • Stay Safe[/yellow]")
    console.print("[dim]Developed by Youssef Mediouni[/dim]\n")
