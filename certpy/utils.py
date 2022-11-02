from typing import List, Tuple

from rich.console import Console
from rich.table import Table


def print_table(title: str, columns: List[str], rows: List[Tuple]):
    tb = Table(title=title, title_justify="center")
    for col in columns:
        tb.add_column(col, no_wrap=True)

    for row in rows:
        tb.add_row(*row)

    console = Console()
    console.print(tb)
