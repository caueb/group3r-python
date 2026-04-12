"""Entry point for python -m group3r."""

import logging
import sys

from .cli import args_to_options, parse_args
from .runner import run


def main():
    parsed = parse_args()
    options = args_to_options(parsed)

    log_level = logging.DEBUG if options.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(name)s %(levelname)s: %(message)s",
    )

    run(options)


if __name__ == "__main__":
    main()
