# Casp: The ClusterFuzz CLI

Casp is a new, modern Command-Line Interface (CLI) for ClusterFuzz that
provides an organized, extensible, and user-friendly way to interact with
ClusterFuzz locally.

## Structure

The CLI is organized into the following structure:

-   `casp/main.py`: The entry point for the CLI. It uses the `click` library to
    create a multi-command CLI that loads commands
    from the `casp/commands` directory.
-   `casp/commands/`: This directory contains the implementation of each CLI
    command, with each command in its own file.
-   `casp/utils/`: This directory contains utility functions and classes that are
    shared across multiple commands.

## Adding a New Command

To add a new command, you need to create a new Python file in the
`src/casp/commands` directory and then import it into `src/casp/main.py`.

For example, to add a `my-command` command, follow these steps:

1.  Create a new file named `my_command.py` in the `src/casp/commands`
    directory with the following content:

    ```python
    # src/casp/commands/my_command.py

    import click

    @click.command(name='my-command', help='This is my new command.')
    @click.option('--verbose', is_flag=True, help='Enables verbose logging.')
    def cli(verbose):
      """My new command."""
      if verbose:
        click.echo('Verbose logging is enabled.')
      click.echo('This is my new command.')
    ```

2.  Import the new command in `src/casp/main.py` and add it to the `cli`
    group:

    ```python
    # src/casp/main.py

    import click

    from .commands import hi
    from .commands import version
    from .commands import my_command  # Add this line

    @click.group()
    def cli():
      """A new, modern Command-Line Interface (CLI) for ClusterFuzz."""

    cli.add_command(hi.cli)
    cli.add_command(version.cli)
    cli.add_command(my_command.cli)  # Add this line
    ```

Once you have completed these steps, the new command will be available as
`casp my-command`.

## Running Tests

To run all unit tests for the `casp` CLI, use the following command from the root of the project:

```bash
python -m unittest discover -s cli/casp/src/casp/tests -v
```