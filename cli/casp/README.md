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

    from casp.commands import hi
    from casp.commands import version
    from casp.commands import my_command  # Add this line

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
python -m unittest discover -s cli/casp/src/casp/tests -p '*_test.py' -v
```

## Writing Tests

To add tests for a new command or feature, create a new Python file in the
`cli/casp/src/casp/tests` directory. The file name should follow the pattern
`<feature_name>_test.py`.

Each test file should contain test classes that inherit from `unittest.TestCase`.
You can use `click.testing.CliRunner` to invoke your CLI commands in tests.

Here's an example for a `my-command` feature:

```python
# cli/casp/src/casp/tests/test_my_command.py

import unittest
from click.testing import CliRunner

from casp.commands import my_command

class MyCommandTest(unittest.TestCase):
  """Tests for the `my-command` CLI command."""

  def setUp(self):
    self.runner = CliRunner()

  def test_my_command_no_verbose(self):
    """Test `my-command` without the --verbose flag."""
    result = self.runner.invoke(my_command.cli)
    self.assertEqual(result.exit_code, 0)
    self.assertIn('This is my new command.', result.output)
    self.assertNotIn('Verbose logging is enabled.', result.output)

  def test_my_command_verbose(self):
    """Test `my-command` with the --verbose flag."""
    result = self.runner.invoke(my_command.cli, ['--verbose'])
    self.assertEqual(result.exit_code, 0)
    self.assertIn('Verbose logging is enabled.', result.output)
    self.assertIn('This is my new command.', result.output)
```