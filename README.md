# md-insights-client-api

API client for MetaDefender InSights threat intelligence feeds.

## Installation

The app has been tested on Python 3.

It's best to install the program into a Python virtual environment. The
recommended way to install it is using [pipx](https://pypa.github.io/pipx/):

    pipx install md-insights-client

It can also be installed using `pip` into a target virtualenv.

    python3 -m pip install md-insights-client

## Configuration

A configuration file must be populated with an API key and a list of feed names to retrieve.

A sample configuration file can be copied from `config/dot.md-insights.yml` and
installed at `$HOME/.md-insights.yml`. Update the configuration file to make
the following changes:

1. Set your API key.
2. Uncomment feed names for the MetaDefender InSights feeds you wish to access.
   Your API key must be provisioned with access to the selected feeds.

Don't forget to set a restrictive mode on the file (0600).

## Usage

When installed, a command called `md-insights-snapshot-client` is available.

See `-h/--help` output for help.

When the command is called, the client script downloads feed snapshots from the
API service. As the compressed snapshots are downloaded, they are decompressed
and the feeds are written to disk.

## Documentation

For information about MetaDefender InSights threat intelligence feeds, see the
documentation site:

<https://www.opswat.com/docs/mdinsights>
