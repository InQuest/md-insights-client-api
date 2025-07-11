# md-insights-client-api

API client for MetaDefender InSights threat intelligence feeds.

## Installation

The app has been tested on Python 3.

It's best to install the program into a Python virtual environment. The
recommended way to install it is using [pipx](https://pypa.github.io/pipx/):

    pipx install md-insights-client

It can also be installed using [pip](https://pip.pypa.io/en/stable/) into a
target virtualenv.

    /path/to/environment/bin/python3 -m pip install md-insights-client

## Configuration

A configuration file must be populated with an API key. If only querying the API
to perform lookups, this configuration setting is all that is required. If
retrieving snapshots, a list of feed names to retrieve must also be specified.

A sample configuration file can be copied from `config/dot.md-insights.yml` and
installed at `$HOME/.md-insights.yml`. Update the configuration file to make
the following changes:

1. Set your API key.
2. Uncomment feed names for the MetaDefender InSights feeds you will access
   (if applicable).

Don't forget to set a restrictive mode on the file:

```
chmod 0600 ~/.md-insights.yml
```

## Usage

When installed, two commands are available.

### md-insights-query-client

The `md-insights-query-client` command can be used to query the MD InSights API
to look up artifacts against one or more threat intelligence collections.

See `-h/--help` output for help.

To use this command, provide multiple positional arguments to the script.

- The first argument is the **query type**, such as `c2-dns`, `c2-ip`,
  `reputation` or `all`. The special `all` type autodetects the artifact
  format(s) to query all relevant collections.
- The second and subsequent arguments are the artifacts for which to query.
  One or more artifacts such as IP addresses or domain names may be specified.

For example:

```
md-insights-query-client all appleprocesshub.com apimonger.com
```

By default, response data is output in tabular format, one indicator per row
that is found in MD InSights collections. If you prefer to see the raw JSON
response format from the API, use the `-j/--json` option.

### md-insights-snapshot-client

The `md-insights-snapshot-client` command can be used to download feed
snapshots. To retrieve feed snapshots, your API key must be provisioned with
access to the selected feeds.

See `-h/--help` output for help.

When the command is called, the client script downloads feed snapshots from the
API service. As the compressed snapshots are downloaded, they are decompressed
and the feeds are written to disk.

## Documentation

For information about MetaDefender InSights threat intelligence feeds, see the
documentation site:

<https://www.opswat.com/docs/mdinsights>
