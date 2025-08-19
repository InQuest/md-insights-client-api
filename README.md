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

When installed, three commands are available.

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

#### Pushing to Anomali ThreatStream

The query client can automatically push enrichment data to Anomali ThreatStream.
Use the `--push-to-threatstream` flag or configure `anomali_auto_push: true` in
your configuration file. See the Anomali ThreatStream Integration section below
for configuration details.

### md-insights-snapshot-client

The `md-insights-snapshot-client` command can be used to download feed
snapshots. To retrieve feed snapshots, your API key must be provisioned with
access to the selected feeds.

See `-h/--help` output for help.

When the command is called, the client script downloads feed snapshots from the
API service. As the compressed snapshots are downloaded, they are decompressed
and the feeds are written to disk.

### md-insights-threatstream

The `md-insights-threatstream` command is a dedicated tool for enriching
Anomali ThreatStream with MD InSights threat intelligence data.

This command queries MD InSights for threat intelligence about specified IOCs
(IP addresses and domain names) and automatically pushes the enrichment data
to your ThreatStream instance.

Features:
- Queries both reputation and C2 data from MD InSights
- Creates or updates indicators in ThreatStream
- Adds enrichment tags based on threat intelligence findings
- Supports dry-run mode for previewing enrichments
- Configurable TLP (Traffic Light Protocol) settings

Example usage:

```bash
# Enrich a single IOC
md-insights-threatstream malicious.example.com

# Enrich multiple IOCs
md-insights-threatstream 192.168.1.1 evil.domain.com suspicious.site.net

# Dry run to preview enrichments without pushing
md-insights-threatstream --dry-run malicious.example.com

# Override configuration settings
md-insights-threatstream --tlp red --source-name "Custom_Source" evil.domain.com
```

## Anomali ThreatStream Integration

The MD InSights client now includes integration with Anomali ThreatStream,
allowing you to automatically push threat intelligence enrichments from
MD InSights to your ThreatStream instance.

### Configuration

Add the following settings to your `~/.md-insights.yml` configuration file:

```yaml
# Anomali ThreatStream integration settings
anomali_api_key: "username:apikey"  # Your ThreatStream API credentials
anomali_api_url: "https://api.threatstream.com/api/v2"  # ThreatStream API URL
anomali_auto_push: false  # Auto-push enrichments when querying (default: false)
anomali_tlp: "amber"  # Traffic Light Protocol setting (white/green/amber/red)
anomali_source_name: "OPSWAT_MDInSights"  # Source name in ThreatStream
```

### How It Works

1. **Query MD InSights**: The tool queries MD InSights for reputation and C2 data
2. **Process Intelligence**: Enrichment data is processed and confidence scores calculated
3. **Create/Update Indicators**: IOCs are created or updated in ThreatStream
4. **Add Enrichment Tags**: Intelligence findings are added as tags to indicators

Enrichment tags include:
- Reputation scores (e.g., `md-insights-reputation-8`)
- Malicious indicators (e.g., `md-insights-malicious`)
- Intelligence sources (e.g., `md-insights-source-insights-ti`)
- C2 attribution (e.g., `md-insights-c2-APT_28`)

### Authentication

You can provide ThreatStream API credentials in three ways:
1. Configuration file (recommended)
2. Environment variables: `ANOMALI_API`, `ANOMALI_URL`, `ANOMALI_TLP`, `ANOMALI_SOURCE`
3. Command-line arguments: `--api-key`, `--api-url`, `--tlp`, `--source-name`

## Documentation

For information about MetaDefender InSights threat intelligence feeds, see the
documentation site:

<https://www.opswat.com/docs/mdinsights>
