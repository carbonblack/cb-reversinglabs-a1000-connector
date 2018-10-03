# Carbon Black - ReversingLabs A1000 Connector

The ReversingLabs A1000 connector submits binaries collected by Carbon Black to ReversingLabs
for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black server. The feed will then tag any binaries executed on your
endpoints identified as malware by ReversingLabs. Only binaries submitted by the A1000 connector
for analysis will be included in the generated Intelligence Feed.

**To use the A1000 connector, you must have a ReversingLabs Private API key. You cannot use a ReversingLabs
Public API key as the Public API is severely rate limited.** You can
apply for a private API key through the ReversingLabs web interface. ReversingLabs Private API keys
are only available via a paid subscription to ReversingLabs.

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-reversinglabs-a1000-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/reversinglabs-a1000/connector.conf.example` file to
`/etc/cb/integrations/reversinglabs-a1000/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for ReversingLabs into the configuration file: place API token
into the `reversinglabs_api_username` and `reversignlabs_api_password` variables in the
`/etc/cb/integrations/reversinglabs-a1000/connector.conf` file.

Any errors will be logged into `/var/log/cb/integrations/reversinglabs-a1000/reversinglabs.log`.

## Additional Configuration Options

### Full Binary Submission

To enable FULL binary submission, change `reversinglabs_deep_scan_threads` to a value greater than 0. We recommend 1 or 2 threads.
You must also add the `submit_full_binaries` option and set it to 1.  These options need to be changed in the `connector.conf` file.
A copy of these options is shown below:

If you are upgrading from an earlier version to 1.0.5 or newer, uploading binaries to ReversingLabs is *automatically* disabled until
you explicitly enable it by adding the `submit_full_binaries=1` option described above into your configuration file.

## Troubleshooting

If you suspect a problem, please first look at the ReversingLabs A1000 connector logs found here:
`/var/log/cb/integrations/reversinglabs-a1000/reversinglabs.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-reversinglabs-a1000-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/reversinglabs-a1000/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-reversinglabs-a1000-connector start`

## Contacting Carbon Black Developer Relations Support

Web: https://community.carbonblack.com/groups/developer-relations
E-mail: dev-support@bcarbonblack.com

### Reporting Problems

When you contact Carbon Black Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM)
* For documentation issues, specify the version of the manual you are using.
* Action causing the problem, error message returned, and event log output (as appropriate)
* Problem severity

