# serviceDetector

Detect whether a service is installed (blindly) and/or running (if exposing named pipes) on a remote machine without using local admin privileges.

## About

In more detail, running this script connects to the target SMB service (445/tcp) remotely and does the following:

1. Checks if the specified **service is installed** through the [MS-LSAT] RPC call [LsarLookupNames()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/65d18faa-0cb2-40ee-a94a-2140212f4ec4).
There is no need to use a privileged account, but only "blind" query is possible (cannot list the services, we can only ask the state of a specific service).

2. Checks if the specified [Named Pipe](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes) exists on the target. Services (processes) may expose a named pipe characteristic to the service, which can
be seen by an unprivileged user. So checking specific named pipes characteristic to services may allow us to infer whether the specific **service
is running or not**.

## Installation

This is a standalone [Python](https://www.python.org/) script using [Impacket](https://github.com/fortra/impacket), no need to install anything.
Tested it on up-to-date [Kali](https://www.kali.org/) and [Arch Linux](https://archlinux.org/) using the latest official Impacket (0.10.0 and 0.9.24) and Python (3.9 and 3.10).

## Configuration

The services, service names to check, named pipes characteristic to the service are specified in JSON config files (or CSV files if it is more
comfortable, what I realized later :), so a custom csv2json converter is also available) in the [conf](./conf) folder. For understanding the format, see the examples included.

Config files included:

- [edr.json](./conf/edr.json) (and [edr.csv](./conf/edr.csv)): common AV/EDR services and named pipes
- [webclient.json](./conf/webclient.json) (and [webclient.csv](./conf/webclient.csv)): for detecting WebClient and Print Spooler on the target
(useful for my favorite [HTTP → LDAP NTLM relay computer takeover attack](https://twitter.com/an0n_r0/status/1616997725484232704)).
- [psexec.json](./conf/psexec.json) (and [psexec.csv](./conf/psexec.csv): for detecting uncleaned Impacket PsExec services running for
[SYSTEM RCE using an unprivileged domain user](https://twitter.com/bugch3ck/status/1626963208811470848).

Use cases may be extended by more services / named pipes, EDR config is quite incomplete, feel free to add more.

The script uses the JSON config format, but later I realized writing CSV is much more comfortable, so included the [csv2json.py](./conf/csv2json.py) script to convert the CSV to JSON.

## Running the tool

Running against a single target to enumerate AV/EDR services (or anything else) is straightforward:

```
./serviceDetector.py -conf conf/edr.json evil.corp/johndoe:Passw0rd1@server.ecorp.local
```

Kerberos authentication is also supported (KRB5CCNAME env var is pointing to the ccache file):

```
./serviceDetector.py -conf conf/edr.json -k -no-pass server.ecorp.local
```

For running against multiple targets effectively [GNU parallel](https://www.gnu.org/software/parallel/) is super useful:

```
cat targets.txt | parallel -j 50 ./serviceDetector.py evil.corp/johndoe:Passw0rd1@{}
```

Note that before running against a bunch of targets test against one in order to prevent account lockout (e.g. in the case of a misspelled password).

Opsec Note: be aware that concurrent mass login to different targets may trigger SOC alerts.

## Acknowledgments

The two techniques used here are not new.

1. [MS-LSAT] RPC call LsarLookupNames() was used earlier by [Vincent Le Toux](https://www.linkedin.com/in/vincentletoux/) ([@mysmartlogon](https://twitter.com/mysmartlogon))
in the Antivirusscanner module of the awesome [PingCastle](https://www.pingcastle.com/) tool.

2. The named pipe idea for detecting running services was inspired by [this tweet](https://twitter.com/tifkin_/status/1419806476353298442) from
[Lee Christensen](.https://www.linkedin.com/in/lee-christensen-6285bb47) ([@tifkin_](https://twitter.com/tifkin_)) when he used this for the WebClient service detection.
This technique for AV/EDR detection was also used by the NamedPipeTouch tool from NSA (leaked by The Shadow Brokers group).

