# mtr - Windows Console MTR Tool

A command-line network diagnostic tool for Windows that combines the functionality of `ping` and `traceroute`, similar to the Linux `mtr` command.

**No administrator privileges required!**

## Features

- 🚀 **Parallel probing** - All hops are probed simultaneously for fast results
- 📊 **Real-time statistics** - Loss%, Last/Avg/Best/Worst RTT, Standard Deviation
- 🔍 **DNS resolution** - Forward and reverse hostname lookup
- 🖥️ **Console-based** - Works in cmd and PowerShell, no GUI
- 🔓 **No admin required** - Uses Windows IcmpSendEcho API

## Installation

### Download
Download the latest release from [Releases](https://github.com/yourusername/mtr/releases).

### Build from source
```powershell
git clone https://github.com/yourusername/mtr.git
cd mtr
cargo build --release
```

The executable will be at `target/release/mtr.exe`.

## Usage

```powershell
# Basic usage (continuous mode, Ctrl+C to exit)
mtr 8.8.8.8
mtr google.com

# Report mode (run N cycles and exit)
mtr -r -C 10 8.8.8.8

# No DNS resolution (faster, IP only)
mtr -n 8.8.8.8

# Custom timeout and interval
mtr -t 300 -i 200 8.8.8.8
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --count <N>` | Number of pings per hop (0 = unlimited) | 0 |
| `-i, --interval <MS>` | Interval between cycles in ms | 500 |
| `-m, --max-ttl <N>` | Maximum number of hops | 30 |
| `-n, --no-dns` | Do not resolve hostnames | false |
| `-r, --report` | Report mode: print final report and exit | false |
| `-C, --report-cycles <N>` | Report mode cycle count | 10 |
| `-t, --timeout <MS>` | Ping timeout in ms | 500 |

## Example Output

```
mtr to 8.8.8.8 (8.8.8.8)
    Host                                           Loss%   Snt   Last    Avg   Best   Wrst  StDev
  1. 192.168.0.1                                     0.0%    10    1.0    1.2    0.0    3.0    0.8
  2. 192.168.1.1                                     0.0%    10    2.0    2.1    1.0    4.0    0.9
  3. ???                                           100.0%    10    ---    ---    ---    ---    ---
  4. 10.0.0.1                                        0.0%    10    5.0    5.3    4.0    7.0    0.8
  ...
 12. 8.8.8.8                                         0.0%    10   44.0   45.2   43.0   48.0    1.5
```

## How It Works

Unlike raw socket implementations that require administrator privileges, this tool uses the Windows `IcmpSendEcho` API through the [winping](https://crates.io/crates/winping) crate. This API is specifically designed for ICMP operations and works without elevated privileges.

The tool sends ICMP Echo Request packets with incrementing TTL values. Intermediate routers respond with "TTL Expired" messages, allowing the tool to discover the path to the target.

## Dependencies

- [winping](https://crates.io/crates/winping) - Windows ICMP without admin
- [clap](https://crates.io/crates/clap) - Command-line argument parsing
- [dns-lookup](https://crates.io/crates/dns-lookup) - DNS resolution
- [ctrlc](https://crates.io/crates/ctrlc) - Ctrl+C handling

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
