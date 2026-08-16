# SECPIPE.sh

A Bash-based security scanning pipeline that chains four tools together into one interactive script: nmap, nikto, nuclei, and ffuf.

## What it does

The script runs a full scan of a target in stages. Each stage uses the results of the earlier stages, so you do not need to copy output between tools by hand.

1. **nmap** scans the target for open ports and services, and builds a list of web services found.
2. **nikto** scans the web services found by nmap for common vulnerabilities.
3. **nuclei** runs template-based vulnerability checks against the same web services.
4. **ffuf** fuzzes the web services to discover hidden paths and files.

## How it works

- The script is menu-driven. When you run it, you choose options from numbered menus instead of typing command-line flags.
- Some settings are asked as free text, such as a target IP or hostname, and are checked before use.
- A few flags are always turned on for every scan, with a comment in the code explaining why.
- Each tool follows the same structure in the code:
  - a function that asks you how to configure the scan
  - a function that runs the scan
  - a function that reads the results and pulls out the useful findings

This keeps every tool in the pipeline consistent and easy to extend.

## Output files

- nmap: normal, XML, and grepable output files, plus a list of discovered web services (`web_services.txt`)
- nikto: scan output following the same pattern as nmap
- nuclei: JSON lines output, plus a clear message when zero findings are found (so an empty result is not confused with a broken run)
- ffuf: JSON output with a fallback text log if JSON parsing fails, plus a `ffuf_notable.txt` file that lists the most interesting results first (working pages, then restricted pages, then redirects)

## Requirements

- Bash
- nmap
- nikto
- nuclei
- ffuf
- jq

## Usage
chmod +x SECPIPE.sh &&
./SECPIPE.sh


Follow the on-screen menus to configure and run each stage.
