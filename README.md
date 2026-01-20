# Windows-Admin-Center-Functions-Overview

## License Disclaimer (Microsoft WAC Scripts)
```
The Windows Admin Center PowerShell scripts included in the extracted modules are Microsoft-provided content. Per the WAC UI notice: "We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein. ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE."
```

## Scope and Licensing
- This repository contains two kinds of content:
  - Site code (HTML/CSS/JS, generator scripts, and data files): you are free to copy/modify/redistribute this as you like.
  - Extracted Windows Admin Center module content under `wac-modules-for-site/`: this remains Microsoft content and is subject to Microsoft/WAC license terms (see the notice above).

## AI Notice
```
The site UI, structure, and code in this repository were generated with AI assistance.
```

## Overview
An overview site for the PowerShell functions found within, and used by WAC (Windows Admin Center).

## Table of Contents
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Build and Run Guide](#build-and-run-guide)
- [Update Workflow](#update-workflow)
- [Hosting Notes](#hosting-notes)
- [Privacy and Security](#privacy-and-security)
- [Troubleshooting](#troubleshooting)
- [Attribution](#attribution)

## Repository Layout
- `index.html`: site entry point
- `styles.css`: site styling
- `app.js`: site logic (search, navigation, lazy code loading)
- `data.json`: generated index of modules/functions and file paths
- `assets/`: highlight.js assets used by the viewer
- `wac-modules-for-site/`: extracted WAC module content (`.psm1` and `.svg` only)
- `Extract-PowerShellModules.ps1`: extractor (run on a WAC install)
- `generate_data.py`: generator for `data.json`

## Requirements
- Windows Admin Center installed on a Windows machine (to extract modules).
- PowerShell (Windows PowerShell 5.1 or PowerShell 7+) to run `Extract-PowerShellModules.ps1`.
- Python 3 to run `generate_data.py` and/or serve locally.

## Build and Run Guide
1. Install Windows Admin Center.
2. Run the PowerShell extractor to generate the module folder:
   - `Extract-PowerShellModules.ps1` creates `wac-modules-for-site/` with `.psm1` and `.svg` files only.
3. Generate `data.json`:
   - `python generate_data.py`
4. Serve the site:
   - `python -m http.server` (or any static server such as nginx).

## Update Workflow
1. Re-run `Extract-PowerShellModules.ps1` against your WAC install.
2. Re-run `python generate_data.py`.
3. Commit changes to `wac-modules-for-site/` and `data.json`.

## Hosting Notes
- GitHub Pages and other static hosts work.
- The site fetches `.psm1` and `.svg` files at runtime, so it must be served over HTTP(S). Opening `index.html` via `file://` will typically break loading.
- Do not use an underscore-prefixed modules folder name on GitHub Pages (Jekyll can ignore `_...` directories). This repo uses `wac-modules-for-site/` to avoid that.

## Privacy and Security
- The viewer runs entirely client-side and does not include telemetry.
- You are serving PowerShell source code. Treat it as sensitive if it contains environment-specific details in your WAC install.

## Troubleshooting
- Icons or code not loading: confirm `wac-modules-for-site/` exists at the repo root and `data.json` points to the correct paths.
- “No code found.”: the function parser may not detect some edge cases; try a different function or open an issue with the module + function name.
- GitHub Pages missing files: ensure the modules folder is not underscore-prefixed and that the files are actually committed.

## Attribution
- Microsoft notice text was taken from the Windows Admin Center UI section labeled "PowerShell scripts use rights".
