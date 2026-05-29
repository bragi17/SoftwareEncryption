# SKey Software Encryption

English | [中文](README.zh-CN.md)

SKey Software Encryption is a Windows-oriented software protection and licensing toolkit. It protects Python applications, JAR files, EXE files, and other compiled single-file artifacts with encrypted payloads, runtime checks, customer key binding, a desktop studio, a CLI builder, and an optional license server.

## Highlights

- Python project protection: build a protected release from a Python source folder while preserving the original folder layout.
- Sentinel-style Python output: runnable files such as `model_server.py` stay as launchers, and protected source sidecars are emitted as `*_r.py`.
- Single-file wrapping: protect an existing JAR, EXE, or compiled artifact and produce a same-name launcher plus runtime files.
- Customer key licensing: each release includes `skey.key`; the first customer run binds it to the local machine fingerprint.
- Time policy support: generate time-limited or perpetual licenses.
- Desktop workflow: PySide6 Studio UI for scanning, configuration, building, activation, diagnostics, help, and English/Chinese switching.
- Optional license server: online activation, lease renewal, offline activation, and revocation for centrally managed deployments.

## Repository Status

This repository contains the product source implementation and packaging scripts. Internal planning documents, test harnesses, generated artifacts such as `dist/`, `build/`, virtual environments, encrypted packages, binaries, local databases, and caches are intentionally omitted from the public tree.

## Quick Start

### Desktop Studio

After building the tools, run:

```powershell
dist\skey-studio.exe
```

From a source checkout, you can run:

```powershell
.\.venv\Scripts\python.exe -m skeystudio
```

### Protect a Python Project

1. Open `skey-studio.exe`.
2. On the Project page, select or paste the Python project folder.
3. Click Scan Project.
4. Review the product metadata, startup entry, protected scope, and license time policy.
5. Save the generated `skey.yaml` in the project root.
6. On the Build page, choose the source folder, config file, and release output folder.
7. Build the protected release.
8. Ship the whole output folder to the customer, including the root-level `skey.key`.

On first run, `skey.key` is bound to the customer's machine fingerprint. Later runs require the same key file and a matching machine fingerprint.

### Protect a Single JAR, EXE, or Compiled Artifact

In Studio, select a single file as the source path on the Build page. The config file may be left empty. The default output is a sibling `-p` folder.

CLI example:

```powershell
.\dist\skey-protect.exe wrap-file --input "<ARTIFACT_FILE>" --out "<PROTECTED_OUTPUT_DIR>"
```

Add `--require-windows-linux-runtime` when the release must contain both Windows
DLLs and Linux SO files. The command fails with a missing-file message if either
target is incomplete.

Run the protected JAR:

```powershell
java -jar "<PROTECTED_OUTPUT_DIR>\<ORIGINAL_FILE_NAME>.jar"
```

For Docker deployments, copy the protected launcher, `.secure` folder, and `skey.key`
into the directory mounted into the backend container, for example `runtime/app`.
The container must start the protected JAR. Windows `.dll` and Linux `.so` runtime
files may coexist in `.secure/rt`; the loader chooses the file for the current OS.
Linux containers require `libskey_jni.so` and, for Python/runtime use,
`libskey_rt.so`.

## CLI Usage

Create a starter config:

```powershell
.\dist\skey-protect.exe init-config --path "C:\path\to\project\skey.yaml"
```

Build a protected Python release:

```powershell
.\dist\skey-protect.exe build --config "C:\path\to\project\skey.yaml" --project "C:\path\to\project" --out "C:\path\to\project-p"
```

Inspect a protected payload:

```powershell
.\dist\skey-protect.exe inspect "C:\path\to\project-p\.secure\payload.skp"
```

Verify a release runtime manifest:

```powershell
.\dist\skey-protect.exe verify-runtime "C:\path\to\project-p"
```

## Licensing Models

### Offline Customer Key Flow

This is the default low-friction flow and does not require pre-registration on a license server.

1. The builder writes `skey.key` into the protected release root.
2. The operator ships the protected release and `skey.key` to the customer.
3. The first run reads `skey.key` and binds it to the current machine.
4. Later runs verify the key signature, package metadata, license time policy, and machine fingerprint.

Important limitation: if an unbound `skey.key` is copied before the first legitimate run, the first machine that runs it becomes the bound machine. Use pre-bound machine codes or the license server flow when stricter control is required.

### Optional License Server Flow

The license server is for deployments that need central control after delivery:

- product, package, and license-code registration;
- online activation;
- lease renewal and expiry enforcement;
- license, package, or machine revocation;
- offline request/response activation for isolated machines.

If you only use the `skey.key` first-run binding flow, customers do not need to be registered on the license server before building a release.

## Project Layout

```text
python/
  skeyprotect/      CLI builder, config models, release generation
  skeystudio/       PySide6 desktop Studio
  skeyserver/       Optional license server
rust/
  crates/           Runtime core, FFI, JNI, and wrapper components
java/
  skey-loader/      Java loader for protected JAR launches
scripts/            Packaging and helper scripts
packaging/          PyInstaller specs
```

## Development

Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

Run static checks and native runtime verification:

```powershell
.\.venv\Scripts\python.exe -m ruff check python
.\.venv\Scripts\python.exe -m mypy python
cargo test --manifest-path rust\Cargo.toml
```

Build Windows release tools:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-release-tools.ps1 -VendorPublicKeySha256 <runtime-public-key-sha256>
```

If Linux runtime artifacts are present under `rust/target/release` or
`rust/target/x86_64-unknown-linux-gnu/release`, the packaging script also copies
`libskey_ffi.so` and `libskey_jni.so` into `dist/`. Protected releases built from
that `dist/` folder will include the Linux `.so` files alongside the Windows DLLs.

## Security Notes

- Never commit production signing keys, server secrets, admin tokens, or GitHub tokens.
- `allow_unsafe_dev_signing_key` is intended for local testing only.
- Replace development signing material before delivering a production release.
- Keep generated `dist/`, `build/`, local databases, encrypted package files, and runtime output out of source control.
- For commercial deployments, consider pre-bound machine codes or server-approved activation instead of first-run binding.

## License

This project is licensed under the [MIT License](LICENSE).
