# SBOM to CVE accuracy test

Measures the whole pipeline on a labelled test set: the agent's Syft run detecting packages,
Grype matching CVEs, and UMEagleEye raising alerts. The reference is OSV.dev (official
advisories aggregated by Google), not Grype itself.

## Files
| File | What it does |
|---|---|
| `manifest.json` | 24 pinned packages (PyPI, npm, Maven, NuGet): 17 known-vulnerable, 7 clean controls, plus one manual Windows program (7-Zip 19.00) as a known-gap check |
| `build-testset.py` | Linux: downloads the packages and unpacks them as files in `/opt/sbomtest` (nothing installed or run) |
| `build-testset.ps1` | Windows: the same into `C:\Program Files\SbomTestSet` |
| `compare.ts` | Read-only: fetches the OSV truth (saved with its date) and compares it with the VM's SBOM and alerts on staging |

## Steps
1. Snapshot each VM. Agent enrolled to **staging**, SBOM on for it, Syft and Grype installed, internet on.
2. Copy this folder to the VM and build the set:
   - Ubuntu: `sudo python3 build-testset.py`
   - Windows (Administrator): `powershell -ExecutionPolicy Bypass -File .\build-testset.ps1`, then install 7-Zip 19.00 from https://www.7-zip.org/a/7z1900-x64.msi
3. On the dashboard, open the VM's agent and **Run now** for SBOM; wait until the SBOM page shows the new run.
4. From `workers/`:
   ```
   npx esbuild scripts/sbom-accuracy/compare.ts --bundle --platform=node --format=cjs --outfile=.sbom-accuracy.cjs
   node .sbom-accuracy.cjs --target staging --host LAB-UBUNTU --out C:/FYP/AP2/eval
   node .sbom-accuracy.cjs --target staging --host LAB-WIN11 --truth C:/FYP/AP2/eval/sbom-accuracy-truth-<date>.json --out C:/FYP/AP2/eval
   ```
   Reuse the same `--truth` file for every VM so both are judged against the same advisories.
5. Restore the snapshots afterwards (and delete the test set's alerts on staging if wanted).

## Reading the result
- **Detection**: planted packages Syft found at the exact version.
- **Recall**: OSV vulnerabilities (a CVE, its GHSA and PYSEC ids counted once) that got an alert.
- **Precision**: alerts that are one of the package's OSV vulnerabilities.
- **Clean alerts**: alerts on the clean controls; should be 0.
- Every miss and every extra alert is listed for manual review: OSV and Grype's database can
  disagree on affected version ranges, so a disagreement is not automatically an error.
