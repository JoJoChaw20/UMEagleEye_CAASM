"""
Builds the labelled SBOM test set on a Linux VM (scripts/sbom-accuracy/README.md).

Every package in manifest.json is downloaded at its pinned version and UNPACKED as files
where the agent's SBOM run looks; nothing is installed or executed. Syft reads only the
metadata: Python *.dist-info, npm node_modules/*/package.json, Java jars, .NET *.deps.json.

    sudo python3 build-testset.py [--dest /opt/sbomtest]

Standard library only. Run again to rebuild from scratch (the folder is replaced).
"""
import argparse
import io
import json
import os
import shutil
import tarfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
UA = {'User-Agent': 'UMEagleEye-sbom-accuracy'}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
        return r.read()


def pypi(dest, name, version):
    meta = json.loads(get(f'https://pypi.org/pypi/{name}/{version}/json'))
    wheels = [u for u in meta['urls'] if u['packagetype'] == 'bdist_wheel' and u['filename'].endswith('-none-any.whl')]
    if not wheels:
        raise RuntimeError(f'{name} {version}: no pure-Python wheel')
    with zipfile.ZipFile(io.BytesIO(get(wheels[0]['url']))) as z:
        z.extractall(os.path.join(dest, 'python', 'site-packages'))


def npm(dest, name, version):
    data = get(f'https://registry.npmjs.org/{name}/-/{name.split("/")[-1]}-{version}.tgz')
    target = os.path.join(dest, 'node', 'node_modules', name)
    os.makedirs(target, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
        for m in t.getmembers():
            parts = m.name.split('/', 1)         # strip the tarball's top folder ("package/")
            if len(parts) < 2 or not parts[1] or m.issym() or m.islnk():
                continue
            m.name = parts[1]
            if os.path.isabs(m.name) or '..' in m.name.split('/'):
                continue                          # never write outside the package folder
            try:
                t.extract(m, target, filter='data')   # Python 3.12+ (and 3.10.12+/3.11.4+)
            except TypeError:
                t.extract(m, target)


def maven(dest, name, version):
    group, artifact = name.split(':')
    url = f'https://repo1.maven.org/maven2/{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}.jar'
    path = os.path.join(dest, 'java', 'lib', f'{artifact}-{version}.jar')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(get(url))


def nuget_app(dest, pkgs):
    """A .NET app folder: its deps.json lists the packages, and their DLLs sit beside it."""
    app = os.path.join(dest, 'dotnet', 'SbomTestApp')
    os.makedirs(app, exist_ok=True)
    tfm = '.NETCoreApp,Version=v6.0'
    targets = {'SbomTestApp/1.0.0': {'dependencies': {p['name']: p['version'] for p in pkgs},
                                     'runtime': {'SbomTestApp.dll': {}}}}
    libraries = {'SbomTestApp/1.0.0': {'type': 'project', 'serviceable': False, 'sha512': ''}}
    for p in pkgs:
        key = f"{p['name']}/{p['version']}"
        dll = None
        with zipfile.ZipFile(io.BytesIO(get(f"https://www.nuget.org/api/v2/package/{p['name']}/{p['version']}"))) as z:
            libs = [n for n in z.namelist() if n.lower().endswith('.dll') and n.lower().startswith('lib/netstandard2.0/')]
            if libs:
                dll = libs[0]
                with open(os.path.join(app, os.path.basename(dll)), 'wb') as f:
                    f.write(z.read(dll))
        targets[key] = {'runtime': {dll: {}} if dll else {}}
        libraries[key] = {'type': 'package', 'serviceable': True, 'sha512': '',
                          'path': key.lower(), 'hashPath': f"{p['name'].lower()}.{p['version']}.nupkg.sha512"}
    deps = {'runtimeTarget': {'name': tfm, 'signature': ''}, 'compilationOptions': {},
            'targets': {tfm: targets}, 'libraries': libraries}
    with open(os.path.join(app, 'SbomTestApp.deps.json'), 'w', encoding='utf-8') as f:
        json.dump(deps, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dest', default='/opt/sbomtest' if os.name != 'nt' else r'C:\Program Files\SbomTestSet')
    args = ap.parse_args()
    with open(os.path.join(HERE, 'manifest.json'), encoding='utf-8') as f:
        manifest = json.load(f)
    if os.path.exists(args.dest):
        shutil.rmtree(args.dest)
    os.makedirs(args.dest)

    ok, failed = 0, []
    for p in manifest['packages']:
        if p['ecosystem'] == 'NuGet':
            continue
        try:
            {'PyPI': pypi, 'npm': npm, 'Maven': maven}[p['ecosystem']](args.dest, p['name'], p['version'])
            ok += 1
            print(f"  ok  {p['ecosystem']:6} {p['name']} {p['version']}")
        except Exception as e:  # noqa: BLE001 - report and carry on
            failed.append(f"{p['name']} {p['version']}: {e}")
    nuget = [p for p in manifest['packages'] if p['ecosystem'] == 'NuGet']
    try:
        nuget_app(args.dest, nuget)
        ok += len(nuget)
        print(f'  ok  NuGet  {len(nuget)} packages in dotnet/SbomTestApp')
    except Exception as e:  # noqa: BLE001
        failed.append(f'NuGet app: {e}')

    with open(os.path.join(args.dest, 'MANIFEST.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    print(f'\n{ok} packages placed in {args.dest}' + (f'; FAILED: {failed}' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
