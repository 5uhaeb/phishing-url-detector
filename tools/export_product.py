"""Export tracked source, pinned models and client reports with a checksum manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile, ZIP_DEFLATED

ROOT=Path(__file__).resolve().parents[1]


def export(output):
    output=output.resolve();output.mkdir(parents=True,exist_ok=True)
    if (ROOT/'.git').exists():
        names=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
        names=[name for name in names if name and (ROOT/name).is_file()]
        revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    else:
        saved=json.loads((ROOT/'DELIVERY_MANIFEST.json').read_text())
        names=[item['path'] for item in saved['files']]
        revision=saved['source_revision']
    excluded={'.git','.venv','node_modules','__pycache__','data','training_output','test-results','playwright-report','dist'}
    paths=[]
    for name in names:
        path=ROOT/name
        if not path.resolve().is_relative_to(ROOT):raise ValueError('Export path escaped source root')
        if any(part in excluded for part in Path(name).parts):continue
        if path.name.startswith('.env') and path.name!='.env.example':continue
        paths.append(name)
    expected=['launcher.py','START_LINKGUARD.cmd','backend/main.py','backend/models/xgboost.joblib',
              'frontend/index.html','reports/model_scores.csv','reports/model_improvements.pdf']
    if not all(name in paths for name in expected):raise ValueError('Stage all delivery files before exporting')
    manifest=dict(product='LinkGuard',delivery_date='2026-11-03',source_revision=revision,
        model='Preserved XGBoost; research ensemble not deployed',
        research_archive='research-archive-2026-11-03',
        files=[dict(path=name,bytes=(ROOT/name).stat().st_size,
                    sha256=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()) for name in sorted(paths)])
    archive=output/'LinkGuard-Source.zip'
    with ZipFile(archive,'w',compression=ZIP_DEFLATED,compresslevel=6) as delivery:
        for name in sorted(paths):delivery.write(ROOT/name,'LinkGuard/'+name)
        delivery.writestr('LinkGuard/DELIVERY_MANIFEST.json',json.dumps(manifest,indent=2))
    with ZipFile(archive) as delivery:
        if delivery.testzip() is not None:raise ValueError('ZIP integrity check failed')
    for name in ['model_scores.csv','model_improvements.pdf','model_improvements.png']:
        shutil.copy2(ROOT/'reports'/name,output/name)
    (output/'README_FIRST.txt').write_text(
        'LinkGuard client delivery\n\n1. Extract LinkGuard-Source.zip.\n'
        '2. Install Python 3.13 and double-click START_LINKGUARD.cmd.\n'
        '   First setup needs internet; later --offline analysis is supported.\n'
        '3. Open model_improvements.pdf for the two-page graphical report.\n'
        '4. model_scores.csv contains the exact metrics and evaluation status.\n\n'
        'The application ships the existing XGBoost model. Research improvements\n'
        'are labelled and are not represented as deployed results.\n'
        'Live application: https://phishing-url-detector-xi.vercel.app\n',encoding='utf-8')
    (output/'SHA256SUMS.txt').write_text('\n'.join(
        hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name
        for path in sorted(output.iterdir()) if path.is_file() and path.name!='SHA256SUMS.txt')+'\n')
    print(json.dumps(dict(archive=str(archive),files=len(paths),archive_mib=archive.stat().st_size/2**20,
                         revision=revision),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    export(parser.parse_args().output)
