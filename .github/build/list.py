import os
import json
import sys
import re
from datetime import datetime

def list_files_in_directory(directory_path):
    """list.json용 - CVE-ID와 published_date만 추출"""
    cve_json = {}
    file_list = []
    files = os.listdir(directory_path)
    filtered_files = [file for file in files if file.startswith('CVE') and file.endswith('.json')]

    for item in filtered_files:
        json_data = {}
        with open(os.path.join(directory_path, item), 'r', encoding='utf-8') as jsonfile:
            data = json.load(jsonfile)
            json_data["id"] = data.get("CVE-ID").strip()
            json_data["published_date"] = data.get("published_date").strip()

        file_list.append(json_data)

    cve_json['cve_list'] = file_list
    return cve_json

def normalize_whitespace(obj):
    """JSON 객체 내 연속 공백을 단일 공백으로 변환"""
    if isinstance(obj, dict):
        return {k: normalize_whitespace(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [normalize_whitespace(item) for item in obj]
    elif isinstance(obj, str):
        return re.sub(r' {2,}', ' ', obj)
    return obj

def get_full_cve_list(directory_path):
    """cves.json용 - 전체 CVE 데이터 통합"""
    cve_list = []
    files = os.listdir(directory_path)
    filtered_files = [file for file in files if file.startswith('CVE') and file.endswith('.json')]

    for item in filtered_files:
        with open(os.path.join(directory_path, item), 'r', encoding='utf-8') as jsonfile:
            data = json.load(jsonfile)
            data = normalize_whitespace(data)
            cve_list.append(data)

    return {"CVE-LIST": cve_list}

def save_json_file(filepath, jsondata):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(jsondata, f, indent=4, ensure_ascii=False)

def get_unique_directories(file_paths):
    """파일 경로 목록에서 중복 없는 디렉토리 목록 추출"""
    directories = [os.path.dirname(path) for path in file_paths]
    unique_directories = set(directories)
    return list(unique_directories)

def get_all_software_years(root_path):
    """전체 소프트웨어/연도 구조 스캔"""
    software_years = {}
    exclude_dirs = ['.git', '.github', '.idea']

    for item in os.listdir(root_path):
        item_path = os.path.join(root_path, item)
        if os.path.isdir(item_path) and item not in exclude_dirs:
            years = []
            for year in os.listdir(item_path):
                year_path = os.path.join(item_path, year)
                if os.path.isdir(year_path) and year.isdigit():
                    # cves.json 파일의 수정 시간 확인
                    cves_file = os.path.join(year_path, 'cves.json')
                    if os.path.exists(cves_file):
                        mtime = os.path.getmtime(cves_file)
                        updated = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d')
                    else:
                        updated = datetime.now().strftime('%Y-%m-%d')
                    years.append({"year": year, "updated": updated})

            if years:
                years.sort(key=lambda x: x["year"])
                software_years[item] = years

    return software_years

def count_cves(root_path, software, year):
    """해당 연도의 CVE 개수 반환"""
    year_path = os.path.join(root_path, software, year)
    files = os.listdir(year_path)
    return len([f for f in files if f.startswith('CVE') and f.endswith('.json')])

def generate_readme(root_path):
    """README.md 자동 생성"""
    software_years = get_all_software_years(root_path)

    readme_content = """<div align="center">

# OpenLENA Security Vulnerability Database

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-ATLENA-black?logo=github)](https://github.com/ATLENA)

**OpenLENA Manager에서 사용하는 보안 취약점(CVE) 데이터 저장소입니다.**

각 소프트웨어별 보안 취약점 정보를 JSON 형식으로 제공합니다.

---

</div>

## About

이 저장소는 OpenLENA에서 관리하는 주요 오픈소스 소프트웨어의 보안 취약점(CVE) 정보를 담고 있습니다.
Manager 애플리케이션에서 자동으로 다운로드하여 보안 점검에 활용할 수 있습니다.

## Download Links

"""

    for software in sorted(software_years.keys()):
        readme_content += f"### {software.upper()}\n\n"
        readme_content += "| Year | Download | CVEs | Last Updated |\n"
        readme_content += "|:----:|:--------:|:----:|:------------:|\n"
        for item in software_years[software]:
            year = item["year"]
            updated = item["updated"]
            cve_count = count_cves(root_path, software, year)
            readme_content += f"| {year} | [cves.json](./{software}/{year}/cves.json) | {cve_count} | {updated} |\n"
        readme_content += "\n"

    readme_content += """## File Structure

```
├── apache/
│   ├── 2024/
│   │   ├── CVE-2024-xxxxx.json   # 개별 CVE 파일
│   │   ├── list.json             # CVE 목록 (ID, 날짜만)
│   │   └── cves.json             # 전체 CVE 데이터 통합
│   └── 2025/
├── nginx/
├── redis/
└── tomcat/
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**[OpenLENA](https://github.com/ATLENA)** - Open Source Enterprise Solution

</div>
"""

    readme_path = os.path.join(root_path, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    print(f"README.md updated: {readme_path}")


def get_all_cve_directories(root_path):
    """전체 CVE 디렉토리 목록 반환"""
    cve_directories = []
    exclude_dirs = ['.git', '.github', '.idea']

    for software in os.listdir(root_path):
        software_path = os.path.join(root_path, software)
        if os.path.isdir(software_path) and software not in exclude_dirs:
            for year in os.listdir(software_path):
                year_path = os.path.join(software_path, year)
                if os.path.isdir(year_path) and year.isdigit():
                    cve_directories.append(year_path)

    return cve_directories

def generate_json_files(directory):
    """디렉토리에 list.json, cves.json 생성"""
    print(f"directory: {directory}")

    # list.json 생성 (간략 목록)
    cve_json = list_files_in_directory(directory)
    if len(cve_json['cve_list']) > 0:
        list_file_path = os.path.join(directory, 'list.json')
        print(f"save file: {list_file_path}")
        save_json_file(list_file_path, cve_json)

        # cves.json 생성 (전체 데이터)
        full_cve_json = get_full_cve_list(directory)
        cves_file_path = os.path.join(directory, 'cves.json')
        print(f"save file: {cves_file_path}")
        save_json_file(cves_file_path, full_cve_json)


# 메인 실행
root_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if len(sys.argv) > 1 and sys.argv[1] == '--all':
    # --all: 전체 디렉토리에 생성
    print("Generating all JSON files...")
    for directory in get_all_cve_directories(root_path):
        generate_json_files(directory)
else:
    # 기본: 변경된 파일 기반으로 생성
    changed_files = sys.argv[1] if len(sys.argv) > 1 else ""
    file_list = [f.strip() for f in changed_files.split(',') if f.strip()]
    print(f"All files changed in the last commit: {file_list}")

    for directory in get_unique_directories(file_list):
        generate_json_files(directory)

# README.md 업데이트
generate_readme(root_path)

