import os
import json
import sys

def list_files_in_directory(directory_path):
    cve_json = {}
    file_list = []
    # 디렉토리 내의 파일 목록을 가져옵니다.
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

def save_list_json_file(filepath, jsondata):
     with open(filepath, 'w') as f:
        json.dump(jsondata, f, indent=4)

def get_unique_directories(file_paths):
    # 각 파일 경로에서 디렉토리 경로를 추출합니다.
    directories = [os.path.dirname(path) for path in file_paths]

    # 중복을 제거하기 위해 set을 사용합니다.
    unique_directories = set(directories)

    # set을 리스트로 변환하여 반환합니다.
    return list(unique_directories)


changed_files = sys.argv[1]
file_list = [f.strip() for f in changed_files.split(',') if f.strip()]
print(f"All files changed in the last commit:{file_list}")


for directory in get_unique_directories(file_list):
    print(f"directory:{directory}, abspath: {os.path.abspath(directory)}")
    cve_json = list_files_in_directory(directory)
    save_list_json_file(os.path.join(directory, 'list.json'), cve_json)

