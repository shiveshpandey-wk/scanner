import requests
import subprocess
import os   
import json

HEADER = {'Authorization': f'token {os.getenv("HOMEBREW_GITHUB_API_TOKEN")}'}

def fetch_repos():
    print('Fetching repositories...')
    repos = []
    page = 1
    total = 0

    while True:
        url = f'https://api.github.com/orgs/Workiva/repos?per_page=100&page={page}'
        response = requests.get(url, headers=HEADER)
        response.raise_for_status()
        data = response.json()
        if not data:
            break

        data = [repo for repo in data if repo['name'].startswith('sa-tools')]
        repos.extend([
            {
                'name': repo['name'],
                'url': repo['html_url'],
                'language': repo['language'],
                'archived' : repo['archived'],
                'tags': repo['tags_url']
            }
            for repo in data
        ])
        total += len(data)
        print('.', end='', flush=True)
        page += 1

    return repos

def get_latest_tag(tags_url):
    if not tags_url:
        return 'tag url not found'
    response = requests.get(tags_url, headers=HEADER)
    response.raise_for_status()
    tags = response.json()
    if not tags:
        return 'No tags'
    latest_tag = tags[0]['name']
    return latest_tag


#grype drydock-prod.workiva.net/workiva/sa-tools-changeset-service:1.1.891 --scope all-layers --by-cve --only-fixed
def scan_Repo(name, tag):
    if tag == 'No tags':
        print('Can not be Scanned')
        return False
    imageName = f'{name}:{tag}'
    try:
        command = ['grype', f'drydock-prod.workiva.net/workiva/{imageName}', '--scope', 'all-layers', '--by-cve', '--only-fixed','-o','json']

        result = subprocess.run(command,capture_output=True,text=True, check=True)
        if result.returncode == 0:
            grype_output = json.loads(result.stdout)
        else:
            print(f'Error scanning {imageName}')

        rows =[]
        
        for match in grype_output.get('matches', []):
            versions = []
            artifact = match.get('artifact', {})
            vulnerability = match.get('vulnerability', {})
            fix = vulnerability.get('fix', {})
            if not fix:
                continue
            else:
                versions = fix.get('versions', [])
            row = {
                'NAME': name,
                'PACKAGE': artifact.get('name') != None and artifact.get('name') or 'N/A',
                'INSTALLED': artifact.get('version') != None and artifact.get('version') or 'N/A',
                'FIXED IN' : versions != None and versions[0] or 'N/A',
                'TYPE' : artifact.get('type') != None and artifact.get('type') or 'N/A',
                'VULNERABILITY': vulnerability.get('id') != None and vulnerability.get('id') or 'N/A',
                'SEVERITY': vulnerability.get('severity') != None and vulnerability.get('severity') or 'N/A'
            }
            rows.append(row)

        if not grype_output.get('matches', []):
            row = {
                'NAME': name,
                'PACKAGE': 'No Vulnerabilities Found',
                'INSTALLED': 'N/A',
                'FIXED IN' : 'N/A',
                'TYPE' : 'N/A',
                'VULNERABILITY': 'N/A',
                'SEVERITY': 'N/A'
            }
            rows.append(row)

        with open(f'grype_output.csv', 'a') as csvfile:
            if not os.path.getsize(csvfile.name):
                csvfile.write('NAME,PACKAGE,INSTALLED,FIXED IN,TYPE,VULNERABILITY,SEVERITY\n')
            for row in rows:
                csvfile.write(f"{row['NAME']},{row['PACKAGE']},{row['INSTALLED']},{row['FIXED IN']},{row['TYPE']},{row['VULNERABILITY']},{row['SEVERITY']}\n")

    except subprocess.CalledProcessError as e:
        print(f'Error scanning {imageName}: {e}')
        return False
    except subprocess.JSONDecodeError as e:
        print(f'Error parsing JSON output for {imageName}: {e}')
        return False

    return True

def main():
    print('Process Started')
    scanned= False
    count = 1
    repos=fetch_repos()
    print('Repositories fetched')
    for repo in repos:
        if repo['archived'] == False:
             if not repo['tags']:
                 print(f'{count}. {repo["name"]} - No tags found')
                 count+=1
                 continue
             latest_tag = get_latest_tag(repo['tags'])
             print(f'{count}.----------------{repo["name"]}:{latest_tag}-Scanning started----------------')
             scanned = scan_Repo(repo["name"],latest_tag)
             if scanned:
                 print(f'{count}.----------------{repo["name"]}:{latest_tag}-Scanning completed----------------')
             else:
                 print(f'{count}.----------------{repo["name"]}:{latest_tag}-Scanning failed----------------')
             count+=1


if __name__ == '__main__':
    main()
