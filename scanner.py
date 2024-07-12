import requests
import subprocess
import os   
import requests

#print(os.getenv("HOMEBREW_GITHUB_API_TOKEN"))
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
    print(f'Scanning {imageName}...')
    try:
        subprocess.run(['grype', f'drydock-prod.workiva.net/workiva/{imageName}', '--scope', 'all-layers', '--by-cve', '--only-fixed'], check=True)

    except subprocess.CalledProcessError as e:
        print(f'Error scanning {imageName}: {e}')
        return False
    return True

def main():
    print('Process Started')
    scanned= False
    count = 1
    repos=fetch_repos()
    print('Repositories fetched')
    for repo in repos:
        if repo['language'] == 'Dart' and repo['archived'] == False:
             if not repo['tags']:
                 print(f'{count}. {repo["name"]} - No tags found')
                 count+=1
                 continue
             latest_tag = get_latest_tag(repo['tags'])
             print(f'{count}. {repo["name"]}:{latest_tag}')
             scanned = scan_Repo(repo["name"],latest_tag)
             print('Scanning completed')
             count+=1


if __name__ == '__main__':
    main()
