import requests
import json
import re
import os
import shutil

from dulwich import porcelain
from dulwich.contrib.paramiko_vendor import ParamikoSSHVendor

REPO_LOCATION = "git@github.com:defenceapp/defenceblocklist.git"
CLONE_LOCATION = "/tmp/defenceblocklist"
GIT_AUTHOR = "Updater <no-reply@defenceblocker.app>"
PRIVATE_KEY_FILENAME = "/tmp/id_ed25519_defenceblocker"
BLOCKLIST_FILENAME = "blockList.json"
BLOCKLIST_FILE_PATH = f"{CLONE_LOCATION}/{BLOCKLIST_FILENAME}"
GIT_DEPLOY_KEY = f"-----BEGIN OPENSSH PRIVATE KEY-----\n" \
                 f"{os.environ['DEFENCEBLOCKER_DEPLOY_KEY']}\n" \
                 f"-----END OPENSSH PRIVATE KEY-----"

BLACKLIST_URL = "https://api.cryptoscamdb.org/v1/blacklist"

def fetch_domain_list(url):
    json_result = requests.get(url).json().get('result')
    domains = []
    for result in json_result:
        if re.match(r"\d+\.\d+\.\d+\.\d+", result):
            continue
        if result.startswith("www."):
            continue
        domains.append(f"*{result}")
    domains = list(set(domains))
    domains.sort()
    return domains


def main():

    blacklist_domains = fetch_domain_list(BLACKLIST_URL)

    content_blocker_json = [{
        "trigger": {
            "url-filter": ".*",
            "if-domain": blacklist_domains
        },
        "action": {
            "type": "block"
        }
    }]

    save_and_push_file(content_blocker_json)


def save_and_push_file(content_blocker_json):

    if os.path.exists(CLONE_LOCATION):
        shutil.rmtree(CLONE_LOCATION)

    with open(PRIVATE_KEY_FILENAME, 'w') as ssh_private_key:
        ssh_private_key.write(GIT_DEPLOY_KEY)

    blocklist_repo = porcelain.clone(REPO_LOCATION, vendor=ParamikoSSHVendor(),
                                     target=CLONE_LOCATION, key_filename=PRIVATE_KEY_FILENAME,
                                     errstream=porcelain.NoneStream())

    with open(BLOCKLIST_FILE_PATH, 'w') as content_blocker_file:
        json.dump(content_blocker_json, content_blocker_file, sort_keys=True, indent=4, separators=(',', ': '))

    if porcelain.status(blocklist_repo.path).unstaged:
        porcelain.add(blocklist_repo.path, paths=[BLOCKLIST_FILE_PATH])
        porcelain.commit(blocklist_repo.path, message="Update blockList.json",
                         author=GIT_AUTHOR,
                         committer=GIT_AUTHOR)
        porcelain.push(blocklist_repo.path, remote_location=REPO_LOCATION, refspecs="master",
                       vendor=ParamikoSSHVendor(), key_filename=PRIVATE_KEY_FILENAME, errstream=porcelain.NoneStream())


def pub_sub_trigger(data, context):
    main()


if __name__ == "__main__":
    main()
