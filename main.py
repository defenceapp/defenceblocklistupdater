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

BLACKLIST_URL = "https://etherscamdb.info/api/blacklist/"
WHITELIST_URL = "https://etherscamdb.info/api/whitelist/"

TARGETED_DOMAINS = [
    ("myetherwallet", "com", 2),
    ("kraken", "com", 1),
    ("mycrypto", "com", 1),
    ("shapeshift", "com", 1),
    ("poloniex", "com", 1),
    ("bitfinex", "com", 1),
    ("blockchain", "com", 1),
    ("coindesk", "com", 1),
    ("coindash", "io", 1),
    ("cobinhood", "com", 1),
    ("coinbase", "com", 1),
    ("bitstamp", "net", 1),
    ("bittrex", "com", 0),
    ("bitmex", "com", 0),
    ("etherdelta", "com", 1),
    ("hitbtc", "com", 0),
    ("electrum", "org", 1),
    ("airswap", "io", 0),
    ("ethfinex", "com", 1),
]

COMMON_SUBS = {

    "a": ("e",),
    "e": ("a",),
    "w": ("v",),
    "l": ("i", "1", "t"),
    "n": ("m",),
    "m": ("n",),
    "i": ("l", "1", "t"),
}


def all_possible_subs(domain, subs):
    domains = set()
    for i in range(len(domain)):
        subdomain = domain[0:i] + domain[i+1:len(domain)]
        domains.add(subdomain)
        if subs > 1:
            domains = domains.union(all_possible_subs(subdomain, subs-1))
    return sorted(list(domains))


def all_possible_regexes(domain, subs):
    sub_domains = all_possible_subs(domain, subs)
    regex_domains = []
    for domain in sub_domains:
        domain_with_fuzz = ".?"
        for character in domain:
            domain_with_fuzz += f"[{character}{''.join(COMMON_SUBS.get(character, []))}].?"
        regex_domains.append(fr"https?://([a-z0-9\-]*\.)*(xn\-\-)?{domain_with_fuzz}(\-[a-z0-9]*)?([a-z0-9\-]*\.)*\..*")
    return regex_domains


def fetch_domain_list(url):
    json_result = requests.get(url).json()
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

    domains = fetch_domain_list(BLACKLIST_URL)

    whitelisted_domains = fetch_domain_list(WHITELIST_URL)

    for domain_body, tld, _ in TARGETED_DOMAINS:
        whitelisted_domains.append(f"*{domain_body}.{tld}")

    whitelisted_domains = list(set(whitelisted_domains))
    whitelisted_domains.sort()

    content_blocker_json = [{
        "trigger": {
            "url-filter": ".*",
            "if-domain": domains
        },
        "action": {
            "type": "block"
        }
    }]

    url_regexes = []
    for domain_body, tld, subs in TARGETED_DOMAINS:
        for url_regex in all_possible_regexes(domain_body, subs):
            rule = {
                "trigger": {
                    "url-filter": url_regex,
                    "unless-domain": [f"{x}" for x in whitelisted_domains]
                },
                "action": {
                    "type": "block"
                }
            }
            url_regexes.append(url_regex)
            content_blocker_json.append(rule)

    print(f"{len(url_regexes)} total regexes")

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
