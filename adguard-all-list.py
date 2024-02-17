import requests
import re
import tarfile
import io

def fetch_data_from_urls(urls):
    data = []
    for url in urls:
        response = requests.get(url, verify=False)  # Adicionando verify=False para ignorar erros de SSL
        if response.status_code == 200:
            if url.endswith('.tar.gz'):
                # Descompactar o arquivo .tar.gz
                with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
                    # Listar todos os arquivos no arquivo .tar.gz
                    for member in tar.getmembers():
                        data.extend(tar.extractfile(member).read().decode('utf-8').splitlines())
            else:
                data.extend(response.text.splitlines())
    return data

def extract_valid_domains_and_ips(lines):
    valid_items = []
    for line in lines:
        # Remover comentários
        line = re.sub(r'#.*$', '', line)
        # Remover espaços em branco adicionais
        line = line.strip()
        # Verificar se é um domínio válido
        domain_match = re.match(r'^([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}$', line)
        if domain_match:
            valid_items.append(domain_match.group())
        else:
            # Verificar se é um endereço IP válido
            ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line)
            if ip_match:
                valid_items.append(ip_match.group())
    return valid_items

def convert_to_adguard_format(data):
    adguard_list = []
    for item in data:
        if re.match(r'^[a-zA-Z0-9-]+$', item):  # Se é um domínio
            adguard_list.append(f'0.0.0.0 {item}')
        else:  # Se é um endereço IP
            adguard_list.append(f'0.0.0.0 {item}')
    return adguard_list

def write_to_file(data, filename):
    with open(filename, 'w', encoding='utf-8') as file:
        for item in data:
            file.write("%s\n" % item)

if __name__ == "__main__":
    # Lista de URLs das fontes de domínios
    urls = [
			'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts',
			'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts',
			'https://github.com/DandelionSprout/adfilt/raw/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
			'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt',
			'https://azorult-tracker.net/api/list/domain?format=plain',
			'https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts',
			'https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt',
			'https://gitlab.com/ZeroDot1/CoinBlockerLists/-/raw/master/hosts',
			'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt',
			'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt',
			'https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-urls-pihole.txt',
			'https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt',
			'https://hole.cert.pl/domains/domains.txt',
			'https://rescure.me/rescure_domain_blacklist.txt',
			'https://raw.githubusercontent.com/HexxiumCreations/threat-list/gh-pages/hosts.txt',
			'https://www.usom.gov.tr/url-list.txt',
			'https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt',
			'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
			'https://openphish.com/feed.txt',
			'https://phishing.army/download/phishing_army_blocklist_extended.txt',
			'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
			'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
			'https://securereload.tech/Phishing/Lists/Latest/',
			'https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt',
			'https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt',
			'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
			'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt',
			'https://threatfox.abuse.ch/downloads/hostfile',
			'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt',
			'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt',
			'https://urlhaus.abuse.ch/downloads/hostfile/'
			'https://dsi.ut-capitole.fr/blacklists/download/malware.tar.gz',
			'https://dsi.ut-capitole.fr/blacklists/download/phishing.tar.gz',
    ]

    # Carregando dados das URLs
    data = fetch_data_from_urls(urls)

    # Extrair domínios e endereços IP válidos
    valid_items = extract_valid_domains_and_ips(data)

    # Convertendo para o formato do AdGuard
    adguard_list = convert_to_adguard_format(valid_items)

    # Filtrando itens duplicados
    unique_adguard_list = list(set(adguard_list))

    # Ordenando os dados únicos em ordem alfabética
    unique_adguard_list.sort()

    # Escrevendo os dados únicos em um arquivo
    write_to_file(unique_adguard_list, 'adguard_list.txt')

    print("Lista única para o AdGuard criada e salva como 'adguard_list.txt'")
