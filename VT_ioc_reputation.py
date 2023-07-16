import requests

API_KEY = '<your api key>'

def check_ioc_reputation(ioc):
    url = f'https://www.virustotal.com/api/v3/files/{ioc}'
    headers = {
        'x-apikey': API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        attributes = result.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        print(malicious)
        undetected = stats.get('undetected', 0)
        total_vendors = stats.get('total', 0)
        d = undetected + malicious
        if malicious <= 0:
        	print("reputation is zero")
        else:
        	return ioc, f"{malicious}/{d}"
    else:
        print(f"Error: {response.status_code}")
        return None

def read_iocs_from_file(file_path):
    with open(file_path, 'r') as file:
        iocs = file.readlines()
    # Remove leading/trailing whitespaces and newlines
    iocs = [ioc.strip() for ioc in iocs]
    return iocs

def save_results_to_file(results):
    with open('results.txt', 'w') as file:
        for ioc, reputation in results:
            file.write(f"{ioc}: {reputation}\n")

def main():
    ioc_file = 'ioc_list.txt'
    iocs = read_iocs_from_file(ioc_file)

    results = []
    for ioc in iocs:
        print(f"Checking reputation for {ioc}")
        result = check_ioc_reputation(ioc)
        if result:
            results.append(result)

    save_results_to_file(results)
    print("Results saved to results.txt")

if __name__ == '__main__':
    main()
