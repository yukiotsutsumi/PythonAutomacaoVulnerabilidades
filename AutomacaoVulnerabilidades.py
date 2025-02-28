import requests
from datetime import datetime

products = [
    "openSUSE", "Windows", "MongoDB", "SAP BusinessObjects",
    "Huawei", "Opera browser"
]

start_date = "2025-01-01"

nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

api_key = "c282a9f9-eec5-4a79-9f9b-c8d08468c762"

def format_date(date_str):
    return datetime.strptime(date_str, "%Y-%m-%d").strftime("%Y-%m-%dT%H:%M:%S.000Z")

def get_today_date():
    return datetime.today().strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Função para buscar vulnerabilidades por produto e data
def search_vulnerabilities(start_date, products):
    start_date_obj = format_date(start_date)
    end_date_obj = get_today_date() 
    vulnerabilities = []

    headers = {
        "apiKey": api_key
    }

    for product in products:
        print(f"Buscando CVEs para o produto: {product}")
        params = {
            "keywordSearch": product,
            "pubStartDate": start_date_obj,
            "pubEndDate": end_date_obj,
            "resultsPerPage": 200,
            "startIndex": 0
        }

        while True:
            try:
                response = requests.get(nvd_api_url, params=params, headers=headers)
                
                # Status HTTP
                print(f"Status da resposta para {product}: {response.status_code}")
                print(f"Resposta: {response.text[:1000]}")
                
                response.raise_for_status()  # Exceção em caso de erro HTTP
                
                request_successful = response.status_code == 200
                
                if request_successful:
                    data = response.json()
                    items = data.get("vulnerabilities", [])
                    print(f"Items encontrados para {product}: {len(items)}")
                    vulnerabilities.extend(items)
                    
                    # Checando se existe uma próxima página
                    if "nextPage" in data.get("result", {}):
                        params["startIndex"] += params["resultsPerPage"]
                    else:
                        break  # Sai do loop se não houver mais páginas
                else:
                    print(f"Erro ao buscar vulnerabilidades para {product}: {response.status_code}")
                    print(f"Detalhes: {response.text}")
                    break  # Sai do loop em caso de erro irreversível
            except requests.exceptions.HTTPError as http_err:
                print(f"Erro HTTP ao conectar à API para {product}: {http_err}")
                print(f"Detalhes: {response.text}")
                break
            except Exception as e:
                print(f"Erro inesperado ao conectar à API para {product}: {e}")
                break

    return vulnerabilities

# Buscar vulnerabilidades com link
vulnerabilities = search_vulnerabilities(start_date, products)

# Verificar se a lista de vulnerabilidades está vazia
print(f"Verificando lista de vulnerabilidades: {len(vulnerabilities)} vulnerabilidades encontradas")

if vulnerabilities:
    print(f"Vulnerabilidades encontradas: {len(vulnerabilities)}")
    for vuln in vulnerabilities:
        cve_id = vuln.get("cve", {}).get("id", "N/A")
        description = next((desc["value"] for desc in vuln.get("cve", {}).get("descriptions", []) if desc["lang"] == "en"), "No description available")
        published_date = vuln.get("cve", {}).get("published", "No publish date available")
        
        # Gerar URL para o CVE
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        print(f"CVE ID: {cve_id}")
        print(f"Description: {description}")
        print(f"Published Date: {published_date}")
        print(f"URL: {cve_url}")
        print("-" * 80)
else:
    print("Nenhuma vulnerabilidade encontrada.")
