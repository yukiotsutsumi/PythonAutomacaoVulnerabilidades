import requests
from datetime import datetime
import pandas as pd
import os

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
                # print(f"Resposta: {response.text[:1000]}")

                response.raise_for_status()  # Exceção em caso de erro HTTP

                request_successful = response.status_code == 200

                if request_successful:
                    data = response.json()
                    items = data.get("vulnerabilities", [])
                    print(f"Items encontrados para {product}: {len(items)}")
                    for item in items:
                        item["product"] = product  # Adiciona o nome do produto a cada item
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
    vuln_data = []

    for vuln in vulnerabilities:
        cve_id = vuln.get("cve", {}).get("id", "N/A")
        description = next((desc["value"] for desc in vuln.get("cve", {}).get("descriptions", []) if desc["lang"] == "en"), "No description available")
        published_date = vuln.get("cve", {}).get("published", "No publish date available")
        product = vuln.get("product", "No product available")

        # Gerar URL para o CVE
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        print(f"CVE ID: {cve_id}")
        print(f"Produto: {product}")
        print(f"Data de publicação: {published_date}")
        print(f"URL: {cve_url}")
        print(f"Descrição: {description}")
        print("-" * 80)

        # Adicionar os dados a uma lista para salvar em Excel
        vuln_data.append({
            "CVE ID": cve_id,
            "Produto": product,
            "Data de publicação": published_date,
            "URL": cve_url,
            "Descrição": description
        })

    # Checar se o arquivo Excel já existe
    if os.path.exists("vulnerabilidades.xlsx"):
        # Se o arquivo existe, ler o conteúdo existente
        df_existing = pd.read_excel("vulnerabilidades.xlsx")

        # Criar um DataFrame do pandas com os novos dados
        df_new = pd.DataFrame(vuln_data)

        # Concatenar dados existentes e novos
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)

        # Remover duplicatas com base no CVE ID
        df_combined.drop_duplicates(subset=["CVE ID"], keep="last", inplace=True)
    else:
        # Se o arquivo não existe, criar um novo
        df_combined = pd.DataFrame(vuln_data)

    # Criar um DataFrame com hyperlinks
    writer = pd.ExcelWriter("vulnerabilidades.xlsx", engine="xlsxwriter")
    df_combined.to_excel(writer, index=False, sheet_name="Vulnerabilidades")

    # Acessar o workbook e worksheet
    workbook  = writer.book
    worksheet = writer.sheets["Vulnerabilidades"]

    # Criar hyperlinks
    for row_num, url in enumerate(df_combined["URL"], start=1):
        worksheet.write_url(f"D{row_num + 1}", url)  # Corrige a coluna da URL para a coluna correta

    writer.close()
    print("Vulnerabilidades salvas em vulnerabilidades.xlsx com hyperlinks")
else:
    print("Nenhuma vulnerabilidade encontrada.")