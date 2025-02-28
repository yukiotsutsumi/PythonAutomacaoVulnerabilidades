import requests
from datetime import datetime
import pandas as pd
import os

#variaveis
products = [
    "openSUSE", "Windows", "MongoDB", "SAP BusinessObjects",
    "Huawei", "Opera browser"
]

start_date = "2025-01-01"

nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

api_key = "c282a9f9-eec5-4a79-9f9b-c8d08468c762"

#funcoes pequenas auxiliares
def format_date(date_str):
    return datetime.strptime(date_str, "%Y-%m-%d").strftime("%Y-%m-%dT%H:%M:%S.000Z")

def get_today_date():
    return datetime.today().strftime("%Y-%m-%dT%H:%M:%S.000Z")

#funcao grandona de fato
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
            "resultsPerPage": 40,
            "startIndex": 0
        }

        while True:
            try:
                response = requests.get(nvd_api_url, params=params, headers=headers)

                # Status HTTP
                print(f"Status da resposta para {product}: {response.status_code}")

                response.raise_for_status()  # excecao

                request_successful = response.status_code == 200

                if request_successful:
                    data = response.json()
                    items = data.get("vulnerabilities", [])
                    print(f"Items encontrados para {product}: {len(items)}")
                    for item in items:
                        item["product"] = product  # add o nome do produto a cada item
                    vulnerabilities.extend(items)

                    # checagem de proxima pagina
                    if "nextPage" in data.get("result", {}):
                        params["startIndex"] += params["resultsPerPage"]
                    else:
                        break  # vaza do loop se não houver mais páginas
                else:
                    print(f"Erro ao buscar vulnerabilidades para {product}: {response.status_code}")
                    print(f"Detalhes: {response.text}")
                    break  # vaza do loop em caso de erro irreversível
            except requests.exceptions.HTTPError as http_err:
                print(f"Erro HTTP ao conectar à API para {product}: {http_err}")
                print(f"Detalhes: {response.text}")
                break
            except Exception as e:
                print(f"Erro inesperado ao conectar à API para {product}: {e}")
                break

    return vulnerabilities

# buscar vulnerabilidades
vulnerabilities = search_vulnerabilities(start_date, products)

# checar se a lista de vulnerabilidades eh vazia
print(f"Verificando lista de vulnerabilidades: {len(vulnerabilities)} vulnerabilidades encontradas")

if vulnerabilities:
    print(f"Vulnerabilidades encontradas: {len(vulnerabilities)}")
    vuln_data = []

    for vuln in vulnerabilities:
        cve_id = vuln.get("cve", {}).get("id", "N/A")
        description = next((desc["value"] for desc in vuln.get("cve", {}).get("descriptions", []) if desc["lang"] == "en"), "No description available")
        published_date = vuln.get("cve", {}).get("published", "No publish date available")
        product = vuln.get("product", "No product available")

        # gerar link de cada cve independente
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        print(f"CVE ID: {cve_id}")
        print(f"Produto: {product}")
        print(f"Data de publicação: {published_date}")
        print(f"URL: {cve_url}")
        print(f"Descrição: {description}")
        print("-" * 80)

        # add os dados a uma lista para salvar em excel
        vuln_data.append({
            "CVE ID": cve_id,
            "Produto": product,
            "Data de publicação": published_date,
            "URL": cve_url,
            "Descrição": description
        })

    # criacao um dataframe do pandas com os novos dados
    df_combined = pd.DataFrame(vuln_data)

    # criacao de um dataframe com hyperlinks
    writer = pd.ExcelWriter("vulnerabilidades.xlsx", engine="xlsxwriter")

    for product in products:
        df_product = df_combined[df_combined["Produto"] == product]
        
        if not df_product.empty:
            df_product.to_excel(writer, index=False, sheet_name=product)

            # Acessar o workbook e worksheet
            workbook  = writer.book
            worksheet = writer.sheets[product]

            # diferenciacao de titulo e resultado com estilos
            header_format = workbook.add_format({'bold': True, 'bg_color': '#e189a5', 'border': 1})
            cell_format = workbook.add_format({'bg_color': '#ffecef', 'border': 1})

            # estilo no cabeçalho
            for col_num, value in enumerate(df_product.columns.values):
                worksheet.write(0, col_num, value, header_format)

            # estilo nas células dos resultados
            for row_num in range(1, len(df_product) + 1):
                for col_num in range(len(df_product.columns)):
                    worksheet.write(row_num, col_num, df_product.iloc[row_num - 1, col_num], cell_format)

            # hyperlinks e estilo da coluna URL
            for row_num, url in enumerate(df_product["URL"], start=1):
                worksheet.write_url(f"D{row_num + 1}", url, cell_format)

            # largura das colunas
            for col_num, col in enumerate(df_product.columns):
                max_len = max(df_product[col].astype(str).map(len).max(), len(col)) + 2
                worksheet.set_column(col_num, col_num, max_len)

    # criacao do gráfico de linha
    df_combined['Data de publicação'] = pd.to_datetime(df_combined['Data de publicação'], errors='coerce')
    df_combined = df_combined.dropna(subset=['Data de publicação'])

    df_combined['Data de publicação'] = df_combined['Data de publicação'].dt.date
    chart_sheet = workbook.add_worksheet('Gráfico')
    chart = workbook.add_chart({'type': 'line'})
    colors = ['blue', 'red', 'green', 'orange', 'purple', 'cyan']

    # separar apenas as datas unicas do grafico
    all_dates = sorted(df_combined['Data de publicação'].unique())

    # conversao all_dates para uma Series para calcular o comprimento máximo
    all_dates_series = pd.Series(all_dates)

    # preencher a coluna de datas
    chart_sheet.write_row('A1', ['Data de Publicação'] + products, header_format)
    chart_sheet.write_column('A2', all_dates, workbook.add_format({'num_format': 'yyyy-mm-dd'}))

    # ajustar a largura da coluna de datas
    max_date_len = max(all_dates_series.astype(str).map(len).max(), len('Data de Publicação')) + 2
    chart_sheet.set_column(0, 0, max_date_len)

    # add dados para cada produto
    for idx, product in enumerate(products):
        df_grouped = df_combined[df_combined["Produto"] == product].groupby('Data de publicação').size().reindex(all_dates, fill_value=0).reset_index(name='Count')
        chart.add_series({
            'name': product,
            'categories': ['Gráfico', 1, 0, len(all_dates), 0],
            'values': ['Gráfico', 1, idx + 1, len(all_dates), idx + 1],
            'line': {'color': colors[idx % len(colors)]},
        })
        chart_sheet.write_column(1, idx + 1, df_grouped['Count'])

    chart.set_title({'name': 'Número de Vulnerabilidades em Função do Tempo'})
    chart.set_x_axis({'name': 'Data de Publicação'})
    chart.set_y_axis({'name': 'Número de Vulnerabilidades'})
    chart.set_size({'width': 800, 'height': 400})  # altura e largura do gráfico
    chart_sheet.insert_chart('G2', chart)

    writer.close()
    print("Vulnerabilidades salvas em vulnerabilidades.xlsx, separadas por produto, com hyperlinks, estilos e gráficos")
else:
    print("Nenhuma vulnerabilidade encontrada.")