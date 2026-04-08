import pandas as pd
import ipaddress

# Cargar el Excel
excel_path = 'vista excel.xlsx'
sheet_name = 'external connections'
df = pd.read_excel(excel_path, sheet_name=sheet_name)

# Asumimos que hay columnas 'Source Network' y 'Network Name' (ajustar si el nombre es distinto)
# Si hay rangos tipo 10.0.0.0/8 o 192.168.1.0/24, los dejamos tal cual
# Si hay IPs sueltas, las pasamos a /32

output = []
for _, row in df.iterrows():
    net = str(row['Source Network']).strip()
    name = str(row['Network Name']).strip() if 'Network Name' in row else net
    if '/' not in net:
        try:
            ipaddress.ip_network(net)  # Si es una IP válida
            net = net + '/32'
        except Exception:
            continue
    output.append(f'{net},{name}')

with open('source_network_map.csv', 'w', encoding='utf-8') as f:
    f.write('network_cidr,source_network_name\n')
    for line in output:
        f.write(line + '\n')

print('Mapeo generado: source_network_map.csv')
