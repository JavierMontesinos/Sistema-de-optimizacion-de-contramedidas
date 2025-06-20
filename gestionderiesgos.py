from pulp import LpProblem, LpMinimize, LpVariable, lpSum, LpBinary
import networkx as nx
import matplotlib.pyplot as plt
import json
import sys

# Definición de amenazas con probabilidad e impacto
amenazas = {
    'T1': {'probabilidad': 0.5, 'impacto': 500},
    'T2': {'probabilidad': 0.4, 'impacto': 500},
    'T3': {'probabilidad': 0.7, 'impacto': 600},
    'T4': {'probabilidad': 0.4, 'impacto': 700},
    'T5': {'probabilidad': 0.3, 'impacto': 400},
    'T6': {'probabilidad': 0.4, 'impacto': 460},
    'T7': {'probabilidad': 0.6, 'impacto': 540},
}

# Definición de vulnerabilidades con aumento de probabilidad
vulnerabilidades = {
    'CVE-2024-0012': {'aumento_prob': 0.47},   # Authentication bypass (PAN-OS) → T1
    'CVE-2024-9474': {'aumento_prob': 0.30},   # Privilege escalation (PAN-OS) → T1/T3
    'CVE-2024-36462': {'aumento_prob': 0.54},  # Uncontrolled resource consumption (Zabbix) → T4
    'CVE-2024-45700': {'aumento_prob': 0.40},  # DoS por resource exhaustion (Zabbix) → T4
    'CVE-2024-42333': {'aumento_prob': 0.35},  # Data alteration via memory leak (Zabbix) → T2
}

# Mapeo de CVEs a amenazas (cada CVE puede afectar a múltiples amenazas)
cve_amenaza_map = {
    'CVE-2024-0012': ['T1'],
    'CVE-2024-9474': ['T1', 'T3'],
    'CVE-2024-36462': ['T4'],
    'CVE-2024-45700': ['T4'],
    'CVE-2024-42333': ['T2']
}

# Calcular el aumento total de probabilidad por amenaza
aumentos_probabilidad = {}
for cve, amenazas_afectadas in cve_amenaza_map.items():
    aumento = vulnerabilidades[cve]['aumento_prob']
    for amenaza in amenazas_afectadas:
        aumentos_probabilidad[amenaza] = aumentos_probabilidad.get(amenaza, 0) + aumento

# Definición de activos y cálculo del riesgo potencial inicial
activos = {
    'A1': {'amenazas': ['T1', 'T2']},
    'A2': {'amenazas': ['T3', 'T4']},
    'A3': {'amenazas': ['T5', 'T6']},
    'A4': {'amenazas': ['T7', 'T1']},
    'A5': {'amenazas': ['T2', 'T3']},
}

# Calcular el riesgo residual potencial por activo
riesgo_residual_total = 0
for activo, datos in activos.items():
    riesgo_residual = 0
    for amenaza in datos['amenazas']:
        p = amenazas[amenaza]['probabilidad'] + aumentos_probabilidad.get(amenaza, 0)
        p = min(p, 1)
        i = amenazas[amenaza]['impacto']
        riesgo_residual += p * i
    datos['riesgo_residual'] = riesgo_residual
    riesgo_residual_total += riesgo_residual

# Imprimir el riesgo potencial inicial por activo y total
print("Riesgo potencial inicial por activo:")
for activo, datos in activos.items():
    print(f" - {activo}: {datos['riesgo_residual']}")
print(f"Riesgo potencial inicial total: {riesgo_residual_total}")

# Cargar las contramedidas desde un archivo JSON
with open("contramedidas.json", "r") as file:
    contramedidas = json.load(file)

# Solicitar al usuario el presupuesto máximo
presupuesto_max = int(input("Ingrese el presupuesto máximo: "))

# Definir el problema de optimización
modelo = LpProblem("Minimizacion_Riesgo_Residual", LpMinimize)
x = {c: LpVariable(f"x_{c}", cat=LpBinary) for c in contramedidas}

# Función objetivo: minimizar el riesgo residual
riesgo_total = 0
for activo, datos_activo in activos.items():
    for amenaza in datos_activo['amenazas']:
        p = amenazas[amenaza]['probabilidad'] + aumentos_probabilidad.get(amenaza, 0)
        p = min(p, 1)
        i = amenazas[amenaza]['impacto']
        reduccion_p = lpSum(x[c] * contramedidas[c].get('reduccion_probabilidad', {}).get(amenaza, 0) for c in contramedidas)
        reduccion_i = lpSum(x[c] * contramedidas[c].get('reduccion_impacto', {}).get(amenaza, 0) for c in contramedidas)
        riesgo_expr = p * i - i * reduccion_p - p * reduccion_i
        var_name = f"riesgo_{activo}_{amenaza}"
        riesgo_var = LpVariable(var_name, lowBound=0)
        modelo += riesgo_var >= riesgo_expr, f"restriccion_{var_name}"
        riesgo_total += riesgo_var

modelo += riesgo_total, "Riesgo_Residual_Total"
modelo += lpSum(contramedidas[c]['coste'] * x[c] for c in contramedidas) <= presupuesto_max, "Presupuesto_Limitado"

# Manejo de M0-DoNothing
m0 = "M0-DoNothing"
if m0 in contramedidas:
    min_coste = min(contramedidas[c]['coste'] for c in contramedidas if c != m0)
    if presupuesto_max < min_coste:
        modelo += x[m0] == 1, "M0_si_no_hay_presupuesto_suficiente"


# Resolver
modelo.solve()

# Mostrar resultados
print("Contramedidas seleccionadas:")
for c in contramedidas:
    if x[c].varValue == 1:
        print(f"- {c}")
        contramedidas[c]['aplicada'] = True

# Riesgo residual por activo post-optimización
riesgo_residual_por_activo = {}
for activo, datos_activo in activos.items():
    riesgo_residual = 0
    for amenaza in datos_activo['amenazas']:
        p = amenazas[amenaza]['probabilidad'] + aumentos_probabilidad.get(amenaza, 0)
        p = min(p, 1)
        i = amenazas[amenaza]['impacto']
        reduccion_p = sum(
    contramedidas[c].get('reduccion_probabilidad', {}).get(amenaza, 0) * (x[c].varValue or 0)
    for c in contramedidas
)
        reduccion_i = sum(
    contramedidas[c].get('reduccion_impacto', {}).get(amenaza, 0) * (x[c].varValue or 0)
    for c in contramedidas
)
        riesgo_amenaza = p * i - i * reduccion_p - p * reduccion_i
        riesgo_residual += max(0, riesgo_amenaza)
    riesgo_residual_por_activo[activo] = round(riesgo_residual,1)

# Imprimir riesgo residual
print("\nRiesgo residual por activo:")
for activo, riesgo in riesgo_residual_por_activo.items():
    print(f" - {activo}: {riesgo}")
print("Riesgo residual total:", modelo.objective.value())

# Crear grafo
def crear_grafo():
    G = nx.DiGraph()
    G.add_nodes_from(activos.keys())
    activos_keys = list(activos.keys())
    for i in range(len(activos_keys) - 1):
        G.add_edge(activos_keys[i], activos_keys[i + 1])
    for activo, datos in activos.items():
        amenazas_sin_cve = set(datos['amenazas'])
        for T in datos['amenazas']:
            for cve, amenazas_cve in cve_amenaza_map.items():
                if T in amenazas_cve:
                    G.add_node(cve)
                    G.add_edge(cve, activo)
                    amenazas_sin_cve.discard(T)
        for T in amenazas_sin_cve:
            G.add_node(T)
            G.add_edge(T, activo)
    for c, datos_c in contramedidas.items():
        if datos_c.get('aplicada', False):
            G.add_node(c)
            for T in datos_c.get('reduccion_probabilidad', {}).keys():
                if T in amenazas:
                    G.add_edge(c, T)
            for T in datos_c.get('reduccion_impacto', {}).keys():
                if T in amenazas:
                    G.add_edge(c, T)
    for cve, Ts in cve_amenaza_map.items():
        for T in Ts:
            if T in amenazas:
                G.add_node(cve)
                G.add_edge(T, cve)
    return G

G = crear_grafo()
colors = ["red" if node.startswith("T") else "lightgreen" if node.startswith("M") else "purple" if node.startswith("CVE") else "lightblue" for node in G.nodes()]
position = {}
for i, activo in enumerate(activos.keys()):
    position[activo] = (i * 2, 0)
for i, cve in enumerate(vulnerabilidades.keys()):
    position[cve] = (i * 2, -0.5)
for i, T in enumerate(amenazas.keys()):
    position[T] = (i * 2, -1)
for i, c in enumerate(contramedidas.keys()):
    position[c] = (i * 2, -1.5)
sizes = [400 if node.startswith("T") else 200 if node.startswith("CVE") else 500 if node.startswith("M") else 1000 for node in G.nodes()]
nx.draw(G, position, node_size=sizes, node_color=colors, with_labels=True, arrows=True, font_size=8)

plt.text(0.99, 0.95, f'Presupuesto: {presupuesto_max}', transform=plt.gca().transAxes, fontsize=8, ha='right', bbox=dict(facecolor='white', alpha=0.5))
plt.text(0.99, 0.90, f'Riesgo potencial inicial total: {riesgo_residual_total}', transform=plt.gca().transAxes, fontsize=8, ha='right', bbox=dict(facecolor='white', alpha=0.5))
plt.text(0.99, 0.85, f'Riesgo residual final total: {modelo.objective.value()}', transform=plt.gca().transAxes, fontsize=8, ha='right', bbox=dict(facecolor='white', alpha=0.5))
y_offset = 0.80
for activo, datos in activos.items():
    plt.text(0.99, y_offset, f'{activo}: Riesgo potencial inicial {datos["riesgo_residual"]} → Riesgo residual final {riesgo_residual_por_activo[activo]}',
             transform=plt.gca().transAxes, fontsize=8, ha='right', bbox=dict(facecolor='white', alpha=0.5))
    y_offset -= 0.05

plt.gcf().canvas.manager.set_window_title("Grafo de Activos, Amenazas, Vulnerabilidades, Contramedidas y su riesgo residual")
plt.show()

# Guardar en archivo
original_stdout = sys.stdout
with open("resultados.txt", "w") as f:
    sys.stdout = f
    try:
        print("Activos, amenazas y vulnerabilidades:")
        for activo, datos in activos.items():
            print(f"{activo}:")
            for amenaza in datos['amenazas']:
                print(f"  - Amenaza: {amenaza}")
        print("\nRiesgo potencial inicial:", riesgo_total)
        print("\nContramedidas aplicadas:")
        for c in contramedidas:
            if x[c].varValue == 1:
                print(f"- {c}")
        print("\nRiesgo residual por activo:")
        for activo, riesgo in riesgo_residual_por_activo.items():
            print(f" - {activo}: {riesgo}")
        print("\nRiesgo residual total:", modelo.objective.value())
    finally:
        sys.stdout = original_stdout