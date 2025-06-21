# Sistema de Optimización de Contramedidas en la Gestión de Riesgos de Ciberseguridad

## Descripción

Este repositorio contiene el código fuente desarrollado para el Trabajo de Fin de Grado (TFG) titulado **"Desarrollo de un Sistema de Optimización de Contramedidas en la Gestión de Riesgos de Ciberseguridad"**.

El sistema implementa un modelo de optimización que selecciona contramedidas de ciberseguridad de forma eficiente bajo restricciones presupuestarias, minimizando el riesgo residual en una red de activos.

La herramienta se basa en la metodología **MAGERIT** (Metodología de Análisis y Gestión de Riesgos de los Sistemas de Información) y utiliza técnicas de programación lineal para determinar la combinación óptima de contramedidas que maximiza la protección con un presupuesto limitado.

## Características

- Modelado de activos, amenazas y vulnerabilidades siguiendo la metodología MAGERIT.
- Catálogo extensible de contramedidas en formato JSON.
- Optimización mediante programación lineal con **PuLP**.
- Visualización de la red y las contramedidas seleccionadas con **NetworkX**.
- Generación de informes detallados sobre el riesgo residual.
- Soporte para diferentes escenarios presupuestarios.

## Requisitos

- Python 3.6 o superior  
- Bibliotecas necesarias:
  - `pulp`
  - `networkx`
  - `matplotlib`

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/JavierMontesinos/Sistema-de-optimizacion-de-contramedidas.git

# Instalar dependencias
pip install pulp networkx matplotlib
```

## Estructura del Proyecto

Sistema-de-optimizacion-de-contramedidas/
├── gestionderiesgos.py # Implementación principal del sistema
├── contramedidas.json # Catálogo de contramedidas
├── resultados.txt # Archivo de salida con resultados
└── README.md # Documentación del proyecto

### Contramedidas

Las contramedidas (M0–M25) se clasifican en preventivas y reactivas, cada una con:
- **Coste**: Valor normalizado según PILAR  
- **Reducción de probabilidad** o **impacto**  
- **Aplicada**: Booleano para seguimiento

## Uso

1. Ejecutar el script principal: python3 gestionderiesgos.py
2. Introducir el presupuesto máximo cuando se solicite

3. El sistema generará:
- Visualización gráfica de la red con contramedidas seleccionadas
- Archivo `resultados.txt` con información detallada
- Resumen en consola del riesgo residual por activo

## Resultados del Caso de Presupuesto Alto

A continuación se muestran los resultados obtenidos para el caso de uso con presupuesto de 200, como ejemplo de los ficheros de salida del programa:

### Resultados Detallados (resultados.txt)
Sistema-de-optimizacion-de-contramedidas/Ficheros de resultados/Caso de uso Coste(200).txt

### Visualización de la Red (NetworkX)
Sistema-de-optimizacion-de-contramedidas/Gráficos obtenidos/Presupuesto alto (200).png

## Contribuciones

Este proyecto fue desarrollado como Trabajo de Fin de Grado por Javier Montesinos Martí en la Universidad Politécnica de Madrid, bajo la tutoría de Carmen Sánchez Zas.

*Última actualización: Junio 2025*
