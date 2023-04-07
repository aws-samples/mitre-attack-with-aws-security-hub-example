# Virtual SOC, integración de MITRE Attack en AWS Security Hub

## Origen

Como operador de seguridad que emplée **únicamente herramientas nativas** del entorno de AWS, podrá ver que la información aportada en los paneles de Security Hub son muy limitados para dar un **enfoque centrado en amenazas y atacantes**; Los hallazgos en Security Hub están más orientados a dar una rápida referencia al cumplimiento de estándares de seguridad.

Sólo algunos hallazgos aportan información del marco de referencia de [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/cloud/) desde el servicio de origen (Amazon GuardDuty aporta esta información para un porcentaje de sus tipos de hallazgos).

Hemos querido extender esta capacidad a un mayor número de hallazgos, lo que aporta al operador de seguridad una rápida comprensión del grado de exposición de su entorno y *a qué tipo de ataques*.

## Objetivos

1.   **Correlación** o mapeado de tácticas y técnicas de [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/cloud/) aplicables al entorno de AWS, con reglas y eventos que puedan ser tratados de manera nativa.
2.   Formación de **Paquete de Reglas de Conformidad de MITRE ATT&CK** para AWS Config.
3.   Finalmente, creación de un proceso de enriquecimiento de hallazgos en Security Hub con la información anterior procesada.

## Estado actual

-   Se han catalogado **60 Técnicas/Sub-Técnicas** (TTP) (de 97 aplicables a entornos en la nube), repartidas en 11 Tácticas (TA) distintas.
-   Se han relacionado con **277 reglas/eventos** de servicios nativos de AWS centralizables en Security Hub.
-   Se han relacionado con controles de los principales estándares de seguridad (ISO27K, ENS, NIST, CIS, PCI, C5).
-   Se ha formalizado un **Paquete de Reglas de Conformidad de MITRE ATT&CK** con 120 reglas administradas.
-   Actualmente el proceso de enriquecimiento tiene la capacidad de crear, actualizar y archivar hallazgos de MITRE en función de los hallazgos originales.

## Vision de futuro

Se están barajando las posibles implicaciones o rumbos a seguir para el proyecto:

-   Desarrollo de paneles para una mejor visualización
-   Inclusión de MITRE ATT&CK - Campaings 
-   Mapeo de eventos de servicios de terceros
-   Auto corrección desde AWS Config para ConformancePack