## Base de Datos

El diseño de la solución está planteado para que en entornos multi-cuenta u Organizaciones sólo sea necesario el **despliegue en la cuenta designada a seguridad** (aquella que centralice la gestión de SecurityHub y Config). Se ha optado por el uso de una instancia *db.t4g.micro* de RDS con motor *Postgresql 14.4*, en Multi-az. Quedando abierto a ajustes a lo largo de la vida del proyecto. La cantidad de datos y el número de operaciones (*limitado) permite el uso de máquinas de baja capacidad y coste operativo.

Puesto que los datos contenidos **no son de caracter sensible**, para el despliegue inicial y actualización es posible el empleo de la *snapshot* (o copia de seguridad) pública:
```
Versión más reciente:
arn:aws:rds:eu-west-1:794731801658:snapshot:vsoc-mitre-integration-repository-v20230119
```

### Credenciales

En primera instancia, la base de datos del repositorio mantiene valores por defecto para el administrador y el usuario de lambda. Es práctica recomendada que modifique la contraseña para estos perfiles. Ver [Pasos de despliegue](../docs/deployment_esp.md).
```
Valores por defecto:
Base de datos: vsocmitreintegrationdatabase

Administrador
user: mirmaster
password: admin12345

Lectura
user: mirlambdareader
password: reader12345
```

### Esquema 

El flujo de relaciones es el siguiente:

Cada *evento* de seguridad está relacionado con una o varias *técnicas*. A su vez, cada técnica tendrá asociada una o varias *tácticas* y un conjunto de *controles* por cada *estandar de seguridad*.

![esquema](../common/schema.png)

Se dispone de tabla de contenido por cada grupo (técnica, táctica, estandar, evento...) y de asociación por cada relación (evento a técnica, técnica a estandar).

### Contenido

Existe un trabajo continuo de actualización de datos a razón de nuevas versiones en MITRE ATT&CK y de servicios nativos de AWS que se centralicen/integren en Security Hub. Estos cambios se volcarán en versiones actualizadas de la copia de seguridad pública.

Actualmente dispone de los siguientes:
-   **60 Técnicas** repartidas entre **11 Tácticas** de MITRE ATT&CK **v12**
-   **277 Reglas** y **eventos** de AWS (50% AwsConfig, 25% GuardDuty, 10% SecurityHub (CIS, PCI), Otros...)

Las relaciones con los **estándares de seguridad** han sido desarrolladas de *manera autónoma*:
-   **NIST 800-53-rev5** : 137 controles
-   **CIS CSC v8** : 142 controles
-   **PCI-DSS v3.2.1** : 147 controles 
-   **C5** *2022* : 17 controles
-   **ENS CNN-STICK** *2022* : 17 controles

## Uso

El despliegue de la base de datos es automático. Existirá una copia de seguridad pública en RDS, por lo que puede omitir estos procesos en su entorno (salvo que realice modificaciones en el contenido de su base de datos).

-   **Función Lambda:** Al existir límites en la realización de consultas (de recuperación e importación) por segundo hacia Security Hub, la solución no permite concurrencias en paralelo del proceso y, adicionalmente, requiere un tiempo de espera entre activaciones para que Security Hub se actualice. Esto deriva a que la función lambda *CONSULTOR-SQL* realizará como máximo **6 consultas de lectura** hacia la base de datos en ventanas de **30 segundos** (*de ahí el reducido número de operaciones).
-   **Administrador:** No es necesario el acceso a la base de datos salvo para tareas de cambio de contraseñas del perfil de administrador y del lector lambda. Ver [Pasos de despliegue](../docs/deployment_esp.md). No obstante, si se van a realizar tareas de actualización o modificación es recomendable crear un nuevo perfil para ello.
