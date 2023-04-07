## Copias de seguridad internas de la base de datos

Al margen de las copias de seguridad (o snapshots) para el sevicio RDS, aquí se exponene copias de seguridad internas para PostgreSQL del contenido de la base de datos. Pueden ser empleadas en procesos SQL para cargar en otros motores compatibles, sin necesidad de soporte de instancias en RDS.

<table>
  <tr><td><i>Ficheros</i> .csv</td><td>Datos en crudo para cada una de las tablas</td></tr>
  <tr><td>mitre-data.sql</td><td>Backup total. Formato Tar y código UTF-8</td></tr>
  <tr><td>mitre-schema.sql</td><td>Backup parcial, sólo esquema. Formato Tar y código UTF-8</td></tr>
</table>
