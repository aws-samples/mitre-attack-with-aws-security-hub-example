## LAMBDA

La solución se conforma de dos funciones Lambda: Integrator (o Integrador) y Querier (o Consultor SQL). Descarge o genere ficheros en formato Zip a partir de los ficheros python para su futuro despliegue mediante CloudFromation.

El **INTEGRADOR** es el encargado de recibir eventos, realizar llamadas API a los servicios de AWS Security Hub y SecretsManager, procesar datos y formar los nuevos "hallazgos MITRE". El **CONSULTOR-SQL** es el encargado de abrir conexión con el repositorio en RDS y realizar consultas.

Es necesario que el **CONSULTOR-SQL** se despliegue en **modo VPC** para disponer de conectividad con recursos desplegados dentro de la VPC; en este caso, la base de datos RDS. **INTEGRADOR** puede desplegarse en modo tradicional. En caso de desear desplegarlo en modo VPC, por limitaciones del propio servicio Lambda, será necesario facilitarle salida hacia Internet mediante *NatGateway*.

<table>
  <tr><td>integrator.index.py</td><td>Módulo principal de la función lambda INTEGRADOR</td></tr>
  <tr><td>integrator.json_generator.py</td><td>Módulo secundario de INTEGRADOR. Encargado de formar documentos json para hallazgos de Security Hub</td></tr>
  <tr><td>integrator.com_database.py</td><td>Módulo secundario de INTEGRADOR. Encargado de recuperar credenciales de acceso a RDS desde SecretsManager</td></tr>
  <tr><td>integrator.api_securityhub.py</td><td>Módulo secundario de INTEGRADOR. Encargado de realizar llamadas API a Security Hub para recuperar e importar hallazgos</td></tr>
</table>

<table>
  <tr><td>querier.index.py</td><td>Módulo principal de la función lambda CONSULTOR-SQL</td></tr>
</table>