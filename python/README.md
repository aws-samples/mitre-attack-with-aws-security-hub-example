## LAMBDA

The solution consists of two Lambda functions: Integrator (or Integrator) and Querier (or SQL Querier). Download Zip or generate Zip files from python files in order of deploy lambda by CloudFormation.

The **INTEGRATOR** is responsible for receiving events, making API calls to the AWS Security Hub and SecretsManager services, processing data and forming the new "MITRE findings".
Hub and SecretsManager services, process data and form the new "MITRE findings". The **QUERIER-SQL** is in charge of opening connection to the repository in RDS and performing queries.

**QUERIER-SQL** needs to be deployed in **VPC mode** in order to have connectivity with resources deployed within the VPC; in this case, the RDS database. **INTEGRATOR** can be deployed in traditional mode. In case you wish to deploy it in VPC mode, due to limitations of the
limitations of the Lambda service itself, it will be necessary to provide it with an output to the Internet via *NatGateway*.

<table>
  <tr><td>integrator.index.py</td><td>INTEGRATOR lambda function main module</td></tr>
  <tr><td>integrator.json_generator.py</td><td>Secondary module of INTEGRATOR. In charge of forming json documents for Security Hub findings</td></tr>
  <tr><td>integrator.com_database.py</td><td>INTEGRATOR secondary module. In charge of retrieving RDS access credentials from SecretsManager</td></tr>
  <tr><td>integrator.api_securityhub.py</td><td>Secondary INTEGRATOR module. In charge of making API calls to Security Hub to retrieve and import findings</td></tr>
</table>

<table>
  <tr><td>querier.index.py</td><td>QUERIER-SQL lambda function main module</td></tr>
</table>