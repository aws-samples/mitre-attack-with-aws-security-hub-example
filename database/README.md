## Internal database backups

In addition to the backups (or snapshots) for the RDS service, here are internal PostgreSQL backups of the database contents. They can be used in SQL processes for loading into other compatible engines, without the need for instance support in RDS.

<table>
  <tr><td><i>File</i> .csv</td><td>Raw data for each of the tables</td></tr>
  <tr><td>mitre-data.sql</td><td>Full backup. Tar format and UTF-8 code</td></tr>
  <tr><td>mitre-schema.sql</td><td>Partial backup, schema only. Tar format and UTF-8 code</td></tr>
</table>
