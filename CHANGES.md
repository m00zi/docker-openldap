# Changelog

Here you can see an overview of changes between each release.

## Version 3.1.3_05

Released on September 12th, 2018.

* Added feature to connect to secure Consul (HTTPS).

## Version 3.1.3_04

Released on August 31st, 2018.

* Added Tini to handle signal forwarding and reaping zombie processes.

## Version 3.1.3_03

Released on August 11th, 2018.

* Added feature to re-generate certificate with Subject Alt Name.

## Version 3.1.3_02

Released on August 1st, 2018.

* Added wrapper to manage config via Consul KV or Kubernetes configmap.

## Version 3.1.3_01

Released on June 6th, 2018.

* Upgraded to Gluu Server 3.1.3.

## Version 3.1.2_01

Released on June 6th, 2018.

* Upgraded to Gluu Server 3.1.2.

## Version 3.1.1_rev1.0.0-beta2

Released on October 25th, 2017.

* Fixed push notification config.

## Version 3.1.1_rev1.0.0-beta1

Released on October 6th, 2017.

* Migrated to Gluu Server 3.1.1.

## Version 3.0.1_rev1.0.0-beta4

Released on August 26th, 2017.

* Always double-check active OpenLDAP servers before doing replication.

## Version 3.0.1_rev1.0.0-beta3

Released on July 20th, 2017.

* Fixed initialization flag to avoid re-generating entries when container is recreated by Containership scheduler (see https://github.com/GluuFederation/containership.io/issues/6).

## Version 3.0.1_rev1.0.0-beta2

Released on July 12th, 2017.

* Fixed template rendering in `oxtrust-config.json`.

## Version 3.0.1_rev1.0.0-beta1

Released on July 7th, 2017.

* Added working OpenLDAP.
* Added feature to do mult-master replication.
