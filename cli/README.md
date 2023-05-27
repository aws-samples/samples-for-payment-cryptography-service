## CLI

As this is a beta build, the following instructions add the Magnus models to your existing CLI installation rather than providing a new CLI.  If you don't have the CLI already, go ahead and install that first.  Once that is complete, add those to the AWS CLI v2 already installed on a machine by running:

```
sudo aws configure add-model --service-model file://magnus-2021-09-14.json --service-name magnuscontrol
sudo aws configure add-model --service-model file://magnusdataplane-2022-02-03.json --service-name magnusdata
```