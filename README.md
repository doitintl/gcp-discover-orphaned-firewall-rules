# Google Cloud Discover Orphaned Firewall Rules

A tool to find all INGRESS firewall rules that are not applied to any VM instances in any project inside a shared VPC (orphaned rules).

## Authentication to Google Cloud

This Project is using the [Google Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/production).

You can either use the following command to login from the terminal using your default setup for gcloud:

```bash
gcloud auth application-default login
```

Or by a service account using the following environment variable:

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/home/user/Downloads/[FILE_NAME].json"
```

## How this tool works

This tool first gets all the INGRESS firewall rules for the given host project.

The next step is getting all of the child projects (projects associated with the host project)

A copy of the firewall rules is made intended to be as an elimination list for all active rules.

For each child project, all VM instances are fetched, and for each VM instance network tags are
checked against the elimination list, if the instance network tags matches any of the rules target
tags, the rule is considered active and removed from the elimination list.

Each child project is using the same elimination list until there are no more child projects, and
the elimination (orphaned rules) list output is saved to a CSV file for further use.

## Build from source

```bash
go get github.com/doitintl/gcp-discover-orphaned-firewall-rules
cd ${GOPATH}/src/github.com/doitintl/gcp-discover-orphaned-firewall-rules
go mod download
go build -o discover-orphaned-rules main.go
cp discover-orphaned-rules /usr/local/bin/
```

If compilation is failed, you should try to enable go modules:

```bash
GOPATH=/tmp/gopath-for-gcp-discover-orphaned-firewall-rules
GO111MODULE=on
go get github.com/doitintl/gcp-discover-orphaned-firewall-rules
go mod download
go build -o discover-orphaned-rules main.go
cp discover-orphaned-rules /usr/local/bin/
```

## How to run

Available flags:

```txt
    --debug         Set log level
    --host string   Host Project ID <Required>
    --running       Filter only running VM instances
```

```bash
$ ./discover-orphaned-rules-darwin-amd64 --host=host-project-123ewquiyt

INFO[2019-06-12T12:57:54+03:00] creating a new Compute API client
INFO[2019-06-12T12:57:54+03:00] host project: host-project-123ewquiyt
INFO[2019-06-12T12:57:56+03:00] firewall Rules for host project: host-project-123ewquiyt
INFO[0001] listing only TargetTags rules...
INFO[0001] number of TargetTags Rules: 3
INFO[2019-06-12T12:57:56+03:00] child project: deleted-project-1268522
WARN[0001] error listing VM instances googleapi: Error 404: Failed to find project deleted-project-1268522, notFound
WARN[2019-06-12T12:57:56+03:00] Could not check project deleted-project-1268522 for orphaned rules: googleapi: Error 404: Failed to find project deleted-project-1268522, notFound
INFO[2019-06-12T12:57:56+03:00] child project: resource-project-12iuyt2854
INFO[0001] making a list of orphaned rules with all rules (active rules will be removed from it)
resource-project-12iuyt2854, ghostresource-project-12iuyt2854, instance-target-demo-ruleresource-project-12iuyt2854, real-ruleINFO[0001] looking for orphaned rules in project..
INFO[0001] remove active rule from orphans list: instance-target-demo-rule
INFO[0001] 2 potential orphaned firewall rules to evalute...
INFO[2019-06-12T12:57:56+03:00] child project: resource-2-23ouyrwe9
INFO[0002] making a list of orphaned rules with all rules (active rules will be removed from it)
resource-2-23ouyrwe9, ghostami-resource-2-23ouyrwe9, instance-target-demo-ruleami-resource-2-23ouyrwe9, real-ruleINFO[0002] looking for orphaned rules in project..
INFO[0002] remove active rule from orphans list: instance-target-demo-rule
INFO[0002] 2 potential orphaned firewall rules to evalute...
INFO[2019-06-12T12:57:57+03:00] generating CSV file for orphaned rules...
INFO[0002] creating a new CSV file: orphaned-rules.csv
INFO[2019-06-12T12:57:57+03:00] done!
```

This will also generate a CSV file:

```csv
rule-name,rule-tags
ghost,dead
real-rule,"real-1,real2,real-3"
```
