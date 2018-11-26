# Motivation

Spectator Meter Transforms provide a mechanism to filter and transform
Spinnaker metrics into a different data model before processing them
further. There are a few reasons for wanting to do this:

* Spinnaker produces a lot of metrics for different audiences
 (e.g. operational monitoring, development insights). This can
 have non-trivial storage and access costs. Only passing through
 metrics of interest (or discarding those known not to be) can
 reduce the persistence costs.

* Some external monitoring systems utilize static schemas and do
 not respond well to changes in metric structure, such as the addition
 of new tags or changing types. A transformation layer can tolerate
 evolution to instrumentation while providing a stable data model
 to these backend systems.

* When the data model for a given metrics change then customer's
 existing customized dashboards and alerting rules may not work as
 expected. Transformations provide a means to produce a stable data
 model to preserve the integrity of these artifacts when updating
 releases.

* It is difficult to know when and how instrumentation has changed,
 particularly when new metrics are added. The specification underlying
 transformations outlined in this proposal provide a means to explicitly
 compare the data model for a given release against a prior known one.

* The metrics produced by Spinnaker are not always consistent in
 how they are named or tagged. Transformations provide a means to
 rectify this in a non-disruptive manner by allowing users to opt-in
 to proposed changes at their own pace before being forced into
 native changes in the codebase.

* The transformations provide a means to provide more extensive
 explicit and implicit documentation about the metrics such as
 their type, tags, and purpose.


# Approach

The transformation mechanism consists of a YAML file specifying each
metric produced by Spinnaker and what its desired data model should be.
The monitoring daemon contains a processing component that understands
this YAML file. The metrics response scraped from the Spinnaker service
are processed by this component to transform the response such that it
appears that Spinnaker reported metrics with the desired data model.

## Tradeoffs

* Maintaining a YAML file separate from the actual implementation
 is not long-term ideal. However, it is short-term pragmatic because it
 does not require changing the code or introducing new mechanisms.
 Longer term, we can introduce new mechanisms into the codebase to
 document and report metrics used, and migrate the metrics themselves to
 a new data model instead of using this mechanism. This mechanism feels
 [to me] like a pragmatic means to get there should be choose to.

* The transformations incur runtime overhead for every metric. However
 this cost is in the daemon, which is independent from the Spinnaker
 service runtime so should not affect Spinnaker's performance.

* The "language" and expressiveness of the proposed YAML is specialized
 for this particular use case. There may be other existing or more
 generalized solutions. Daemon performance is not a current concern,
 but embedded in the service runtime could be.

* The current transformation "language" is not powerful enough to invert.
 In particular, it allows for surjective mappings where multiple metrics
 may aggregate into the same metric but using different label values
 to distinguish among them. It is not worth supporting the inverse of
 this because it is not a use case of interest other than providing
 backward compatability. The expectation is that if backward compatability
 were needed, the community should be given sufficient time to opt-in at
 their own pace (within reason).

* Most Spinnaker metrics are internally consistent in how they are used
 when they appear in multiple places (but might be inconsistent with how
 other metrics are used). But not all; there are a number of metrics in
 the Kubernetes provider and some Amazon provider metrics that dont quite fit
 what I currently have, but am looking at interim ways to accomodate them.
 These limit the robustness of some desirable transformations without wiring
 some knowledge of these anomolies into the transformation mechanism or
 perhaps adding weird accomodations into the specification grammar. This has
 not yet been done.


# Language

The YAML file uses a new entry in the existing Metric Filters to specify
transformations. The existing Metric Filters can co-exist however are no
longer relevant or needed given the transforms.

The entry `monitoring.transforms` contains a dictionary keyed by
the Spectator meter name whose value is the transformation specification
using the following schema:

  Attribute | Description
  ----------|------------
  kind | Specifies the Spectator meter type. e.g. `Timer`.
  docs | Documentation for the metric. This is not part of the transformation however allows these specifications to be a vehicle for providing documentation.
  unit | Documents the value units.
  tags | A list of tags to pass through as is. These tags are optional. Spectator measurements do not require specific tags so entries in this list may not be present in all measurements for the given meter. Spectator tag values are always STRING.
  rename | The new name for the metric, replacing the original name that was the key.
  add_tags | A dictionary of tags to inject with their values. The values are strings. This is intended to aggregate multiple metrics into a common composite metric using the tag(s) to distinguish the original measurement.
  discard_tag_values | A dictionary keyed by tag names whose values are regular expressions to match for that tag. If a regular expression matches, then disregard that metric instance entirely. This is intended to drop specific dimensions of spectator types using the "statistic" tag which are essentially different metrics. In particular the "percentile" dimension if not of interest, or perhaps the "totalTime" dimension if only the counter desired.
  per_account | Indicates that this metric is captured per each account (i.e. it has an `account` tag). See [per tags](#per_tags) for more information.
  per_application | Indicates that this metric is captured per each application (i.e. it has an `application` tag). See [per tags](#per_tags) for more information.
  change_tags | A list of *TagTransformations* whereby existing tags can be modified.

  *TagTransformation* entries in the `change_tags` attribute are as follows:

  Attribute | Description
  ------|------
   from | The name of the tag in the original spectator measurement.
   to | The name of the target tag, or a list of target tags if the old value is to be split into multiple new tags.
   type | The type of the new tag, or list of types if there are multiple target tags. The list length must be the same as `to` and each list element corresponds between the two attributes. Type can be STRING, BOOL, or INT. If not mentioned then it is INT. *Note:* It is currently looking like it might be best to leave the actual tag values as strings, some metric stores require strings (the daemon converts to strings where this is the case).
   compare_value | If the type is a BOOL then this is the `True` value. If this is not present then "true" is `True`. For example if changing "success" to a BOOL then the compare_value might be "success" so that "success" becomes True and other values become False.
   extract_regex | A regular expression to extract one or more substrings from the original value. By having multiple capture groups a given tag can be split into multiple tags. The number of capture groups should align with the `to` attribute. If the capture group is empty (or optional and not found) then that `to` tag will be given the `default_value`.
   default_value | If present, this is the default value for non-matching regex. By default this is empty.



Note that if tags are stripped from a metric then the measurement is treated as
if it never had that tag, which might involve aggregating other measurements
that only different by that dropped tag (or multiple dropped tags).

## per_tags

To deal with certain high cardinality tags, there are special attribute
`per_account` and `per_application`. These indicate that these tags are present,
however can be handled in a special way. The special way is not yet fully
realized.

In the future this could be to optionally include it or not, or to associate it
in a different way. For example in Stackdriver to have monitored resources for
applications or accounts where these metrics might [also] be associated with
the monitored resource for that specific entity, essentially factoring out the
high cardinality tag from the individual instances and into the single monitored
resource for all metrics associated with it.


# Examples

## Change the name and strip any tags

Here we change the name of the metric. The new metric will not have any
tags even if tags are encountered in the original measurement
```
    front50.requests:
      rename: front50/client/finished
      kind: Counter
      unit: requests
      tags: # None
```


## Aggregate mulitiple distinct metrics into a new composite one

Here we combine distinct failure and success metrics into a common one
injecting a "success" tag to distinguish the measurements of each.

We carry forward two tags from the original metrics. If others are
encountered then they will be dropped (but their values aggregated among
the remaining present tags).

```
    hystrix.rollingCountFallbackFailure:
      rename: hystrix/rollingCount/fallback
      kind: Gauge
      docs: Hystrix fallback outcomes over the current rolling window.
            if "success" is true then the fallback succeeded,
            otherwise it failed.
      unit: requests
      tags:
        - metricGroup
        - metricType
      add_tags:
        success: false

    hystrix.rollingCountFallbackSuccess:
      rename: hystrix/rollingCount/fallback
      kind: Gauge
      docs: Hystrix fallback outcomes over the current rolling window.
            if "success" is true then the fallback succeeded,
            otherwise it failed.
      unit: requests
      tags:
        - metricGroup
        - metricType
      add_tags:
        success: true

```    


## Convert some tag values from STRING to INT and BOOL

Here we change the HTTP status code from a string to its integer value.
Likewise we change success from a string to a boolean. The tag names
are standard so were not changed.

```
    okhttp.requests:
      rename: okhttp/completions
      kind: Timer
      docs: Records the time spent in okhttp requests and their outcome.
      unit: requests
      tags:
        - status
        - requestHost
      change_tags:
        - from: statusCode
          to: statusCode
          type: INT
        - from: success
          to: success
          type: BOOL
```


## Change some tag values

There are two changes here. One is that we are changing a non-standard
"error" attribute into a standard "success" one. The other is that
we are changing the "serviceEndpoint" tag to only indicate the region
that the service was in. If the endpoint has no region then we are
calling that a "global" region.

```
    aws.request.httpRequestTime:
      rename: platform/aws/api/http/completions
      kind: Timer
      docs: Records the time and outcome of each AWS request.
      unit: requests
      tags:
        - requestType
        - serviceName
        - serviceEndpoint
        - AWSErrorCode
      change_tags:
        - from: error
          to: success
          type: BOOL
          compare_value: 'false'
        - from: statusCode
          to: statusCode
          type: INT
        - from: serviceEndpoint
          to: region
          type: STRING
          extract_regex: '(?:[^\.]+\.)?([^\.]+-[^\.]+)\.amazonaws.com'
          default_value: global
```


## Accomodate high cardinality tags

Here we mark the counter has being `per_account` becaues it will have an
"account" tag which we may want to handle specially as discussed elsewhere.

```
    bakesRequested:
      rename: bakery/bake/calls
      kind: Counter
      docs: Number of bakes initiated.
      unit: bakes
      tags:
        - flavor
      per_account: true
```


## Split complex tag value into composite components

Here the `agent` tag value is actually composite indicating many different
pieces of information. We are going to split this apart into individual tags
so they are easier to consume and reason about.

One of the tags happens to have the same name as the original, this is
coincidence. The value will be replaced.

```
    executionTime:
      rename: clouddriver/cache/execution/successful
      kind: Timer
      docs: Records the time spent in successful caching agent executions.
            Note that this does not include time spent in unsuccessful
            executions.
      unit: executions
      per_account: true
      change_tags:
        - from: agent
          to: [provider, account, region, agent]
          type: [STRING, STRING, STRING, STRING]
          extract_regex: '([^/]+)/(?:([^/]+)/(?:([^/\[]+)/)?)?(.+)'

```

# Usage

The following instructions assume halyard > 1.13 (as of 2018-12-05,
the current version is 1.12) or from github master and can be used
with Spinnaker release 1.11 or master.


## Configuration

For the proposed schema to work, we need to add additional tags to the
metrics to identify the service coming from. This does not happen by
default so we need to configure the daemon to do this. Add the following
to a file called `spinnaker-monitoring-local.yml` and put it in the
`.hal/profiles/default/`

```
spectator:
  inject_service_tag: true
```

## Location


Place yaml files in `~/.hal/default/profiles/monitoring-daemon/filters`.
The file `default.yml` acts as a baseline. If `<service>.yml` files are
present, they will override values for the given service. This should not
be needed unless a metric common to multiple services would be mapped to
entirely different metrics depending on the service it originated in.


# Standardization

As alluded to earlier, this transformation mechanism gives us an opportunity
to reshape the metrics that Spinnaker provides. While giving new names and
structure, we should define some vocabulary and standards to provide more
consistency and clarity to what is being measured and how to consume and
interpret the data.

## Meter Vocabulary

The following standard names or patterns are used where applicable.

Name | Type | Description
---- | ---- | ----
/calls | COUNTER | Counts the calls made or things begun.
/completions | TIMER | Records the duration of a call or other process and tags describing the outcome status, suitable enough to distinguish success from failure.
/finished | COUNTER | Counts the calls that were completed where only a counter is used and not a TIMER.
/errors | COUNTER | Counts errors where only error cases are counted.
/successful | COUNTER or TIMER | Counts successes where only successful cases are counted.
.../api/... | instrumentation around an API, typically external calls. Often these will also have a method tag refining the particular entry point within the API.

## Tag Vocabulary

The following standard tags are used when applicable.

Name | Type | Description
---- | ---- | ---- 
success | BOOL | Indicates success when the metric wants to distinguish success (true) from failure (false). 
status | STRING | Indicates the HTTP Status Series (perhaps this should be called httpStatusSeries or httpSeries). e.g. "2xx". This always appears in conjunction with statusCode.
statusCode | INT | The specific HTTP response code (perhaps this should be called httpStatusCode or httpCode). e.g. 200.
platform | STRING | When the metric is for activity on a particular platform or cloud provider. e.g. "aws". This is not necessary on provider-specific meters, but where there are standard meters used to instrument platform-specific code, values should be tagged to distinguish the different platform implementations from one another.
region | STRING | The region being instrumented where applicable. The region is the native platform region name.
method | STRING | The name of the particular method if applicable. This is typically for API related instrumentation.
application | STRING | The spinnaker application where applicable. Application is a potentially high cardinality tag so should be used with care.
account | STRING | The spinnaker account where applicable. Account is a potentially high cardinality tag so should be used with care.


# Considerations

Most instrumentation are `Counter`, `Timer`, or `Gauge`. There are a few
`DistributionSummary` and a few `PercentileTimer` and
`PercentileDistributionSummary`.


## Syntax

**Historic**: Existing meters often use '.' as a hierarchical separator and are
mostly lower case. Sometimes they use camel case, sometimes they
appear to use a '.' to separate words where others might introduce
camelcase. '_' is never used.

**Proposed**: Use camelCase with '/' as a hierarchical separator (or '.', but '/'
offers easy deconfliction between old names and new names to force switch everything over).

## Terminology
"requests" is sometimes a `Counter`, and sometimes a `Timer`.
Counters are typically used when instrumenting at the starting point,
Timers at the endpoint point. Since timers are at the end, they typically
contain outcome context. Since counters are at the start, they typically do
not.

We should have a standard term when there is a count of things started
(e.g. "calls") and a standard term for the time that the call ultimately took
(e.g. "outcomes")


## Try it

An implementation of the proposed specification described in this document
can be retrieved as follows:

```
mkdir -p ~/.hal/default/profiles/monitoring-daemon/filters
git clone \
    https://github.com/ewiseblatt/spinnaker-monitoring \
    -b experimental_transforms

# Give configuration information to Halyard
cd spinnaker-monitoring
cp spinnaker-monitoring-daemon/experimental/spinnaker-monitoring-local.yml \
      ~/.hal/default/profiles/monitoring-daemon
cp spinnaker-monitoring-daemon/experimental/metric_filters/* \
      ~/.hal/default/profiles/monitoring-daemon/filters


# Install the new dashboards:

# If using Prometheus:
  GRAFANA_USER=admin
  GRAFANA_PASSWORD=admin
  GRAFANA_NETLOC=localhost:3000
  OVERWRITE=true
  SOURCE_DIR=./spinnaker-monitoring-third-party/third_party/prometheus/experimental

  for dashboard in ${SOURCE_DIR}/*-dashboard.json; do
    echo "Installing $(basename $dashboard)"
    x=$(sed -e "/\"__inputs\"/,/],/d" \
            -e "/\"__requires\"/,/],/d" \
            -e "s/\${DS_SPINNAKER\}/Spinnaker/g" < "$dashboard")
    temp_file=$(mktemp)
    echo "{ \"dashboard\": $x, \"overwrite\": $OVERWRITE }" > $temp_file
    curl -s -S -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
         http://${GRAFANA_NETLOC}/api/dashboards/import \
         -H "Content-Type: application/json" \
         -X POST \
         -d @${temp_file}
    rm -f $temp_file
  done


# If using Stackdriver. See remarks[*] in document below:
   # If you need to specify another project or credentials
   # Then set then in PROJECT_ARGS
   # PROJECT_ARGS="--project <project> --credentials_path <json_path>"

   CLI=./spinnaker-monitoring-daemon/bin/spinnaker-monitoring.sh
   pip install -r $STACKDIR/requirements.txt

   # Remove your old metric descriptors.
   $CLI clear_stackdriver $PROJECT_ARGS
   sleep 90  # give time for descriptors to clear

   $CLI clear_stackdriver $PROJECT_ARGS
   # This should return 0 cleared. If not wait longer and try again.


   # Create custom metric descriptors.
   # When we run the CLI we'll need our transform filters in place, so just link the directory here.
   ln -s `pwd`/spinnaker-monitoring-daemon/experimental/filters spinnaker-monitoring-daemon/filters
   $CLI upsert_stackdriver_descriptors $PROJECT_ARGS


   # Install the Dashboards
   #
   # You need to be whitelisted for the Stackdriver Dashboard API
   # while it is in early-access. Ask your sales rep.
   export STACKDRIVER_API_KEY=

   STACKDIR=./spinnaker-monitoring-third-party/third_party/stackdriver
   for dashboard in $STACKDIR/experimental/*-dashboard.json; do
     $CLI upload_stackdriver_dashboard --dashboard ${dashboard} $PROJECT_ARGS
   done
   
```

## Stackdriver Caveat

For stackdriver, you might want to configure it to record monitoring into a different project if
you want to be able to retain your old monitoring data if that is important to you.

Stackdriver has limitations on the number of custom metric descriptors (500 by default) you can use in a project.
Spinnaker already exceeds taht without any filtering. Therefore you will need to clear out your old
ones to make way for these new ones. Using this transform strategy, we'll consume around 125.

When you delete the descriptors you will eventually lose all your old data. You will not be able to see
the data that still exists until the descriptors are restored. If you are running an old daemon, that would be
sufficient to restore the descriptors automatically (as the meters are encountered). This also means that if
you run an unfiltered daemon, then it will add the additional old filters back which will add all those descriptors
back.

You can rerun clear_stackdriver to delete everything then either run upsert the new descriptors again
or run the old daemon depending on which way you wish to proceed.