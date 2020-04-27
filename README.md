




[Spark Driver UI](https://spark.apache.org/docs/latest/security.html#authentication-and-authorization)

Examples configuration values that might be required for a fictional customer at Acme Co.

```
# we need to provide our own authentication filter (which can also be configured here).
spark.ui.filters=com.cloudera.cde.KnoxAuthenticationFilter
spark.com.cloudera.cde.KnoxAuthenticationFilter.maxClockSkewSeconds=10

# Whether UI ACLs should be enabled. If enabled, this checks to see if the user has access permissions to 
# view or modify the application. Note this requires the user to be authenticated, so if no authentication 
# filter is installed, this option does not do anything.
spark.acls.enable=true

# Comma-separated list of groups that have view access to the Spark application.
spark.ui.view.acls.groups=ACME_CO_SPARK_USERS

# The list of groups for a user is determined by a group mapping service defined by the trait 
# org.apache.spark.security.GroupMappingServiceProvider, which can be configured by this property.
spark.user.groups.mapping=???
```

[Spark History Server](https://spark.apache.org/docs/latest/security.html#spark-history-server-acls)
```
# Specifies whether ACLs should be checked to authorize users viewing the applications in the history server. 
spark.history.ui.acls.enable=true

# Comma separated list of groups that have view access to all the Spark applications in history server.
spark.history.ui.admin.acls.groups=ACME_CO_SPARK_USERS
```

[Spark Jobs](https://spark.apache.org/docs/latest/security.html#authentication-and-authorization)

```
# Comma-separated list of groups that have view and modify access to the Spark application.
# Is this needed or enforced by the Jobs API?
spark.admin.acls.groups=ACME_CO_SPARK_ADMINS

# Comma-separated list of groups that have modify access to the Spark application.
# Is this needed or enforced by the Jobs API?
spark.modify.acls.groups=ACME_CO_SPARK_USERS

```