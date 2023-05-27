# Magnus examples

These have been tested on MacOS and may require modifications to work on other systems.

## Instructions

### Install Maven

How exactly you do this depends on the OS. If you're on a Mac and have Homebrew installed, `brew install maven` should do it.

### Add the packages to Maven

```
mvn install:install-file \
-Dfile=AWSMagnusControlPlaneJavaClient-1.12.x.jar \
-DgroupId=com.amazonaws.services.magnuscontrolplane \
-DartifactId=magnuscontrolplane \
-Dversion=1.12.x \
-Dpackaging=jar

mvn install:install-file \
-Dfile=AWSMagnusDataPlaneJavaClient-1.12.x.jar \
-DgroupId=com.amazonaws.services.magnusdataplane \
-DartifactId=magnusdataplane \
-Dversion=1.12.x \
-Dpackaging=jar
```

### Build this stuff

If you have make installed:

```
make clean
make
```

If you don't:

```
mvn clean
mvn package
```

In both cases the clean step is unnecessary if it's the first time you're building it.

### Set up your creds

The examples pull your AWS credentials from environment variables, so you'll need to get them from whatever system you use and add them to the environment like so:

```
export AWS_ACCESS_KEY_ID=ASIA....
export AWS_SECRET_ACCESS_KEY=abcd....
export AWS_SESSION_TOKEN=wxyz....
```

### Run the examples

There are four examples. Most of the detailed API interaction logic is in the ControlPlaneUtils and DataPlaneUtils classes; the four below use those helper functions to call the API.

#### CreateAlias

This will create an alias, either with a name you provide or a random one if you don't specify anything. The main purpose of this is to demonstrate basic operations against the API.

`./run_example.sh CreateAlias` or `./run_example.sh CreateAlias "alias/testalias-abcde"`

#### ListAliases

This will list all the aliases in your account, plus what key they point to (if any).

The main purpose of this example is to let you inspect your resources and see how pagination works.

`./run_example.sh ListAliases`

#### ListKeys

This will list all the keys in your account, with a bit of info about each one's type. 

The main purpose of this example is to let you inspect your resources and see how pagination works, as well as show some ways in which interacting with keys is different than interacting with aliases (for example, the attributes are nested more deeply, and ListKeys only returns the ARN, not all the info about the object, so an additional GetKey call is necessary).

`./run_example.sh ListKeys`

#### Create Params For Import

This will create the params for import.

The main purpose of this example is to provide the inputs needed to import a Zone Master Key/KEK using TR-34. This API is not idempotent
(that is it returns different results each time), but each result is valid until the time specified in the request.
`./run_example.sh CreateParamsForImport`

#### Demo

This will create keys behind aliases, generate a pin block, then translate that pin block to a different key and format. It takes one optional argument, which it'll append as a suffix on the alias names. If it's run multiple times, it'll use the same keys instead of generating new ones unless you change the suffix.

The main purpose of this example is to show how to perform basic dataplane operations.

`./run_example Demo` or `./run_example Demo "-1"`
