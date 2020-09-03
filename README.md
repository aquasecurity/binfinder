# binfinder
Find binary files not installed through package manager


## Prerequisites

### Software

- go version &gt;= 1.12.4 <https://golang.org/>
  - if you're on a sensible o/s: `$ pacman -S go go-tools`
  - if you're on Mac, you can install using Brew `brew install go`
    - You can install brew using `ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
  - for Windows/installers please visit [Golang Downloads](https://golang.org/dl/)
- docker version &gt;= 19
  - for download please visit [Docker Downlaods](https://docs.docker.com/engine/install/)


## How to run the binfinder
You can initiatite the build of server using command
```bash
$ go build -o binfinder .
```
Once the build is complete, you can run the bindfinder by running:
```
$ ./binfinder --images <comma separated list of image> --output data --top 20
```
The output will be diff files per image, top flag(default 0) if value greater than 0 pulls the popular N images to run binfinder upon.

To run analysis on diff files created after finding diffs, you can run analysis to get count per diff across all json files:
```
$ ./binfinder --analyze --output data
```
The output will be analysis.csv file.

To run binfinder on registry pass `--registry host` flag to CLI
```
$ ./binfinder --top=10 --registry=http://localhost:5000 --output data
```
CLI will pull images from repositry and check for binary diffs.

To run binfinder on DTR registry pass `--registry host --dtr --user={USER} --password={PASSWORD}` flag to CLI
```
$ ./binfinder --top=10 --registry=https://vm01-7b86bb7b.westeurope.cloudapp.azure.com:8443 --dtr --user={user} --password={password} --output data
```
CLI will pull images from DTR and check for binary diffs.

## Note:
* Binfinder requires shell files alpine.sh, ubuntu.sh, centos.sh, and centos_get_all_pkg.sh files to work, these shell files
must be present in the directory from where the command is to be executed.
* To improve performance pull the docker image before hand.
