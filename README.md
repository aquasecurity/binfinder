# binfinder
Find binary files not installed through package manager

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
The output will be analysis.json file.

## Note:
* Binfinder requires shell files alpine.sh, ubuntu.sh, centos.sh, and centos_get_all_pkg.sh files to work, these shell files
must be present in the directory from where the command is to be executed.
* To improve performance pull the docker image before hand.
