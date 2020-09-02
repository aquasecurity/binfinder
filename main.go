package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"

	"github.com/aquasecurity/binfinder/pkg/repository/popular"
	"github.com/aquasecurity/binfinder/pkg/repository/popular/docker"
	dtrRepo "github.com/aquasecurity/binfinder/pkg/repository/popular/dtr"
	"github.com/aquasecurity/binfinder/pkg/repository/popular/registryV2"
)

const (
	workers = 1
)

var (
	images    = flag.String("images", "", "comma separated images on which to run diff")
	outputDir = flag.String("output", "data", "output directory to store the diff files")
	topN      = flag.Int("top", 0, "top images to run binfinder")
	analyze   = flag.Bool("analyze", false, "run analysis on diff saved in data folder")

	dtr      = flag.Bool("dtr", false, "use DTR API")
	registry = flag.String("registry", "", "pulls images from registry")
	user     = flag.String("user", "", "registry user")
	password = flag.String("password", "", "registry password")

	// Common
	checkOSName     = `run -u root --rm --entrypoint cat %v /etc/os-release`
	argsAllELFFiles = `run -u root --rm -v %v/%v.sh:/%v.sh --entrypoint sh %v /%v.sh`

	// CentOS
	checkCentOSName = `run -u root --rm --entrypoint cat %v /etc/centos-release`

	// Ubuntu
	listArgs  = `run -u root --rm --entrypoint ls %v /var/lib/dpkg/info/`
	parseFile = `run -u root --rm --entrypoint cat %v /var/lib/dpkg/info/%v`

	// Alpine
	argsParseAPKFile = `run -u root --rm --entrypoint cat %v /lib/apk/db/installed`
	argsAPKInfo      = `run -u root --rm --entrypoint apk %v info -L %v`

	imageProvider popular.ImageProvider

	cli *dockerClient.Client
)

type Diffs struct {
	ImageName string
	ELFNames  []string
}

func main() {
	flag.Parse()
	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, os.ModePerm); err != nil {
			log.Fatalf("error creating output directory to save diffs: %v", err)
		}
	}
	if *analyze {
		exportAnalysis("analysis.csv")
		return
	}
	if *topN > 0 {
		if *registry != "" {
			var err error
			cli, err = dockerClient.NewEnvClient()
			if err != nil {
				log.Printf("error creating docker client for DTR: %v", err)
				return
			}
			if *dtr == true {
				imageProvider = dtrRepo.NewPopularProvider(*registry, *user, *password)
			} else {
				imageProvider = registryV2.NewPopularProvider(*registry, *user, *password)
			}
		} else {
			imageProvider = docker.NewPopularProvider()
		}
		ctx := context.Background()
		popularImges, err := imageProvider.GetPopularImages(ctx, *topN)
		if err != nil {
			log.Printf("error fetching popular images: %v", err)
			return
		}
		*images = strings.Join(popularImges, ",")
	} else {
		log.Printf("topN value is 0, running binfinder on images passed by --images flag\n")
	}
	if *images == "" {
		log.Printf("got no image to scan for diff\n")
		return
	}

	concurrency := make(chan bool, workers)
	wg := &sync.WaitGroup{}
	for _, img := range strings.Split(*images, ",") {
		// to capture cases when images are scraped from dockerhub explore page, and we don't know if "latest" is valid tag or not
		if img == "elasticsearch" {
			img = "elasticsearch:7.9.0"
		}
		// to capture cases when images are scraped from dockerhub explore page, and we don't know if "latest" is valid tag or not
		if img == "logstash" {
			img = "logstash:7.9.0"
		}
		_, err := os.Stat(fmt.Sprintf("%v/%v", *outputDir, strings.ReplaceAll(img, "/", "-")+"-diff.json"))
		if err == nil || img == "busybox" {
			log.Printf("skipping img: %v to parse diff, already present", img)
			continue
		}
		osName, err := getOS(img)
		if err != nil {
			log.Printf("unable to get OS info skipping img: %v", img)
			continue
		}
		osName = strings.ToLower(osName)
		if strings.Contains(osName, "alpine") {
			concurrency <- true
			wg.Add(1)
			go func(img string) {
				defer wg.Done()
				fetchAlpineDiff(img)
				<-concurrency
			}(img)
		} else if strings.Contains(osName, "ubuntu") || strings.Contains(osName, "debian") {
			concurrency <- true
			wg.Add(1)
			go func(img string) {
				defer wg.Done()
				fetchUbuntuDiff(img)
				<-concurrency
			}(img)
		} else if strings.Contains(osName, "centos") || strings.Contains(osName, "linux") {
			concurrency <- true
			wg.Add(1)
			go func(img string) {
				defer wg.Done()
				fetchCentOSDiff(img)
				<-concurrency
			}(img)
		}
	}
	wg.Wait()
}

func exportAnalysis(outputFile string) {
	diffFileCount := make(map[string]int64)
	filepath.Walk(*outputDir, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(info.Name(), ".json") {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			c, err := ioutil.ReadAll(f)
			if err != nil {
				return err
			}
			var d Diffs
			if err = json.Unmarshal(c, &d); err != nil {
				return err
			}
			for _, e := range d.ELFNames {
				if _, ok := diffFileCount[e]; !ok {
					diffFileCount[e] = 0
				}
				diffFileCount[e] = diffFileCount[e] + 1
			}
		}
		return nil
	})
	type binCount struct {
		name  string
		count int64
	}
	var counts []binCount
	for k, v := range diffFileCount {
		counts = append(counts, binCount{name: k, count: v})
	}

	sort.Slice(counts, func(i, j int) bool {
		if counts[i].count > counts[j].count {
			return true
		}

		return sort.StringsAreSorted([]string{counts[i].name, counts[j].name}) // if counts are equal sort by name
	})
	f, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err) // FIXME: Avoid use of log.Fatal as it makes it untestable, return err and handle it.
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	for _, c := range counts {
		w.Write([]string{c.name, fmt.Sprintf("%v", c.count)})
	}
}

func pullImage(imageName string) error {
	fmt.Printf("Pulling image: %v...\n", imageName)
	if *user != "" {
		authConfig := types.AuthConfig{
			Username: *user,
			Password: *password,
		}
		encodedJSON, err := json.Marshal(authConfig)
		if err != nil {
			log.Printf("error marshalling DTR credentials: %v", err)
			return err
		}
		authStr := base64.URLEncoding.EncodeToString(encodedJSON)
		rc, err := cli.ImagePull(context.Background(), imageName, types.ImagePullOptions{ // FIXME: rc needs to be closed by the caller.
			RegistryAuth: authStr,
		})
		if err != nil {
			log.Fatal(err) // FIXME: Avoid use of log.Fatal as it makes it untestable, return err and handle it.
		}
		if _, err = ioutil.ReadAll(rc); err != nil { // Q: What does this do?
			log.Printf("error marshalling DTR credentials: %v", err) // Q: I don't think this is the right error string to show.
			return err
		}
	} else {
		_, err := exec.Command("docker", "pull", imageName).Output()
		if err != nil {
			log.Fatal(err) // FIXME: Avoid use of log.Fatal as it makes it untestable, return err and handle it.
		}
	}
	fmt.Printf("Pulled image: %v...\n", imageName)
	return nil
}

func getOS(imageName string) (string, error) {
	pullImage(imageName)
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(checkOSName, imageName), " ")...).Output()
	if err != nil {
		// check for centOS
		// Q: Is this only needed for centos:6?
		// Q: What else is there that we need to cover?
		out, err = exec.Command("docker",
			strings.Split(fmt.Sprintf(checkCentOSName, imageName), " ")...).Output()
		if err != nil {
			return "", err
		}
	}
	return strings.Split(string(out), "\n")[0], nil
}

func fetchAlpineDiff(imageName string) {
	fmt.Printf("processing image: %v...\n", imageName)
	diffJson := Diffs{ImageName: imageName}
	allPackages := make(map[string]bool)
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(argsParseAPKFile, imageName), " ")...).Output()
	if err != nil {
		log.Printf("%v:  alpine OS, error listing apk files: %v\n", imageName, err)
		return
	}
	for _, f := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(f) != "" {
			if len(f) < 2 {
				continue
			}
			if f[:2] == "P:" || f[:2] == "o:" {
				allPackages[f[2:]] = true
			}
		}
	}
	pkgELFFiles := make(map[string]bool)
	for p := range allPackages {
		out, err = exec.Command("docker",
			strings.Split(fmt.Sprintf(argsAPKInfo, imageName, p), " ")...).Output()
		if err != nil {
			continue
		}
		for _, f := range strings.Split(string(out), "\n") {
			f = strings.TrimSpace(f)
			if f != "" && !strings.HasSuffix(f, "contains:") {
				if !strings.HasPrefix(f, "/") {
					f = "/" + f
				}
				pkgELFFiles[f] = true
			}
		}
	}
	fmt.Printf("%v: found %v packages\n", imageName, len(pkgELFFiles))
	pkgELFFiles["/usr/bin/file"] = true
	currDir, _ := os.Getwd()
	out, err = exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "alpine", "alpine", imageName, "alpine"), " ")...).Output()
	if err != nil {
		log.Printf("%v: alpine OS, error listing all elf files: %v\n", imageName, err)
		return
	}
	count := 0
	for _, f := range strings.Split(string(out), "\n") {
		parts := strings.Split(f, ":")
		if len(parts) > 1 {
			if strings.HasPrefix(strings.TrimSpace(parts[1]), "ELF") &&
				!strings.Contains(strings.TrimSpace(parts[1]), "shared object") {
				f = strings.TrimSpace(parts[0])
				if f != "" {
					count++
					if _, ok := pkgELFFiles[f]; !ok {
						diffJson.ELFNames = append(diffJson.ELFNames, strings.TrimSpace(f))
					}
				}
			}
		}
	}
	fmt.Printf("%v: found %v binaries\n", imageName, count)
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		log.Printf("%v: alpine OS, error marshalling diff: %v\n", imageName, err)
		return
	}
	file, err := os.Create(fmt.Sprintf("%v/%v", *outputDir, strings.ReplaceAll(imageName, "/", "-")+"-diff.json"))
	if err != nil {
		log.Printf("%v: alpine OS, error creating diff file: %v\n", imageName, err)
		return
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		log.Printf("%v: alpine OS, error writing diff file: %v\n", imageName, err)
		return
	}
	fmt.Printf("%v: found %v binaries installed not through a package manager\n", imageName,
		len(diffJson.ELFNames))
}

func fetchUbuntuDiff(imageName string) {
	fmt.Printf("processing image: %v...\n", imageName)
	diffJson := Diffs{ImageName: imageName}
	fileLists := make(map[string]bool)
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(listArgs, imageName), " ")...).Output()
	if err != nil {
		log.Printf("%v: ubuntu, error listing pkg files: %v\n", imageName, err)
		return
	}
	for _, f := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(f) != "" && strings.HasSuffix(f, ".list") {
			fileLists[f] = true
		}
	}

	pkgELFFiles := make(map[string]bool)
	for f := range fileLists {
		out, err = exec.Command("docker",
			strings.Split(fmt.Sprintf(parseFile, imageName, f), " ")...).Output()
		if err != nil {
			log.Printf("%v: ubuntu, error listing pkg bin files: %v\n", imageName, err)
			return
		}
		for _, content := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(content) != "" {
				pkgELFFiles[content] = true
			}
		}
	}
	fmt.Printf("%v: found %v packages\n", imageName, len(pkgELFFiles))
	pkgELFFiles["/usr/bin/file"] = true
	currDir, _ := os.Getwd()
	out, err = exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "ubuntu", "ubuntu", imageName, "ubuntu"), " ")...).Output()
	if err != nil {
		log.Printf("%v: ubuntu, error listing all bin files: %v\n", imageName, err)
		return
	}
	count := 0
	for _, f := range strings.Split(string(out), "\n") {
		parts := strings.Split(f, ":")
		if len(parts) > 1 {
			if strings.HasPrefix(strings.TrimSpace(parts[1]), "ELF") &&
				!strings.Contains(strings.TrimSpace(parts[1]), "shared object") {
				f = strings.TrimSpace(parts[0])
				if f != "" {
					count++
					if _, ok := pkgELFFiles[f]; !ok {
						diffJson.ELFNames = append(diffJson.ELFNames, strings.TrimSpace(f))
					}
				}
			}
		}
	}
	fmt.Printf("%v: found %v binaries\n", imageName, count)
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		log.Printf("%v: ubuntu, error marshalling diff: %v\n", imageName, err)
		return
	}
	file, err := os.Create(fmt.Sprintf("%v/%v", *outputDir, strings.ReplaceAll(imageName, "/", "-")+"-diff.json"))
	if err != nil {
		log.Printf("%v: ubuntu, error creating diff file: %v\n", imageName, err)
		return
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		log.Printf("%v: ubuntu, error writing diff file: %v\n", imageName, err)
		return
	}
	fmt.Printf("%v: found %v binaries installed not through a package manager\n", imageName,
		len(diffJson.ELFNames))
}

func fetchCentOSDiff(imageName string) {
	fmt.Printf("processing image: %v...\n", imageName)
	diffJson := Diffs{ImageName: imageName}
	pkgELFFiles := make(map[string]bool)
	currDir, _ := os.Getwd()
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "centos_get_all_pkg", "centos_get_all_pkg", imageName, "centos_get_all_pkg"), " ")...).Output()
	if err != nil {
		log.Printf("%v: centOS, error listing all pkg files: %v\n", imageName, err)
		return
	}
	for _, f := range strings.Split(string(out), "\n") {
		f = strings.TrimSpace(f)
		if f != "" && !strings.HasSuffix(f, "contains:") {
			if !strings.HasPrefix(f, "/") {
				f = "/" + f
			}
			pkgELFFiles[f] = true
		}
	}
	fmt.Printf("%v: found %v packages\n", imageName, len(pkgELFFiles))
	pkgELFFiles["/usr/bin/file"] = true
	out, err = exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "centos", "centos", imageName, "centos"), " ")...).Output()
	if err != nil {
		log.Printf("%v: centOS, error listing all files: %v\n", imageName, err)
		return
	}
	count := 0
	for _, f := range strings.Split(string(out), "\n") {
		parts := strings.Split(f, ":")
		if len(parts) > 1 {
			if strings.HasPrefix(strings.TrimSpace(parts[1]), "ELF") &&
				!strings.Contains(strings.TrimSpace(parts[1]), "shared object") {
				f = strings.TrimSpace(parts[0])
				if f != "" {
					count++
					if _, ok := pkgELFFiles[f]; !ok {
						diffJson.ELFNames = append(diffJson.ELFNames, strings.TrimSpace(f))
					}
				}
			}
		}
	}
	fmt.Printf("%v: found %v binaries\n", imageName, count)
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		panic(err)
	}
	file, err := os.Create(fmt.Sprintf("%v/%v", *outputDir, strings.ReplaceAll(imageName, "/", "-")+"-diff.json"))
	if err != nil {
		log.Printf("%v: error creating diff in CentOS: %v\n", imageName, err)
		return
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		log.Printf("%v: error saving CentOS diff: %v\n", imageName, err)
		return
	}
	fmt.Printf("%v: found %v binaries installed not through a package manager\n", imageName,
		len(diffJson.ELFNames))
}
