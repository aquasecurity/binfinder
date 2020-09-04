package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
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
	"time"

	"github.com/docker/docker/api/types"
	dockerClient "github.com/docker/docker/client"

	"github.com/aquasecurity/binfinder/pkg/contract"
	"github.com/aquasecurity/binfinder/pkg/repository/popular"
	"github.com/aquasecurity/binfinder/pkg/repository/popular/docker"
	dtrRepo "github.com/aquasecurity/binfinder/pkg/repository/popular/dtr"
	"github.com/aquasecurity/binfinder/pkg/repository/popular/registryV2"
)

var (
	images    = flag.String("images", "", "comma separated images on which to run diff")
	outputDir = flag.String("output", "data", "output directory to store the diff files")
	topN      = flag.Int("top", 0, "top images to run binfinder")
	analyze   = flag.Bool("analyze", false, "run analysis on diff saved in data folder")
	workers   = flag.Int("workers", 1, "run binfinder in parallel on multiple images")

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

	cli contract.DockerContract
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
		log.Printf("analyzing results and saving to: analysis.csv")
		exportAnalysis("analysis.csv")
		return
	}
	var err error
	cli, err = dockerClient.NewEnvClient()
	if err != nil {
		log.Printf("binfinder expects docker daemon running on the machine: %v", err)
		return
	}
	if !isDockerDaemonRunning() {
		log.Printf("binfinder expects docker daemon running on the machine")
		return
	}
	if *topN > 0 {
		if *registry != "" {
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

	concurrency := make(chan bool, *workers)
	wg := &sync.WaitGroup{}
	for _, img := range strings.Split(*images, ",") {
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

func isDockerDaemonRunning() bool {
	_, err := cli.Info(context.Background())
	if err != nil {
		return false
	}
	return true
}

func exportAnalysis(outputFile string) {
	diffFileCount := make(map[string]int64)
	filepath.Walk(*outputDir, func(path string, info os.FileInfo, err error) error {
		if info == nil {
			return nil
		}
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
				log.Printf("%v found invalid json file: %v", info.Name(), err)
				return nil
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
		log.Printf("error exporting analysis, got error: %v", err)
		return
	}
	w := csv.NewWriter(f)
	defer w.Flush()
	for _, c := range counts {
		if err = w.Write([]string{c.name, fmt.Sprintf("%v", c.count)}); err != nil {
			log.Printf("error writing row to CSV analysis, got error: %v", err)
		}
	}
}

func pullImage(imageName string) error {
	fmt.Printf("Pulling image: %v...\n", imageName)
	if *user != "" {
		if *password == "" {
			return errors.New(fmt.Sprintf("%v: pull image expects valid password for user", imageName))
		}
		authConfig := types.AuthConfig{
			Username: *user,
			Password: *password,
		}
		encodedJSON, err := json.Marshal(authConfig)
		if err != nil {
			log.Printf("error marshalling registry credentials: %v", err)
			return err
		}
		authStr := base64.URLEncoding.EncodeToString(encodedJSON)
		imageNameWithHost := imageName
		if *registry == "" {
			imageNameWithHost = "docker.io/library/" + imageName
		}
		rc, err := cli.ImagePull(context.Background(), imageNameWithHost, types.ImagePullOptions{
			RegistryAuth: authStr,
		})
		if err != nil {
			log.Printf("%v: error pulling image: %v", imageName, err)
			return err
		}
		return rc.Close()
	}
	_, err := exec.Command("docker", "pull", imageName).Output()
	if err != nil {
		log.Printf("%v: error pulling image: %v", imageName, err)
		return err
	}
	fmt.Printf("Pulled image: %v...\n", imageName)
	return nil
}

func getOS(imageName string) (string, error) {
	if err := pullImage(imageName); err != nil {
		return "", err
	}
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(checkOSName, imageName), " ")...).Output()
	if err != nil {
		// check for centOS
		// Q: Is this only needed for centos:6?
		// Ans: Yes for centos based images the OS information is kept in /etc/centos-release, while in other OS its /etc/os-release.
		// Q: What else is there that we need to cover?
		// Ans: Did not find any other image which fails in top 50 images from docker one case way busybox based image they also don't had any OS check file
		out, err = exec.Command("docker",
			strings.Split(fmt.Sprintf(checkCentOSName, imageName), " ")...).Output()
		if err != nil {
			return "", err
		}
	}
	return strings.Split(string(out), "\n")[0], nil
}

func getPackages(osName string, imageName string, command ...string) ([]byte, error) {
	fmt.Printf("processing image: %v...\n", imageName)
	out, err := exec.Command("docker", command...).Output()
	if err != nil {
		log.Printf("%v:  %s OS, error listing package files: %v\n", imageName, osName, err)
		return nil, err
	}
	return out, nil
}

func findBins(pkgELFFiles map[string]bool, osName string, imageName string, diffJson *Diffs, command ...string) int {
	pkgELFFiles["/usr/bin/file"] = true
	out, err := exec.Command("docker", command...).Output()
	if err != nil {
		log.Printf("%v: %s OS, error listing all elf files: %v\n", imageName, osName, err)
		return 0
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
	return count
}

func generateDiffFile(diffJson Diffs, osName string, imageName string) {
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		log.Printf("%v: %s, error marshalling diff: %v\n", osName, imageName, err)
		return
	}
	file, err := os.Create(fmt.Sprintf("%v/%v", *outputDir, strings.ReplaceAll(imageName, "/", "-")+"-diff.json"))
	if err != nil {
		log.Printf("%v: %s, error creating diff file: %v\n", osName, imageName, err)
		return
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		log.Printf("%v: %s, error writing diff file: %v\n", osName, imageName, err)
		return
	}
	fmt.Printf("%v: found %v binaries installed not through a package manager\n", imageName,
		len(diffJson.ELFNames))
}

func fetchAlpineDiff(imageName string) {
	now := time.Now()
	diffJson := Diffs{ImageName: imageName}
	allPackages := make(map[string]bool)

	out, err := getPackages("alpine", imageName, strings.Split(fmt.Sprintf(argsParseAPKFile, imageName), " ")...)
	if err != nil {
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
	fmt.Printf("%v: found %v packages took %v\n", imageName, len(pkgELFFiles), time.Since(now))

	now = time.Now()
	currDir, _ := os.Getwd()
	cmd := strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "alpine", "alpine", imageName, "alpine"), " ")
	count := findBins(pkgELFFiles, "alpine", imageName, &diffJson, cmd...)

	fmt.Printf("%v: found %v binaries took %v\n", imageName, count, time.Since(now))
	generateDiffFile(diffJson, "alpine", imageName)

}

func fetchUbuntuDiff(imageName string) {
	now := time.Now()
	diffJson := Diffs{ImageName: imageName}
	fileLists := make(map[string]bool)
	pkgELFFiles := make(map[string]bool)

	out, err := getPackages("ubuntu", imageName, strings.Split(fmt.Sprintf(listArgs, imageName), " ")...)
	if err != nil {
		return
	}

	for _, f := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(f) != "" && strings.HasSuffix(f, ".list") {
			fileLists[f] = true
		}
	}
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
	fmt.Printf("%v: found %v packages took %v\n", imageName, len(pkgELFFiles), time.Since(now))

	now = time.Now()
	currDir, _ := os.Getwd()
	cmd := strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "ubuntu", "ubuntu", imageName, "ubuntu"), " ")
	count := findBins(pkgELFFiles, "ubuntu", imageName, &diffJson, cmd...)

	fmt.Printf("%v: found %v binaries took %v\n", imageName, count, time.Since(now))
	generateDiffFile(diffJson, "ubuntu", imageName)
}

func fetchCentOSDiff(imageName string) {
	now := time.Now()
	diffJson := Diffs{ImageName: imageName}
	pkgELFFiles := make(map[string]bool)
	currDir, _ := os.Getwd()

	out, err := getPackages("centOS", imageName, strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "centos_get_all_pkg", "centos_get_all_pkg", imageName, "centos_get_all_pkg"), " ")...)
	if err != nil {
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
	fmt.Printf("%v: found %v packages took %v\n", imageName, len(pkgELFFiles), time.Since(now))

	now = time.Now()
	cmd := strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "centos", "centos", imageName, "centos"), " ")
	count := findBins(pkgELFFiles, "centOS", imageName, &diffJson, cmd...)

	fmt.Printf("%v: found %v binaries took %v\n", imageName, count, time.Since(now))
	generateDiffFile(diffJson, "centOS", imageName)
}
