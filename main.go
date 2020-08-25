package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/binfinder/pkg/repository/popular"
	"github.com/aquasecurity/binfinder/pkg/repository/popular/docker"
)

const (
	workers = 1
)

var (
	images    = flag.String("images", "mysql,alpine", "comma separated images on which to run diff")
	outputDir = flag.String("output", "data", "output directory to store the diff files")
	topN      = flag.Int("top", 0, "top images to run binfinder on")
	analyze   = flag.Bool("analyze", false, "run analysis on diff saved in data folder")

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
)

type Diffs struct {
	ImageName string
	ELFNames  []string
}

func main() {
	flag.Parse()
	if *outputDir != "" {
		if err := os.MkdirAll(*outputDir, os.ModePerm); err != nil {
			log.Fatal(err)
		}
	}
	if *analyze {
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
		data, err := json.MarshalIndent(diffFileCount, "", " ")
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile("analysis.json", data, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		if *topN > 0 {
			imageProvider = docker.NewPopularProvider()
			ctx := context.Background()
			popularImges, err := imageProvider.GetPopularImages(ctx, *topN)
			if err != nil {
				log.Fatal(err)
			}
			*images = strings.Join(popularImges, ",")
		}
		concurrency := make(chan bool, workers)
		wg := &sync.WaitGroup{}
		for _, img := range strings.Split(*images, ",") {
			if img == "elasticsearch" {
				img = "elasticsearch:7.9.0"
			}
			if img == "logstash" {
				img = "logstash:7.9.0"
			}
			_, err := os.Stat(fmt.Sprintf("%v/%v", *outputDir, strings.ReplaceAll(img, "/", "-")+"-diff.json"))
			if err == nil || img == "busybox" {
				log.Printf("skipping img: %v", img)
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
}

func pullImage(imageName string) {
	fmt.Printf("Pulling image: %v...\n", imageName)
	_, err := exec.Command("docker", "pull", imageName).Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Pulled image: %v...\n", imageName)
	return
}

func getOS(imageName string) (string, error) {
	pullImage(imageName)
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(checkOSName, imageName), " ")...).Output()
	if err != nil {
		// check for centOS
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
		log.Fatal(err)
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
		log.Fatal(err)
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
		panic(err)
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		panic(err)
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
		log.Fatal(err)
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
			log.Fatal(err)
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
		log.Fatal(err)
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
		panic(err)
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		panic(err)
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
		log.Fatal(err)
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
		log.Fatal(err)
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
		panic(err)
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v: found %v binaries installed not through a package manager\n", imageName,
		len(diffJson.ELFNames))
}
