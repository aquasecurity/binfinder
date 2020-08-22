package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var (
	images = flag.String("images", "mongo:latest,grafana/grafana", "comma separated images on which to run diff")

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
)

type Diffs struct {
	ImageName string
	ELFNames  []string
}

func main() {
	flag.Parse()
	wg := &sync.WaitGroup{}
	for _, img := range strings.Split(*images, ",") {
		osName := strings.ToLower(getOS(img))
		if strings.Contains(osName, "alpine") {
			wg.Add(1)
			go func(img string) {
				defer wg.Done()
				fetchAlpineDiff(img)
			}(img)
		} else if strings.Contains(osName, "ubuntu") || strings.Contains(osName, "debian") {
			wg.Add(1)
			go func(img string) {
				defer wg.Done()
				fetchUbuntuDiff(img)
			}(img)
		} else if strings.Contains(osName, "centos") {
			wg.Add(1)
			go func(img string) {
				defer wg.Done()
				fetchCentOSDiff(img)
			}(img)
		}
	}
	wg.Wait()
}

func getOS(imageName string) string {
	out, err := exec.Command("docker",
		strings.Split(fmt.Sprintf(checkOSName, imageName), " ")...).Output()
	if err != nil {
		// check for centOS
		out, err = exec.Command("docker",
			strings.Split(fmt.Sprintf(checkCentOSName, imageName), " ")...).Output()
		if err != nil {
			log.Fatal(err)
		}
	}
	return strings.Split(string(out), "\n")[0]
}

func fetchAlpineDiff(imageName string) {
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
		//if err != nil {
		//	log.Fatal(err)
		//}
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
	pkgELFFiles["/usr/bin/file"] = true
	currDir, _ := os.Getwd()
	out, err = exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "alpine", "alpine", imageName, "alpine"), " ")...).Output()
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range strings.Split(string(out), "\n") {
		parts := strings.Split(f, ":")
		if len(parts) > 1 {
			if strings.HasPrefix(strings.TrimSpace(parts[1]), "ELF") &&
				!strings.Contains(strings.TrimSpace(parts[1]), "shared object") {
				f = strings.TrimSpace(parts[0])
				if f != "" {
					if _, ok := pkgELFFiles[f]; !ok {
						diffJson.ELFNames = append(diffJson.ELFNames, strings.TrimSpace(f))
					}
				}
			}
		}

	}
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		panic(err)
	}
	file, err := os.Create(strings.ReplaceAll(imageName, "/", "-") + "-diff.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v: found %v files installed from package manager and %v from other sources\n", imageName,
		len(pkgELFFiles), len(diffJson.ELFNames))
}

func fetchUbuntuDiff(imageName string) {
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
	pkgELFFiles["/usr/bin/file"] = true
	currDir, _ := os.Getwd()
	out, err = exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "ubuntu", "ubuntu", imageName, "ubuntu"), " ")...).Output()
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range strings.Split(string(out), "\n") {
		parts := strings.Split(f, ":")
		if len(parts) > 1 {
			if strings.HasPrefix(strings.TrimSpace(parts[1]), "ELF") &&
				!strings.Contains(strings.TrimSpace(parts[1]), "shared object") {
				f = strings.TrimSpace(parts[0])
				if f != "" {
					if _, ok := pkgELFFiles[f]; !ok {
						diffJson.ELFNames = append(diffJson.ELFNames, strings.TrimSpace(f))
					}
				}
			}
		}
	}
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		panic(err)
	}
	file, err := os.Create(strings.ReplaceAll(imageName, "/", "-") + "-diff.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v: found %v files installed from package manager and %v from other sources\n", imageName,
		len(pkgELFFiles), len(diffJson.ELFNames))
}

func fetchCentOSDiff(imageName string) {
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
	pkgELFFiles["/usr/bin/file"] = true
	out, err = exec.Command("docker",
		strings.Split(fmt.Sprintf(argsAllELFFiles, currDir, "centos", "centos", imageName, "centos"), " ")...).Output()
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range strings.Split(string(out), "\n") {
		parts := strings.Split(f, ":")
		if len(parts) > 1 {
			if strings.HasPrefix(strings.TrimSpace(parts[1]), "ELF") &&
				!strings.Contains(strings.TrimSpace(parts[1]), "shared object") {
				f = strings.TrimSpace(parts[0])
				if f != "" {
					if _, ok := pkgELFFiles[f]; !ok {
						diffJson.ELFNames = append(diffJson.ELFNames, strings.TrimSpace(f))
					}
				}
			}
		}
	}
	content, err := json.MarshalIndent(diffJson, "", " ")
	if err != nil {
		panic(err)
	}
	file, err := os.Create(strings.ReplaceAll(imageName, "/", "-") + "-diff.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	_, err = io.Copy(file, bytes.NewReader(content))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v:found %v files installed from package manager and %v from other sources\n", imageName,
		len(pkgELFFiles), len(diffJson.ELFNames))
}
