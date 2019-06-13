// Copyright © 2019 Ami Mahloof <ami.mahloof@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.package main

package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
)

// FirewallRule contains rule name tags
type FirewallRule struct {
	Name string
	Tags []string
}

// VMInstance contains instance Name and NetworkTags
type VMInstance struct {
	Name        string
	NetworkTags []string
}

// LogrusFileHook filehook formatter
type LogrusFileHook struct {
	file      *os.File
	flag      int
	chmod     os.FileMode
	formatter *logrus.TextFormatter
}

func newLogrusFileHook(file string, flag int, chmod os.FileMode) (*LogrusFileHook, error) {
	plainFormatter := &logrus.TextFormatter{DisableColors: true}
	logFile, err := os.OpenFile(file, flag, chmod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to write file on filehook %v", err)
		return nil, err
	}

	return &LogrusFileHook{logFile, flag, chmod, plainFormatter}, err
}

// Fire event
func (hook *LogrusFileHook) Fire(entry *logrus.Entry) error {
	plainformat, err := hook.formatter.Format(entry)
	line := string(plainformat)
	_, err = hook.file.WriteString(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to write file on filehook(entry.String) %v", err)
		return err
	}

	return nil
}

// Levels logrus levels for filehook
func (hook *LogrusFileHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

func isEmptyIntersection(set1, set2 []string) bool {
	for _, val1 := range set1 {
		for _, val2 := range set2 {
			if val1 == val2 {
				return false
			}
		}
	}
	return true
}

func getFirewallRulesForTargetTags(computeService *compute.Service, projectID string) (*[]FirewallRule, error) {
	var rules []FirewallRule
	ctx := context.Background()
	req := computeService.Firewalls.List(projectID).Filter(`direction="ingress"`)
	if err := req.Pages(ctx, func(page *compute.FirewallList) error {
		log.Info("listing only TargetTags rules...")
		for _, firewall := range page.Items {
			if len(firewall.TargetTags) > 0 {
				rules = append(rules, FirewallRule{Name: firewall.Name, Tags: firewall.TargetTags})
			}
		}
		return nil
	}); err != nil {
		log.Errorf("error getting firewall rules: %v", err)
		return nil, err
	}
	log.Infof("number of TargetTags Rules: %d", len(rules))
	log.Debugf("firewall Rules: %v", rules)
	return &rules, nil
}

func getVMInstances(computeService *compute.Service, projectID string) (*[]VMInstance, error) {
	ctx := context.Background()
	var instances []VMInstance
	req := computeService.Instances.AggregatedList(projectID)
	if viper.GetBool("running") {
		req.Filter(`status=Running`)
	}
	if err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, instancesScopedList := range page.Items {
			for _, vmInstance := range instancesScopedList.Instances {
				instances = append(instances, VMInstance{
					Name:        vmInstance.Name,
					NetworkTags: vmInstance.Tags.Items,
				})
			}
		}
		return nil
	}); err != nil {
		log.Warnf("error listing VM instances %v", err)
		return nil, err
	}

	return &instances, nil
}

func getOrphanedFirewallRules(computeService *compute.Service, projectID string, firewallRules *[]FirewallRule, orphans map[string]FirewallRule) (map[string]FirewallRule, error) {
	log.Debug("getting list of VM instances in project...")
	vmInstances, err := getVMInstances(computeService, projectID)
	if err != nil {
		return orphans, err
	}

	log.Infof("making a list of orphaned rules with all rules (active rules will be removed from it)")
	for _, rule := range *firewallRules {
		if rule.Name != "nil" {
			orphans[rule.Name] = rule
		}
		fmt.Printf("%s, %s", projectID, rule.Name)
	}

	log.Info("looking for orphaned rules in project..")
	for _, rule := range *firewallRules {
		for _, instance := range *vmInstances {
			if len(instance.NetworkTags) > 0 {
				log.Debugf(
					"%v - current rule tags:: %v - VM Instance network tags:: %v - match?: %v",
					instance.Name,
					rule.Tags,
					instance.NetworkTags,
					!isEmptyIntersection(rule.Tags, instance.NetworkTags),
				)
				if !isEmptyIntersection(rule.Tags, instance.NetworkTags) {
					if _, ok := orphans[rule.Name]; ok {
						log.Infof("remove active rule from orphans list: %v", rule.Name)
						delete(orphans, rule.Name)
					}
				}
			} else {
				log.Warnf(
					"skipping instance %v since it does not have any network tags",
					instance.Name,
				)
			}
		}
	}

	log.Infof("%v potential orphaned firewall rules to evalute...", len(orphans))
	for _, orphan := range orphans {
		log.Debugf("potential orphan rule name: %v", orphan.Name)
	}
	return orphans, nil
}

func getChildProjects(computeService *compute.Service, hostProjectID string) ([]string, error) {
	ctx := context.Background()
	var childProjects []string
	req := computeService.Projects.GetXpnResources(hostProjectID)

	if err := req.Pages(ctx, func(page *compute.ProjectsGetXpnResources) error {
		for _, xpnResourceID := range page.Resources {
			childProjects = append(childProjects, xpnResourceID.Id)
		}
		return nil
	}); err != nil {
		log.Errorf("error listing child projects (XPN Resources): %v", err)
		return nil, err
	}
	return childProjects, nil
}

func initClient() (*compute.Service, error) {
	ctx := context.Background()
	oauthClient, err := google.DefaultClient(ctx, compute.CloudPlatformScope)
	computeService, err := compute.New(oauthClient)
	if err != nil {
		return nil, err
	}
	return computeService, nil
}

func generateCSV(orphanedRules map[string]FirewallRule) error {
	filename := "orphaned-rules.csv"
	log.Info("creating a new CSV file: ", filename)
	file, err := os.Create(filename)
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err != nil {
		log.Errorf("error creating file %s - %v", filename, err)
		return err
	}
	records := [][]string{
		{"rule-name", "rule-tags"},
	}
	for _, rule := range orphanedRules {
		data := []string{
			rule.Name,
			fmt.Sprintf("%v", strings.Join(rule.Tags, ",")),
		}
		records = append(records, data)
	}
	err = writer.WriteAll(records)
	if err != nil {
		return err
	}
	return nil
}

func setLogger() *logrus.Logger {
	lvlDebug := viper.GetBool("debug")
	logfileName := "orphaned-firewall-rules-gcp.log"
	var logLevel log.Level

	if lvlDebug {
		logLevel = log.DebugLevel
	} else {
		logLevel = log.InfoLevel
	}

	logrus := &logrus.Logger{
		Out: os.Stdout,
		Formatter: &logrus.TextFormatter{
			ForceColors:   true,
			FullTimestamp: true,
		},
		Hooks: make(logrus.LevelHooks),
		Level: logLevel,
	}
	fileHook, err := newLogrusFileHook(logfileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		log.Error("error creating log file: ", logfileName)
	}
	logrus.Hooks.Add(fileHook)
	return logrus
}

func setCmdLineFlags() {
	flag.Bool("debug", false, "Set log level")
	flag.Bool("running", false, "Filter only running VM instances")
	flag.String("host", "", "Host Project ID < Required>")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	flag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	if viper.IsSet("host") {
		log.Errorf("host flag is not set")
		flag.PrintDefaults()
		os.Exit(1)
	}

}

func main() {
	setCmdLineFlags()
	log := setLogger()
	log.Infof("creating a new Compute API client")
	computeService, err := initClient()
	if err != nil {
		log.Fatalf("error creating compute client: %s", err)
	}

	hostProject := viper.GetString("host")
	log.Info("host project: ", hostProject)
	childProjects, err := getChildProjects(computeService, hostProject)
	if err != nil {
		log.Errorf("error getting child projects for host project %s, %v", hostProject, err)
	}

	log.Infof("firewall Rules for host project: %s", hostProject)
	firewallRules, err := getFirewallRulesForTargetTags(computeService, hostProject)
	if err != nil {
		log.Fatalf("error getting firewall rules for host project %s, %v", hostProject, err)
	}

	orphanedRules := make(map[string]FirewallRule, len(*firewallRules))
	for _, childProject := range childProjects {
		log.Infof("child project: %s", childProject)
		orphanedRules, err = getOrphanedFirewallRules(
			computeService,
			childProject,
			firewallRules,
			orphanedRules,
		)
		if err != nil {
			log.Warnf("Could not check project %s for orphaned rules: %s", childProject, err)
		}
	}

	log.Info("generating CSV file for orphaned rules...")
	err = generateCSV(orphanedRules)
	if err != nil {
		log.Errorf("error saving rules to csv - %v", err)
	}
	log.Info("done!")
}
