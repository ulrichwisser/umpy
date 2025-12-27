package main

import (
	"os"
	"fmt"
	"sync"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"

	"github.com/apex/log"
	"github.com/apex/log/handlers/text"
)

const MINAGE = "MinAge"
const MAXAGE = "MaxAge"
const MINVALID = "MinValid"
const MAXVALID = "MaxValid"
const DEFAULT_MINAGE int = 4 * 60 * 60         // 4 hours
const DEFAULT_MAXAGE int = 4 * 24 * 60 * 60    // 4 days
const DEFAULT_MINVALID int = 21 * 24 * 60 * 60 // 21 days
const DEFAULT_MAXVALID int = 30 * 24 * 60 * 60 // 30 days

const NSEC3_MAXITERATIONS = "MaxNsec3Iterations"
const NSEC3_OPTOUTOK = "Nsec3OptOutOk"

const DEFAULT_NSEC3_MAXITERATIONS int = 10
const DEFAULT_NSEC3_OPTOUTOK bool = false

const CHECK_NSEC = "CheckNSEC"
const CHECK_NSEC3 = "CheckNSEC3"
const CHECK_RRSIG = "CheckRRSIG"

const VERBOSE = "verbose"
const VERBOSE_QUIET int = 0
const VERBOSE_ERROR int = 1
const VERBOSE_WARNING int = 2
const VERBOSE_INFO int = 3
const VERBOSE_DEBUG int = 4
const VERBOSE_TRACE int = 5

const MULTISIGNER = "MultiSigner"
const DEFAULT_MULTISIGNER bool = false

type Cache map[string]map[string][]dns.RR

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:                   "umpy [-v] [--nsec] [--nsec3] [--norrsig] [-f <config file>] [--now <timestamp>] [<zone file name>]",
	Version:               "0.0.1a",
	Short:                 "Validate DNSSEC information in a zone file",
	Long:                  `umpy validates DNSSEC information in a zone file.`,
	Run:                   func(cmd *cobra.Command, args []string) { run(args) },
	DisableFlagsInUseLine: true,
	Args:                  cobra.MaximumNArgs(1),
}

func main() {
	// default logging to STDERR
	log.SetHandler(text.New(os.Stderr))

	// Use flags for viper values
	viper.BindPFlags(pflag.CommandLine)

	if err := rootCmd.Execute(); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	// Set default log handler
	log.SetHandler(text.New(os.Stderr))

	cobra.OnInitialize(initConfig)

	rootCmd.Flags().CountP(VERBOSE, "v", "repeat for more verbose printouts")
	rootCmd.Flags().Bool("nsec", true, "validate nsec chain")
	rootCmd.Flags().Bool("nsec3", true, "validate nsec3 chain")
	rootCmd.Flags().Bool("norrsig", false, "disable rrsig validation")
	rootCmd.Flags().String("now", "", "reference time for signature validation")
	rootCmd.Flags().StringP("config", "f", "", "config file (default is $HOME/.umpy)")

	// Use flags for viper values
	viper.BindPFlags(rootCmd.Flags())
}

// initConfig reads in config file and ENV variables if set.sdfsdf					
func initConfig() {


	// init log level
	switch viper.GetInt(VERBOSE) {
		case VERBOSE_QUIET:   	log.SetLevel(log.FatalLevel)
		case VERBOSE_ERROR:   	log.SetLevel(log.ErrorLevel)
		case VERBOSE_WARNING: 	log.SetLevel(log.WarnLevel)
		case VERBOSE_INFO:    	log.SetLevel(log.InfoLevel)
		case VERBOSE_DEBUG:   	log.SetLevel(log.DebugLevel)
		default: 				log.SetLevel(log.ErrorLevel)
	}

	// Set defaults
	//
	// default log loglevel
	viper.SetDefault(VERBOSE, VERBOSE_QUIET)

	// Default signature life times
	viper.SetDefault(MINAGE, DEFAULT_MINAGE)
	viper.SetDefault(MAXAGE, DEFAULT_MAXAGE)
	viper.SetDefault(MINVALID, DEFAULT_MINVALID)
	viper.SetDefault(MAXVALID, DEFAULT_MAXVALID)

	// Allow recommended digest types
	viper.SetDefault("SHA1", false)
	viper.SetDefault("SHA256", true)
	viper.SetDefault("GOST94", false)
	viper.SetDefault("SHA384", true)
	viper.SetDefault("SHA512", true)

	// Allow recommended algorithms
	viper.SetDefault("RSASHA256", true)
	viper.SetDefault("RSASHA512", true)
	viper.SetDefault("ECDSAP256SHA256", true)
	viper.SetDefault("ECDSAP384SHA384", true)
	viper.SetDefault("ED25519", true)
	viper.SetDefault("ED448", true)

	// Which checks should be performed
	viper.SetDefault(CHECK_RRSIG, true)

	// Default values for NSEC3 checks
	viper.SetDefault(NSEC3_MAXITERATIONS, DEFAULT_NSEC3_MAXITERATIONS)
	viper.SetDefault(NSEC3_OPTOUTOK, DEFAULT_NSEC3_OPTOUTOK)

	// Multisigner
	viper.SetDefault(MULTISIGNER, DEFAULT_MULTISIGNER)

	// Find home directory.
	home, err := homedir.Dir()
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	// Search config in home directory with name ".umpy" (without extension).
	viper.SetConfigName(".umpy")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(home)
	viper.AddConfigPath(".")

	// config file specified om command line
	if viper.GetString("config") != "" {
		// Use config file from the flag.
		viper.SetConfigFile(viper.GetString("config"))
	}

	// read in environment variables that match
	viper.SetEnvPrefix("UMPY")
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		if len(viper.GetString("config")) > 0 {
			log.Fatalf("Error reading config file: '%s' %s",viper.GetString("config"), err.Error())
		}
		log.Info(err.Error())
	} else {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}

	// special handling of dnssec timing data
	// user specified strings need to be converted to  int
	for _, opt := range []string{MINAGE, MAXAGE, MINVALID, MAXVALID} {
		if viper.GetInt(opt) == 0 { // this indicates there is no int value
			value, parserOk := stringToTTL(viper.GetString(opt))
			if !parserOk {
				log.Errorf("Could not parse config %s value %s\n", opt, viper.GetString(opt))
				os.Exit(5)
			}
			viper.Set(opt, value)
		}
	}
}

func run(args []string) {
	//
	// Take care of command line arguments
	//
	if viper.GetBool("norrsig") {
		viper.Set(CHECK_RRSIG, false)
	}
	if viper.IsSet("nsec") {
		viper.Set(CHECK_NSEC, viper.GetBool("nsec"))
	}
	if viper.IsSet("nsec3") {
		viper.Set(CHECK_NSEC3, viper.GetBool("nsec3"))
	}

	//
	// ZONE FILE
	//
	log.Debug("Start reading zone file")
	var zonef *os.File
	if len(args) > 0 {
		var err error
		zonef, err = os.Open(args[0])
		if err != nil {
			log.Errorf("Could not open zonefile %s", args[0])
			log.Error(err.Error())
			os.Exit(5)
		}
	} else {
		zonef = os.Stdin
	}

	origin, cache := readZonefile(zonef)

	// close the file we opened
	if len(args) > 0 {
		zonef.Close()
	}
	log.Debug("Zone file successfully read.")


	if len(cache) == 0 {
		log.Info("Zone file empty.")
		os.Exit(1)
	}

	// check for NSEC chain
	if !viper.IsSet(CHECK_NSEC) {
		foundNSEC := hasNSEC(cache)
		viper.Set(CHECK_NSEC, foundNSEC)
	}
		if viper.GetBool(CHECK_NSEC) {
			log.Debug("NSEC records will be checked.")
		} else {
			log.Debug("NSEC records will not be checked.")
		}

	// check for NSEC3 chain
	if !viper.IsSet(CHECK_NSEC3) {
		foundNSEC3 := hasNSEC3(cache)
		viper.Set(CHECK_NSEC3, foundNSEC3)
		if viper.GetInt("verbose") >= VERBOSE_DEBUG {
		}
	}
		if viper.GetBool(CHECK_NSEC3) {
			log.Debug("NSEC3 records will be checked.")
		} else {
			log.Debug("NSEC3 records will not be checked.")
		}

	/******************************************************

	START CHECKING

	******************************************************/
	var wg sync.WaitGroup
	results := make(chan Result)

	go RunTest("DNSKEY", cache, origin, checkDNSKEY, &wg, results)
	go RunTest("DS", cache, origin, checkDS, &wg, results)
	go RunTest("CDS", cache, origin, checkCDS, &wg, results)
	go RunTest("CDNSKEY", cache, origin, checkCDNSKEY, &wg, results)
	go RunTest("SOA", cache, origin, checkSOA, &wg, results)
	wg.Add(5)

	// RRSIG
	if viper.GetBool(CHECK_RRSIG) {
		go RunTest("RRSIG", cache, origin, checkRRSIG, &wg, results)
		wg.Add(1)
	}

	// NSEC
	if viper.GetBool(CHECK_NSEC) {
		go RunTest("NSEC", cache, origin, checkNsec, &wg, results)
		wg.Add(1)
	}

	// NSEC3
	if viper.GetBool(CHECK_NSEC3) {
		go RunTest("NSEC3PARAM", cache, origin, checkNSEC3PARAM, &wg, results)
		go RunTest("NSEC3", cache, origin, checkNSEC3, &wg, results)
		wg.Add(2)
	}

	/* -------------- DONE WITH ALL CHECKS --------------	*/

	var result *Result = &Result{}
	go func() {
		for r := range results {
			result.Add(r)
		}
		wg.Done()
	}()
	wg.Wait()
	close(results)
	log.Infof("Total %d erros and %d warnings", result.errors, result.warnings)


	/* -------------- SET EXIT CODE  --------------	*/

	if result.errors > 0 {
		os.Exit(5)
	}
	if result.warnings > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func RunTest(name string, cache Cache, origin string, f func(Cache, string) Result, wg *sync.WaitGroup, c chan Result) {
	defer log.Trace(fmt.Sprintf("Testing %s", name)).Stop(nil)
	r := f(cache, origin)
	log.Infof("Test %s reported %d warnings and %d errors.", name, r.warnings, r.errors)
	c <- r
	wg.Done()
}
