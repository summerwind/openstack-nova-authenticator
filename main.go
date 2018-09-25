package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/summerwind/openstack-nova-authenticator/auth"
	"github.com/summerwind/openstack-nova-authenticator/config"
	yaml "gopkg.in/yaml.v2"
)

var (
	VERSION = "0.0.1"
	COMMIT  = "HEAD"
)

var (
	attestor *auth.Attestor
	issuer   *auth.Issuer
)

// loadConfig loads the specified configuration file and returns
// config.
func loadConfig(configPath string) (*config.Config, error) {
	buf, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	c := config.New()
	err = yaml.Unmarshal(buf, &c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// sendError sends a JSON formatted error response.
func sendError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, "{\"error\":\"%s\"}", msg)
}

// accessLog writes a record of access log to the stdio.
func accessLog(instanceID, roleName, addr *string, status *int) {
	log.Printf("status:%d instance_id:%s role:%s remote_addr:%s", *status, *instanceID, *roleName, *addr)
}

// authHandler handles a request for authentication.
func authHandler(w http.ResponseWriter, r *http.Request) {
	instanceID := r.FormValue("instance_id")
	roleName := r.FormValue("role")
	status := 200

	defer accessLog(&instanceID, &roleName, &r.RemoteAddr, &status)

	if r.Method != "POST" {
		status = 405
		sendError(w, "Method Not Allowed", status)
		return
	}

	if instanceID == "" {
		status = 405
		sendError(w, "Invalid instance ID", status)
		return
	}
	if roleName == "" {
		sendError(w, "Invalid role", 400)
		return
	}

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		status = 500
		sendError(w, "Invalid remote address", status)
		return
	}

	instance, err := attestor.Attest(instanceID, roleName, addr)
	if err != nil {
		status = 400
		sendError(w, fmt.Sprintf("Authentication failed: %s", err), status)
		fmt.Fprintf(os.Stderr, "Attestation failed: %s\n", err)
		return
	}

	t, err := issuer.NewToken(instance, roleName)
	if err != nil {
		status = 500
		sendError(w, "Internal Server error", status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, "{\"token\":\"%s\"}", t)
}

// run starts the HTTP server to process authentication.
func run(cmd *cobra.Command, args []string) error {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}

	c, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	attestor, err = auth.NewAttestor(c)
	if err != nil {
		return err
	}

	issuer, err = auth.NewIssuer(c)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", authHandler)

	server := &http.Server{
		Addr:    c.Listen,
		Handler: mux,
	}

	go func() {
		if c.TLS.CertFile != "" {
			server.ListenAndServeTLS(c.TLS.CertFile, c.TLS.KeyFile)
		} else {
			server.ListenAndServe()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	var cmd = &cobra.Command{
		Use:   "openstack-nova-authenticator",
		Short: "Instance authenticator for OpenStack.",
		RunE:  run,

		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringP("config", "c", "config.yml", "Path to the configuration file")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
