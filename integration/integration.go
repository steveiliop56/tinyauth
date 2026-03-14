package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"time"
)

var ProxiesToTest = []string{"traefik", "nginx", "envoy"}

const (
	EnvFile    = ".env"
	ConfigFile = "config.yml"
)

const (
	TinyauthURL = "http://tinyauth.127.0.0.1.sslip.io"
	WhoamiURL   = "http://whoami.127.0.0.1.sslip.io"
)

const (
	DefaultUsername = "test"
	DefaultPassword = "password"
)

func main() {
	logFlag := flag.Bool("log", false, "enable stack logging")
	flag.Parse()

	rootFolder, err := os.Getwd()

	if err != nil {
		slog.Error("fail", "error", err)
		os.Exit(1)
	}

	slog.Info("root folder", "folder", rootFolder)

	integrationRoot := rootFolder

	if _, err := os.Stat(path.Join(rootFolder, ".git")); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Error("fail", "error", err)
			os.Exit(1)
		}
	} else {
		integrationRoot = path.Join(rootFolder, "integration")
	}

	slog.Info("integration root", "folder", integrationRoot)

	for _, proxy := range ProxiesToTest {
		slog.Info("begin", "proxy", proxy)
		compose := fmt.Sprintf("docker-compose.%s.yml", proxy)
		if _, err := os.Stat(path.Join(integrationRoot, compose)); err != nil {
			slog.Error("fail", "proxy", proxy, "error", err)
			os.Exit(1)
		}
		if err := createInstanceAndRunTests(compose, *logFlag, proxy, integrationRoot); err != nil {
			slog.Error("fail", "proxy", proxy, "error", err)
			os.Exit(1)
		}
		slog.Info("end", "proxy", proxy)
	}
}

func runTests(client *http.Client, name string) error {
	if err := testUnauthorized(client); err != nil {
		slog.Error("fail unauthorized test", "name", name)
		return err
	}

	slog.Info("unauthorized test passed", "name", name)

	if err := testLoggedIn(client); err != nil {
		slog.Error("fail logged in test", "name", name)
		return err
	}

	slog.Info("logged in test passed", "name", name)

	if err := testACLAllowed(client); err != nil {
		slog.Error("fail acl test", "name", name)
		return err
	}

	slog.Info("acl test passed", "name", name)

	return nil
}

func createInstanceAndRunTests(compose string, log bool, name string, integrationDir string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	composeFile := path.Join(integrationDir, compose)
	envFile := path.Join(integrationDir, EnvFile)
	cmdArgs := []string{"compose", "-f", composeFile, "--env-file", envFile, "up", "--build", "--force-recreate", "--remove-orphans"}
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)

	if log {
		setupCmdLogging(cmd)
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	defer func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	}()

	slog.Info("instance created", "name", name)

	if err := waitForHealthy(); err != nil {
		return err
	}

	slog.Info("instance healthy", "name", name)

	client := &http.Client{}

	if err := runTests(client, name); err != nil {
		return err
	}

	slog.Info("tests passed", "name", name)

	cmd.Process.Signal(os.Interrupt)

	if err := cmd.Wait(); cmd.ProcessState.ExitCode() != 130 && err != nil {
		return err
	}

	return nil
}

func setupCmdLogging(cmd *exec.Cmd) {
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			slog.Info("docker out", "stdout", scanner.Text())
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			slog.Error("docker out", "stderr", scanner.Text())
		}
	}()
}

func waitForHealthy() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	ticker := time.NewTicker(10 * time.Second)
	client := http.Client{}

	for {
		select {
		case <-ctx.Done():
			return errors.New("tinyauth not healthy after 5 minutes")
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, "GET", TinyauthURL+"/api/healthz", nil)
			if err != nil {
				return err
			}
			res, err := client.Do(req)
			if err != nil {
				continue
			}
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
}
