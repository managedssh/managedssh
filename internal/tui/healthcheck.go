package tui

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mylovelytools/managedssh/internal/host"
	"github.com/mylovelytools/managedssh/internal/sshclient"
	"github.com/mylovelytools/managedssh/internal/vault"
)

type hostHealthStatus int

const (
	healthUnknown hostHealthStatus = iota
	healthRed
	healthYellow
	healthGreen
)

func healthCheckAllCmd(hosts []host.Host, encKey []byte) tea.Cmd {
	copiedHosts := make([]host.Host, len(hosts))
	copy(copiedHosts, hosts)
	return func() tea.Msg {
		statuses := make(map[string]hostHealthStatus, len(copiedHosts))
		if len(copiedHosts) == 0 {
			return healthCheckDoneMsg{statuses: statuses}
		}

		workerCount := runtime.GOMAXPROCS(0)
		if workerCount < 1 {
			workerCount = 1
		}
		if workerCount > len(copiedHosts) {
			workerCount = len(copiedHosts)
		}

		type result struct {
			hostID string
			status hostHealthStatus
		}

		jobs := make(chan host.Host, len(copiedHosts))
		results := make(chan result, len(copiedHosts))

		var wg sync.WaitGroup
		wg.Add(workerCount)
		for i := 0; i < workerCount; i++ {
			go func() {
				defer wg.Done()
				for h := range jobs {
					results <- result{hostID: h.ID, status: checkHostHealth(h, encKey)}
				}
			}()
		}

		for _, h := range copiedHosts {
			jobs <- h
		}
		close(jobs)

		wg.Wait()
		close(results)
		for r := range results {
			statuses[r.hostID] = r.status
		}

		return healthCheckDoneMsg{statuses: statuses}
	}
}

func checkHostHealth(h host.Host, encKey []byte) hostHealthStatus {
	users := h.AccountNames()
	if len(users) == 0 {
		return healthRed
	}

	for _, username := range users {
		_, resolved, ok := h.ResolveAccount(username)
		if !ok {
			continue
		}

		var password []byte
		if resolved.AuthType == "password" && len(resolved.Password) > 0 {
			dec, err := vault.Decrypt(encKey, resolved.Password)
			if err != nil {
				continue
			}
			password = dec
		}

		var keyData []byte
		if resolved.AuthType == "key" && len(resolved.EncKey) > 0 {
			dec, err := vault.Decrypt(encKey, resolved.EncKey)
			if err != nil {
				zeroBytes(password)
				continue
			}
			keyData = dec
		}

		var keyPassphrase []byte
		if resolved.AuthType == "key" && len(resolved.EncKeyPass) > 0 {
			dec, err := vault.Decrypt(encKey, resolved.EncKeyPass)
			if err != nil {
				zeroBytes(password)
				zeroBytes(keyData)
				continue
			}
			keyPassphrase = dec
		}

		err := sshclient.Verify(sshclient.VerifyConfig{
			Host:          h.Hostname,
			Port:          h.Port,
			DialTimeout:   hostDialTimeout(h),
			User:          username,
			Password:      password,
			KeyPath:       resolved.KeyPath,
			KeyData:       keyData,
			KeyPassphrase: keyPassphrase,
		})
		zeroBytes(password)
		zeroBytes(keyData)
		zeroBytes(keyPassphrase)
		if err == nil {
			return healthGreen
		}

		var unknown *sshclient.UnknownHostError
		if errors.As(err, &unknown) {
			return healthGreen
		}
	}

	if hostRespondsToPing(h.Hostname) {
		return healthYellow
	}
	return healthRed
}

func hostRespondsToPing(hostname string) bool {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", hostname)
	if err := cmd.Run(); err == nil {
		return true
	}
	return false
}

func (m model) healthIndicator(status hostHealthStatus) string {
	switch status {
	case healthGreen:
		return lipHealthGreen.Render("●")
	case healthYellow:
		return lipHealthYellow.Render("●")
	case healthRed:
		return lipHealthRed.Render("●")
	default:
		if m.healthChecking {
			return lipHealthPending.Render("○")
		}
		return lipHealthUnknown.Render("○")
	}
}

func healthLabel(status hostHealthStatus) string {
	switch status {
	case healthGreen:
		return "Green (reachable)"
	case healthYellow:
		return "Yellow (ping OK, SSH uncertain)"
	case healthRed:
		return "Red (unreachable/invalid)"
	default:
		return "Unknown"
	}
}

func (m model) hostHealth(hostID string) hostHealthStatus {
	if status, ok := m.healthStatuses[hostID]; ok {
		return status
	}
	return healthUnknown
}
