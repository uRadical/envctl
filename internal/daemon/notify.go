package daemon

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
)

// Notifier interface for desktop notifications
type Notifier interface {
	Notify(title, body string) error
}

// NewNotifier returns a platform-specific notifier
func NewNotifier() Notifier {
	switch runtime.GOOS {
	case "darwin":
		return &darwinNotifier{}
	case "linux":
		return &linuxNotifier{}
	case "windows":
		return &windowsNotifier{}
	default:
		return &nullNotifier{}
	}
}

// darwinNotifier sends notifications on macOS using osascript
type darwinNotifier struct{}

func (n *darwinNotifier) Notify(title, body string) error {
	script := fmt.Sprintf(`display notification %q with title %q`, body, title)
	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		slog.Debug("macOS notification failed", "error", err)
		return err
	}
	return nil
}

// linuxNotifier sends notifications on Linux using notify-send
type linuxNotifier struct{}

func (n *linuxNotifier) Notify(title, body string) error {
	// Try notify-send first (most common)
	if path, err := exec.LookPath("notify-send"); err == nil {
		cmd := exec.Command(path, title, body)
		if err := cmd.Run(); err != nil {
			slog.Debug("notify-send failed", "error", err)
			// Fall through to try other methods
		} else {
			return nil
		}
	}

	// Try zenity as fallback
	if path, err := exec.LookPath("zenity"); err == nil {
		cmd := exec.Command(path, "--notification", "--title="+title, "--text="+body)
		if err := cmd.Run(); err != nil {
			slog.Debug("zenity notification failed", "error", err)
		} else {
			return nil
		}
	}

	// Try kdialog for KDE
	if path, err := exec.LookPath("kdialog"); err == nil {
		cmd := exec.Command(path, "--passivepopup", body, "5", "--title", title)
		if err := cmd.Run(); err != nil {
			slog.Debug("kdialog notification failed", "error", err)
		} else {
			return nil
		}
	}

	slog.Debug("No notification method available on Linux")
	return fmt.Errorf("no notification method available")
}

// windowsNotifier sends notifications on Windows using PowerShell
type windowsNotifier struct{}

func (n *windowsNotifier) Notify(title, body string) error {
	script := fmt.Sprintf(`
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

		$template = @"
		<toast>
			<visual>
				<binding template="ToastText02">
					<text id="1">%s</text>
					<text id="2">%s</text>
				</binding>
			</visual>
		</toast>
"@
		$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
		$xml.LoadXml($template)
		$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
		[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("envctl").Show($toast)
	`, title, body)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Run(); err != nil {
		slog.Debug("PowerShell toast notification failed", "error", err)
		// Fall back to simple balloon tip
		return n.notifyBalloon(title, body)
	}
	return nil
}

// notifyBalloon uses a simpler balloon notification as fallback
func (n *windowsNotifier) notifyBalloon(title, body string) error {
	script := fmt.Sprintf(`
		Add-Type -AssemblyName System.Windows.Forms
		$balloon = New-Object System.Windows.Forms.NotifyIcon
		$balloon.Icon = [System.Drawing.SystemIcons]::Information
		$balloon.BalloonTipIcon = 'Info'
		$balloon.BalloonTipTitle = '%s'
		$balloon.BalloonTipText = '%s'
		$balloon.Visible = $true
		$balloon.ShowBalloonTip(5000)
	`, title, body)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run()
}

// nullNotifier is a no-op notifier for unsupported platforms
type nullNotifier struct{}

func (n *nullNotifier) Notify(title, body string) error {
	slog.Debug("Notifications not supported on this platform",
		"title", title,
		"body", body,
	)
	return nil
}

// NotificationService manages notification sending for the daemon
type NotificationService struct {
	notifier Notifier
	enabled  bool
}

// NewNotificationService creates a new notification service
func NewNotificationService(enabled bool) *NotificationService {
	return &NotificationService{
		notifier: NewNotifier(),
		enabled:  enabled,
	}
}

// SetEnabled enables or disables notifications
func (s *NotificationService) SetEnabled(enabled bool) {
	s.enabled = enabled
}

// Notify sends a notification if enabled
func (s *NotificationService) Notify(title, body string) error {
	if !s.enabled {
		return nil
	}
	return s.notifier.Notify(title, body)
}

// NotifyRequest sends a notification about an incoming request
func (s *NotificationService) NotifyRequest(from, env string) error {
	title := "envctl - Request Received"
	body := fmt.Sprintf("%s is requesting your %s env", from, env)
	return s.Notify(title, body)
}

// NotifyEnvReceived sends a notification about received environment
func (s *NotificationService) NotifyEnvReceived(from, env string, count int) error {
	title := "envctl - Environment Received"
	body := fmt.Sprintf("Received %s env from %s (%d variables)", env, from, count)
	return s.Notify(title, body)
}

// NotifyProposal sends a notification about a new proposal
func (s *NotificationService) NotifyProposal(team, action string) error {
	title := "envctl - Approval Required"
	body := fmt.Sprintf("New %s proposal for team %s", action, team)
	return s.Notify(title, body)
}

// NotifyPeerConnected sends a notification about peer connection
func (s *NotificationService) NotifyPeerConnected(peerName string) error {
	title := "envctl - Peer Connected"
	body := fmt.Sprintf("%s is now online", peerName)
	return s.Notify(title, body)
}
