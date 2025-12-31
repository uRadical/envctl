package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"envctl.dev/go/envctl/internal/audit"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View audit logs",
	Long: `View and filter audit logs.

In interactive mode, use arrow keys to navigate, / to search,
f to filter, and q to quit.

Examples:
  envctl log
  envctl log --level error
  envctl log --since 1h
  envctl log --follow
  envctl log --format json`,
	RunE: runLog,
}

func init() {
	logCmd.Flags().String("level", "", "filter by level (debug, info, warn, error)")
	logCmd.Flags().String("since", "24h", "show logs since (e.g., 5m, 1h, 24h, 2025-01-15)")
	logCmd.Flags().String("until", "", "show logs until")
	logCmd.Flags().String("category", "", "filter by category (identity, project, secrets, etc.)")
	logCmd.Flags().String("project", "", "filter by project")
	logCmd.Flags().String("search", "", "search text")
	logCmd.Flags().String("format", "tui", "output format (tui, table, json)")
	logCmd.Flags().Bool("follow", false, "follow new logs (like tail -f)")
	logCmd.Flags().Int("limit", 1000, "maximum entries to show")
	rootCmd.AddCommand(logCmd)
}

func runLog(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	follow, _ := cmd.Flags().GetBool("follow")

	// Build query options
	opts := buildLogQueryOpts(cmd)

	switch format {
	case "json":
		return outputLogJSON(opts)
	case "table":
		return outputLogTable(opts)
	case "tui":
		if follow {
			return runLogFollowMode(opts)
		}
		return runLogTUI(opts)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func buildLogQueryOpts(cmd *cobra.Command) audit.QueryOpts {
	opts := audit.QueryOpts{}

	if level, _ := cmd.Flags().GetString("level"); level != "" {
		opts.Level = strings.ToUpper(level)
	}

	if since, _ := cmd.Flags().GetString("since"); since != "" {
		if t, err := parseLogTimeArg(since); err == nil {
			opts.Since = &t
		}
	}

	if until, _ := cmd.Flags().GetString("until"); until != "" {
		if t, err := parseLogTimeArg(until); err == nil {
			opts.Until = &t
		}
	}

	opts.Category, _ = cmd.Flags().GetString("category")
	opts.Project, _ = cmd.Flags().GetString("project")
	opts.Search, _ = cmd.Flags().GetString("search")
	opts.Limit, _ = cmd.Flags().GetInt("limit")

	return opts
}

func parseLogTimeArg(s string) (time.Time, error) {
	// Try duration format (e.g., "1h", "5m", "24h")
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}

	// Try date formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	}

	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s", s)
}

// --- TUI Model ---

type logModel struct {
	events      []audit.Event
	viewport    viewport.Model
	searchInput textinput.Model
	filter      audit.QueryOpts
	width       int
	height      int
	searching   bool
	selected    int
	showDetails bool
	ready       bool
}

func newLogModel(opts audit.QueryOpts) logModel {
	ti := textinput.New()
	ti.Placeholder = "Search..."
	ti.Width = 30

	return logModel{
		filter:      opts,
		searchInput: ti,
	}
}

func (m logModel) Init() tea.Cmd {
	return m.loadLogs
}

func (m logModel) loadLogs() tea.Msg {
	events := audit.Default().Query(m.filter)
	return logsLoadedMsg{events: events}
}

type logsLoadedMsg struct {
	events []audit.Event
}

func (m logModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerHeight := 4
		footerHeight := 2
		m.viewport = viewport.New(msg.Width, msg.Height-headerHeight-footerHeight)
		m.viewport.SetContent(m.renderLogs())
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		if m.searching {
			switch msg.String() {
			case "enter":
				m.filter.Search = m.searchInput.Value()
				m.searching = false
				return m, m.loadLogs
			case "esc":
				m.searching = false
				m.searchInput.SetValue("")
				return m, nil
			}
			var cmd tea.Cmd
			m.searchInput, cmd = m.searchInput.Update(msg)
			return m, cmd
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "/":
			m.searching = true
			m.searchInput.Focus()
			return m, nil
		case "up", "k":
			if m.selected > 0 {
				m.selected--
				m.viewport.SetContent(m.renderLogs())
			}
		case "down", "j":
			if m.selected < len(m.events)-1 {
				m.selected++
				m.viewport.SetContent(m.renderLogs())
			}
		case "enter":
			m.showDetails = !m.showDetails
			m.viewport.SetContent(m.renderLogs())
		case "r":
			return m, m.loadLogs
		case "1":
			m.filter.Level = ""
			return m, m.loadLogs
		case "2":
			m.filter.Level = audit.LevelDebug
			return m, m.loadLogs
		case "3":
			m.filter.Level = audit.LevelInfo
			return m, m.loadLogs
		case "4":
			m.filter.Level = audit.LevelWarn
			return m, m.loadLogs
		case "5":
			m.filter.Level = audit.LevelError
			return m, m.loadLogs
		case "c":
			// Cycle through categories
			m.filter.Category = nextCategory(m.filter.Category)
			return m, m.loadLogs
		case "esc":
			// Clear all filters
			m.filter.Level = ""
			m.filter.Category = ""
			m.filter.Search = ""
			m.filter.Project = ""
			return m, m.loadLogs
		case "pgup":
			m.viewport.ViewUp()
		case "pgdown":
			m.viewport.ViewDown()
		case "home":
			m.selected = 0
			m.viewport.SetContent(m.renderLogs())
		case "end":
			if len(m.events) > 0 {
				m.selected = len(m.events) - 1
				m.viewport.SetContent(m.renderLogs())
			}
		}

	case logsLoadedMsg:
		m.events = msg.events
		m.selected = 0
		if m.ready {
			m.viewport.SetContent(m.renderLogs())
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func nextCategory(current string) string {
	categories := append([]string{""}, audit.AllCategories()...)
	for i, c := range categories {
		if c == current {
			return categories[(i+1)%len(categories)]
		}
	}
	return ""
}

func (m logModel) View() string {
	if !m.ready {
		return "Loading..."
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Separator
	sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	b.WriteString(sepStyle.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	// Logs viewport
	b.WriteString(m.viewport.View())
	b.WriteString("\n")

	// Footer
	b.WriteString(sepStyle.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	if m.searching {
		b.WriteString("Search: ")
		b.WriteString(m.searchInput.View())
	} else {
		helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
		b.WriteString(helpStyle.Render("[↑↓] Navigate  [Enter] Details  [/] Search  [1-5] Level  [c] Category  [r] Refresh  [q] Quit"))
	}

	return b.String()
}

func (m logModel) renderHeader() string {
	titleStyle := lipgloss.NewStyle().Bold(true)
	filterStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	countStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))

	levelStr := "ALL"
	if m.filter.Level != "" {
		levelStr = m.filter.Level
	}

	categoryStr := "ALL"
	if m.filter.Category != "" {
		categoryStr = m.filter.Category
	}

	header := titleStyle.Render("Audit Logs") + "  "
	header += filterStyle.Render(fmt.Sprintf("Level: [%s]  Category: [%s]", levelStr, categoryStr))

	if m.filter.Search != "" {
		header += filterStyle.Render(fmt.Sprintf("  Search: [%s]", m.filter.Search))
	}
	if m.filter.Project != "" {
		header += filterStyle.Render(fmt.Sprintf("  Project: [%s]", m.filter.Project))
	}

	header += "  " + countStyle.Render(fmt.Sprintf("(%d entries)", len(m.events)))

	return header
}

func (m logModel) renderLogs() string {
	if len(m.events) == 0 {
		emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Italic(true)
		return emptyStyle.Render("No log entries found matching the current filters.")
	}

	var b strings.Builder

	// Styles
	timeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	debugStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	selectedStyle := lipgloss.NewStyle().Background(lipgloss.Color("237"))
	actionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("5"))

	for i, event := range m.events {
		// Time
		timeStr := event.Timestamp.Format("15:04:05")
		line := timeStyle.Render(timeStr) + "  "

		// Level with color
		var levelStyle lipgloss.Style
		switch event.Level {
		case audit.LevelDebug:
			levelStyle = debugStyle
		case audit.LevelInfo:
			levelStyle = infoStyle
		case audit.LevelWarn:
			levelStyle = warnStyle
		case audit.LevelError:
			levelStyle = errorStyle
		default:
			levelStyle = infoStyle
		}
		line += levelStyle.Render(fmt.Sprintf("%-5s", event.Level)) + "  "

		// Action
		line += actionStyle.Render(fmt.Sprintf("%-22s", event.Action)) + "  "

		// Summary
		line += m.formatSummary(event)

		// Truncate if too long
		if len(line) > m.width-2 {
			line = line[:m.width-5] + "..."
		}

		// Selected row
		if i == m.selected {
			// Pad to full width for selection highlight
			padding := m.width - len(stripAnsi(line))
			if padding > 0 {
				line += strings.Repeat(" ", padding)
			}
			line = selectedStyle.Render(line)
		}

		b.WriteString(line)
		b.WriteString("\n")

		// Show details for selected
		if i == m.selected && m.showDetails {
			b.WriteString(m.renderDetails(event))
			b.WriteString("\n")
		}
	}

	return b.String()
}

// stripAnsi removes ANSI escape codes for length calculation
func stripAnsi(s string) string {
	result := s
	for {
		start := strings.Index(result, "\x1b[")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}

func (m logModel) formatSummary(e audit.Event) string {
	switch e.Category {
	case audit.CategorySecrets:
		if e.Target != "" {
			if strings.Contains(e.Action, "sent") {
				return fmt.Sprintf("%s → %s", e.Env, e.Target)
			}
			return fmt.Sprintf("%s ← %s", e.Env, e.Target)
		}
		if e.Peer != "" {
			return fmt.Sprintf("%s ← %s", e.Env, e.Peer)
		}
		return e.Env
	case audit.CategoryPeer:
		if e.Peer != "" {
			addr := ""
			if a, ok := e.Details["addr"]; ok {
				addr = fmt.Sprintf(" (%s)", a)
			}
			return e.Peer + addr
		}
	case audit.CategoryChain:
		if blocks, ok := e.Details["blocks"]; ok {
			return fmt.Sprintf("%s (+%v blocks)", e.Project, blocks)
		}
		return e.Project
	case audit.CategoryMember:
		return fmt.Sprintf("%s - %s", e.Project, e.Target)
	case audit.CategoryIdentity:
		if e.Target != "" {
			return e.Target
		}
	case audit.CategoryDaemon:
		if version, ok := e.Details["version"]; ok {
			return fmt.Sprintf("v%s", version)
		}
	}

	if e.Project != "" {
		if e.Env != "" {
			return fmt.Sprintf("%s/%s", e.Project, e.Env)
		}
		return e.Project
	}
	return e.Message
}

func (m logModel) renderDetails(e audit.Event) string {
	detailStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		PaddingLeft(4)

	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))

	var lines []string
	lines = append(lines, keyStyle.Render("Message: ")+e.Message)

	if e.Project != "" {
		lines = append(lines, keyStyle.Render("Project: ")+e.Project)
	}
	if e.Env != "" {
		lines = append(lines, keyStyle.Render("Env: ")+e.Env)
	}
	if e.Target != "" {
		lines = append(lines, keyStyle.Render("Target: ")+e.Target)
	}
	if e.Peer != "" {
		lines = append(lines, keyStyle.Render("Peer: ")+e.Peer)
	}
	if e.Actor != "" {
		lines = append(lines, keyStyle.Render("Actor: ")+e.Actor)
	}
	if e.Error != "" {
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
		lines = append(lines, keyStyle.Render("Error: ")+errorStyle.Render(e.Error))
	}
	if len(e.Details) > 0 {
		for k, v := range e.Details {
			lines = append(lines, keyStyle.Render(k+": ")+fmt.Sprintf("%v", v))
		}
	}

	return detailStyle.Render(strings.Join(lines, "\n"))
}

func runLogTUI(opts audit.QueryOpts) error {
	p := tea.NewProgram(newLogModel(opts), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// --- JSON Output ---

func outputLogJSON(opts audit.QueryOpts) error {
	events := audit.Default().Query(opts)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(events)
}

// --- Table Output ---

func outputLogTable(opts audit.QueryOpts) error {
	events := audit.Default().Query(opts)

	fmt.Printf("%-10s %-5s %-22s %s\n", "TIME", "LEVEL", "ACTION", "DETAILS")
	fmt.Println(strings.Repeat("-", 80))

	for _, e := range events {
		timeStr := e.Timestamp.Format("15:04:05")
		details := formatLogTableDetails(e)
		fmt.Printf("%-10s %-5s %-22s %s\n", timeStr, e.Level, e.Action, details)
	}

	return nil
}

func formatLogTableDetails(e audit.Event) string {
	parts := []string{}
	if e.Project != "" {
		parts = append(parts, "project="+e.Project)
	}
	if e.Env != "" {
		parts = append(parts, "env="+e.Env)
	}
	if e.Target != "" {
		parts = append(parts, "target="+e.Target)
	}
	if e.Peer != "" {
		parts = append(parts, "peer="+e.Peer)
	}
	if e.Error != "" {
		parts = append(parts, "error="+e.Error)
	}
	if len(parts) == 0 {
		return e.Message
	}
	return strings.Join(parts, " ")
}

// --- Follow Mode ---

func runLogFollowMode(opts audit.QueryOpts) error {
	// Initial load
	events := audit.Default().Query(opts)
	for _, e := range events {
		printLogFollowEvent(e)
	}

	fmt.Println("--- Following logs (Ctrl+C to stop) ---")

	// Watch for new events
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastTime := time.Now()

	for range ticker.C {
		since := lastTime
		queryOpts := opts
		queryOpts.Since = &since
		queryOpts.Limit = 100

		newEvents := audit.Default().Query(queryOpts)
		for _, e := range newEvents {
			if e.Timestamp.After(lastTime) {
				printLogFollowEvent(e)
				lastTime = e.Timestamp
			}
		}
	}

	return nil
}

func printLogFollowEvent(e audit.Event) {
	timeStr := e.Timestamp.Format("15:04:05")

	// Color level
	levelColor := ""
	switch e.Level {
	case audit.LevelDebug:
		levelColor = "\033[90m" // gray
	case audit.LevelInfo:
		levelColor = "\033[34m" // blue
	case audit.LevelWarn:
		levelColor = "\033[33m" // yellow
	case audit.LevelError:
		levelColor = "\033[31m" // red
	}
	resetColor := "\033[0m"

	fmt.Printf("%s  %s%-5s%s  %-22s  %s\n",
		timeStr, levelColor, e.Level, resetColor, e.Action, e.Message)
}
