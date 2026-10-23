package main

// "bng sessions": the management API from the command line

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	sessAPI       string
	sessTokenFile string
	sessJSON      bool

	sessUsername, sessIP, sessMAC, sessPublic, sessType, sessState string
	sessUp, sessDown                                               string
)

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List, inspect and terminate subscriber sessions (PPPoE and IPoE)",
	Long: `Talks to the management API of a running BNG (--api-addr of "bng run").

Examples:
  bng sessions list
  bng sessions list --username gmedia1
  bng sessions list --public 198.18.0.1:1500     # who had this public IP:port
  bng sessions show 3f9a0c1d2e4b5a69
  bng sessions kill --username gmedia1
  bng sessions kill 3f9a0c1d2e4b5a69
  bng sessions rate 3f9a0c1d2e4b5a69 --up 10M --down 50M
  bng sessions summary`,
}

func init() {
	rootCmd.AddCommand(sessionsCmd)
	pf := sessionsCmd.PersistentFlags()
	pf.StringVar(&sessAPI, "api", "http://127.0.0.1:8090", "Management API of the BNG")
	pf.StringVar(&sessTokenFile, "token-file", "", "File with the API token (if the BNG has --api-token-file)")
	pf.BoolVar(&sessJSON, "json", false, "Print the API's JSON")

	filters := func(c *cobra.Command) {
		c.Flags().StringVar(&sessUsername, "username", "", "User name (IPoE: the MAC)")
		c.Flags().StringVar(&sessIP, "ip", "", "IPv4 address, or IPv6 address within the subscriber's prefixes")
		c.Flags().StringVar(&sessMAC, "mac", "", "Client MAC address")
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			q := sessQuery()
			if sessPublic != "" {
				q.Set("public", sessPublic)
			}
			if sessType != "" {
				q.Set("type", sessType)
			}
			if sessState != "" {
				q.Set("state", sessState)
			}
			var resp struct {
				Count    int          `json:"count"`
				Sessions []apiSession `json:"sessions"`
			}
			raw, err := sessCall(http.MethodGet, "/api/v1/sessions?"+q.Encode(), nil, &resp)
			if err != nil || sessJSON {
				return sessPrintRaw(raw, err)
			}
			printSessions(resp.Sessions)
			fmt.Printf("%d session(s)\n", resp.Count)
			return nil
		},
	}
	filters(list)
	list.Flags().StringVar(&sessPublic, "public", "", "CGNAT public address, optionally with port (IP or IP:port)")
	list.Flags().StringVar(&sessType, "type", "", "pppoe or ipoe")
	list.Flags().StringVar(&sessState, "state", "", "State, e.g. established")

	show := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one session (id = Acct-Session-Id)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var s apiSession
			raw, err := sessCall(http.MethodGet, "/api/v1/sessions/"+url.PathEscape(args[0]), nil, &s)
			if err != nil || sessJSON {
				return sessPrintRaw(raw, err)
			}
			printSession(s)
			return nil
		},
	}

	kill := &cobra.Command{
		Use:   "kill [<id>]",
		Short: "Terminate a session by id, or all sessions of a user, address or MAC",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var path string
			switch {
			case len(args) == 1:
				path = "/api/v1/sessions/" + url.PathEscape(args[0])
			case sessUsername != "" || sessIP != "" || sessMAC != "":
				path = "/api/v1/sessions?" + sessQuery().Encode()
			default:
				return fmt.Errorf("give a session id, --username, --ip or --mac")
			}
			var resp struct {
				Killed   int          `json:"killed"`
				Sessions []apiSession `json:"sessions"`
				Errors   []string     `json:"errors"`
			}
			raw, err := sessCall(http.MethodDelete, path, nil, &resp)
			if err != nil || sessJSON {
				return sessPrintRaw(raw, err)
			}
			for _, s := range resp.Sessions {
				fmt.Printf("killed %s %s %s %s\n", s.Type, s.ID, s.Username, s.IPv4)
			}
			for _, e := range resp.Errors {
				fmt.Printf("error: %s\n", e)
			}
			fmt.Printf("%d session(s) terminated\n", resp.Killed)
			return nil
		},
	}
	filters(kill)

	rate := &cobra.Command{
		Use:   "rate <id>",
		Short: "Change a session's speed limit (like a RADIUS CoA)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			up, err := parseBPS(sessUp)
			if err != nil {
				return fmt.Errorf("--up: %w", err)
			}
			down, err := parseBPS(sessDown)
			if err != nil {
				return fmt.Errorf("--down: %w", err)
			}
			body, _ := json.Marshal(map[string]uint64{"up_bps": up, "down_bps": down})
			var s apiSession
			raw, err := sessCall(http.MethodPatch, "/api/v1/sessions/"+url.PathEscape(args[0]), body, &s)
			if err != nil || sessJSON {
				return sessPrintRaw(raw, err)
			}
			fmt.Printf("%s %s: up %s down %s\n", s.ID, s.Username, formatBPS(s.UpRateBPS), formatBPS(s.DownRateBPS))
			return nil
		},
	}
	rate.Flags().StringVar(&sessUp, "up", "0", "Upload limit, e.g. 10M (0 = unlimited)")
	rate.Flags().StringVar(&sessDown, "down", "0", "Download limit, e.g. 50M (0 = unlimited)")

	summary := &cobra.Command{
		Use:   "summary",
		Short: "Session counts, CGNAT usage and data plane statistics",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := sessCall(http.MethodGet, "/api/v1/summary", nil, nil)
			return sessPrintRaw(raw, err)
		},
	}

	sessionsCmd.AddCommand(list, show, kill, rate, summary)
	// main prints the error; usage only with -h
	for _, c := range sessionsCmd.Commands() {
		c.SilenceUsage, c.SilenceErrors = true, true
	}
}

func sessQuery() url.Values {
	q := url.Values{}
	if sessUsername != "" {
		q.Set("username", sessUsername)
	}
	if sessIP != "" {
		q.Set("ip", sessIP)
	}
	if sessMAC != "" {
		q.Set("mac", sessMAC)
	}
	return q
}

// sessCall calls the API; the raw body is returned for --json and errors
func sessCall(method, path string, body []byte, out any) ([]byte, error) {
	req, err := http.NewRequest(method, strings.TrimRight(sessAPI, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sessTokenFile != "" {
		tok, err := os.ReadFile(sessTokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s: %s", resp.Status, e.Error)
		}
		return nil, fmt.Errorf("%s", resp.Status)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, err
		}
	}
	return raw, nil
}

func sessPrintRaw(raw []byte, err error) error {
	if err != nil {
		return err
	}
	os.Stdout.Write(raw)
	return nil
}

func printSessions(sessions []apiSession) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tUSERNAME\tSTATE\tIPV4\tIPV6 WAN\tNAT\tRATE UP/DOWN\tTRAFFIC UP/DOWN\tUPTIME")
	for _, s := range sessions {
		nat := "-"
		if s.NAT != nil {
			nat = fmt.Sprintf("%s:%d-%d", s.NAT.PublicIP, s.NAT.PortStart, s.NAT.PortEnd)
		}
		traffic := "-"
		if s.Counters != nil {
			traffic = formatBytes(s.Counters.UpBytes) + "/" + formatBytes(s.Counters.DownBytes)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s/%s\t%s\t%s\n",
			s.ID, s.Type, dash(s.Username), s.State, dash(s.IPv4), dash(s.IPv6WAN), nat,
			formatBPS(s.UpRateBPS), formatBPS(s.DownRateBPS), traffic,
			(time.Duration(s.UptimeSeconds) * time.Second).String())
	}
	w.Flush()
}

func printSession(s apiSession) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%s\t%s\n", k, v)
		}
	}
	row("ID", s.ID)
	row("Type", s.Type)
	if s.PPPoESessionID != 0 {
		row("PPPoE session", strconv.Itoa(int(s.PPPoESessionID)))
	}
	row("Username", s.Username)
	row("Auth", s.Auth)
	row("MAC", s.MAC)
	if s.VLAN != 0 {
		row("VLAN", strconv.Itoa(int(s.VLAN)))
	}
	row("Circuit-ID", s.CircuitID)
	row("State", s.State)
	row("IPv4", s.IPv4)
	row("IPv6 WAN prefix", s.IPv6WAN)
	row("IPv6 delegated", s.IPv6PD)
	if s.NAT != nil {
		row("CGNAT", fmt.Sprintf("%s ports %d-%d", s.NAT.PublicIP, s.NAT.PortStart, s.NAT.PortEnd))
	}
	row("Rate up/down", formatBPS(s.UpRateBPS)+" / "+formatBPS(s.DownRateBPS))
	if s.Since != nil {
		row("Since", s.Since.Local().Format(time.RFC3339))
		row("Uptime", (time.Duration(s.UptimeSeconds) * time.Second).String())
	}
	if s.SessionTimeout > 0 {
		row("Session-Timeout", (time.Duration(s.SessionTimeout) * time.Second).String())
	}
	if s.IdleTimeout > 0 {
		row("Idle-Timeout", (time.Duration(s.IdleTimeout) * time.Second).String())
	}
	if s.LeaseExpires != nil {
		row("Lease expires", s.LeaseExpires.Local().Format(time.RFC3339))
	}
	if c := s.Counters; c != nil {
		row("Upload", fmt.Sprintf("%s (%d packets, %d dropped by the limit)", formatBytes(c.UpBytes), c.UpPackets, c.UpDropped))
		row("Download", fmt.Sprintf("%s (%d packets, %d dropped by the limit)", formatBytes(c.DownBytes), c.DownPackets, c.DownDropped))
	}
	w.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatBPS(bps uint64) string {
	switch {
	case bps == 0:
		return "unlimited"
	case bps%1_000_000_000 == 0:
		return fmt.Sprintf("%dG", bps/1_000_000_000)
	case bps%1_000_000 == 0:
		return fmt.Sprintf("%dM", bps/1_000_000)
	case bps%1000 == 0:
		return fmt.Sprintf("%dk", bps/1000)
	}
	return strconv.FormatUint(bps, 10)
}

// parseBPS parses a rate such as 50M, 1.5G, 512k or 1000000 (bits/s)
func parseBPS(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "G"), strings.HasSuffix(s, "g"):
		mult, s = 1e9, s[:len(s)-1]
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "m"):
		mult, s = 1e6, s[:len(s)-1]
	case strings.HasSuffix(s, "K"), strings.HasSuffix(s, "k"):
		mult, s = 1e3, s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid rate %q", s)
	}
	return uint64(v * mult), nil
}
