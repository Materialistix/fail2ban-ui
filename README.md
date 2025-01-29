# Fail2ban UI

A Swissmade, management interface for [Fail2ban](https://www.fail2ban.org/).
It provides a modern dashboard to currently:

- View all Fail2ban jails and banned IPs
- Unban IP addresses directly
- Edit and save jail/filter configs
- Reload Fail2ban when needed
- See recent ban events
- More to come...

Built by [Swissmakers GmbH](https://swissmakers.ch).

---

## Features

1. **Basic Real-time Dashboard**  
   - Automatically loads all jails, banned IPs, and last 5 ban events on page load.

2. **Unban IPs**  
   - Unban any blocked IP without needing direct CLI access.

3. **Edit Fail2ban Configs**  
   - Click on any jail name to open a modal with raw config contents (from `/etc/fail2ban/filter.d/*.conf` by default).  
   - Save changes, then reload Fail2ban.

4. **Responsive UI**  
   - Built with [Bootstrap 5](https://getbootstrap.com/).

5. **Loading Overlay & Reload Banner**  
   - Displays a loading spinner for all operations.  
   - Shows a reload banner when configuration changes occur.

---

## Requirements

- **Go 1.22.9+** (module-compatible)
- **Fail2ban** installed and running
- **Linux** environment with permissions to run `fail2ban-client` and read/write config files (e.g., `/etc/fail2ban/filter.d/`)
- Sufficient privileges to reload Fail2ban (run as `sudo` or configure your system accordingly)

---

## Installation & Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/swissmakers/fail2ban-ui.git
   cd fail2ban-ui
   ```

2. **Initialize or tidy Go modules** (optional if you already have them):
   ```bash
   go mod tidy
   ```

3. **Run the server** (with `sudo` if necessary):
   ```bash
   sudo go run ./cmd/server
   ```
   By default, it listens on port `:8080`.

4. **Open the UI**:
   - Visit [http://localhost:8080/](http://localhost:8080/) (or replace `localhost` with your server IP).

5. **Manage Fail2ban**:
   - See jails and banned IPs on the main dashboard
   - Unban IPs via the “Unban” button
   - Edit jail configs by clicking the jail name
   - Save your changes, then **reload** Fail2ban using the top banner prompt

---

## Security Considerations

- Running this UI typically requires **root** or sudo privileges to execute `fail2ban-client` and manipulate config files.  
- Consider restricting network access or using authentication (e.g., reverse proxy with Basic Auth or a firewall rule) to ensure only authorized users can access the dashboard.  
- Make sure your Fail2ban logs and configs aren’t exposed publicly.

---

## Contributing

We welcome pull requests and issues! Please open an [issue](./issues) if you find a bug or have a feature request.

1. **Fork** this repository
2. **Create** a new branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -m 'Add some feature'`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Open** a pull request

---

## License

```text
GNU GENERAL PUBLIC LICENSE, Version 3
```