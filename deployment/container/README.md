# **Fail2Ban-UI Container**

A **containerized version of Fail2Ban-UI**, allowing easy deployment for managing Fail2Ban configurations, logs, and bans via a web-based UI.


## How to Build the Image

```bash
podman build -t fail2ban-ui --target=standalone-ui .
```

For **Docker**, just replace `podman` with `docker` for every command, e.g.:
```bash
docker build -t fail2ban-ui --target=standalone-ui .
```


## For SELinux enabled systems
If SELinux is enabled, you must apply the required SELinux policies to allow the container to communicate with Fail2Ban.
The policies are located here: "`./SELinux/`"

Apply the prebuilt SELinux Modules with:

```bash
semodule -i fail2ban-container-ui.pp
semodule -i fail2ban-container-client.pp
```

### Manually Compile and Install SELinux Rules

If you want to change or compile the SELinux rules by yourself run:

```bash
checkmodule -M -m -o fail2ban-container-client.mod fail2ban-container-client.te
semodule_package -o fail2ban-container-client.pp -m fail2ban-container-client.mod
semodule -i fail2ban-container-client.pp
```


## How to Run the Container

Create the needed folder to store the fail2ban-ui config first:
```bash
mkdir /opt/podman-fail2ban-ui
```

Then run the container with the following prompt in background (-d) as test. For a productive container setup please use a systemd service.
```bash
podman run -d \
  --name fail2ban-ui \
  --network=host \
  -v /opt/podman-fail2ban-ui:/config:Z \
  -v /etc/fail2ban:/etc/fail2ban:Z \
  -v /var/log:/var/log:ro \
  -v /var/run/fail2ban:/var/run/fail2ban \
  -v /usr/share/GeoIP:/usr/share/GeoIP:ro \
  localhost/fail2ban-ui
```

### Stop and Remove Container
Stop the running container:
```bash
podman stop fail2ban-ui
```
Remove the container:
```bash
podman rm fail2ban-ui
```

## Troubleshooting

### UI Not Accessible
- Ensure port **8080 (or custom port)** is **not blocked** by the firewall. (e.g. firewalld)
- Check container logs:
```bash
podman logs fail2ban-ui
```
- Ensure **Fail2Ban UI is running** inside the container:
```bash
podman exec -it fail2ban-ui ps aux
```

## Contact & Support
For issues, contributions, or feature requests, visit our GitHub repository:  
🔗 [GitHub Issues](https://github.com/swissmakers/fail2ban-ui/issues)

For enterprise support, visit:  
🔗 [Swissmakers GmbH](https://swissmakers.ch)
