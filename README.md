<div align="center">
  
![](https://img.shields.io/github/languages/count/rexionmars/tigerctl?color=red)
![](https://img.shields.io/github/issues-pr/rexionmars/tigerctl)
![](https://img.shields.io/github/issues/rexionmars/tigerctl?color=pink)
![](https://img.shields.io/github/issues-pr/rexionmars/tigerctl?color=orange)

<img src="docs/img/tigerctl.png" alt="Snake logo">

</div

A CLI tool for fast password management with encrypted data

## Instalation
```sh
git clone https://github.com/rexionmars/tigerctl
```
```sh
cd tigerctl && go build
sudo cp tigerctl /bin
```
Or view release lists:<br>
https://github.com/rexionmars/tigerctl/releases/tag/Release

## Usage
```sh
tigerctl 
Usage: tigerctl <command> <service>
Available commands:
 get  <service>: Retrieves the password for the specified service.
 set  <service>: Sets a new password for the specified service.
 rm   <service>: Removes the specified service.
 edit <service>: Edits the email and password for the specified service.
 list: Lists all saved services.
```
```sh
# Add new service
tigerctl set google
  Email: youremail@foo.com
  Password: yourpassword

# View all services
tigerctl list
Saved services:
 - google

# Get credentials
tigerctl get google
Email: youremail@foo.com
Password: yourpassword*

# Remove servive
tigerctl rm google

# Edit service
tigerctl edit google
```
