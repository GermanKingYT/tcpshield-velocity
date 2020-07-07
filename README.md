# TCPShield

Edit #dotSpace:

- Only Velocity-Plugin
- Without Config (Cloud System don't need something to configure)
- Changed Logger to Log4j -> so cloudnet and other cloudsystems log info


TCPShield is the plugin for the same named DDoS mitigation service [TCPShield](https://tcpshield.com).

This plugin is responsible for validating clients join via the TCPShield network.
It also parses passed IP addresses so the server is aware of the real player IP address.  

### Compatibility

TCPShield is compatible with Paper, Spigot / CraftBukkit, BungeeCord and Velocity.

When using Spigot / CraftBukkit, [ProtocolLib](https://github.com/aadnk/ProtocolLib) needs to be installed. This is not necessary when Paper is being used.

### Setup
Setting up the plugin is easy as cake. Please follow [these](https://docs.tcpshield.com/onboarding-1/tcpshield-plugin) guidelines. 

### Compiling
In order to compile TCPShield, [install Gradle](https://docs.gradle.org/current/userguide/installation.html) and run the following command in the project folder:
```
gradle build
```

The dependencies should install themselves automatically. After the build has finished, the compiled jar file can be found under `/build/libs`.

### Support
See [Contact](https://docs.tcpshield.com/about-us)

### Contributors

These wonderful contributors have helped TCPShield make this plugin better! 

* [Fuzzlemann](https://github.com/Fuzzlemann)
* [RyanDeLap](https://github.com/RyanDeLap)
