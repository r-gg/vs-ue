# Secure Distributed Email Service with Java RMI

Implements:
 - Decentralized Naming Service
 - Secure Mail Access and Mail Transfer Protocols

## Decentralized naming service architecture and related workflow diagrams

![image](https://github.com/r-gg/vs-ue/assets/90387385/a2075479-8026-458e-b0a8-759ce6c34424)

![image](https://github.com/r-gg/vs-ue/assets/90387385/31415ce4-3e60-4ac5-bd18-e57962ba8e58)

![image](https://github.com/r-gg/vs-ue/assets/90387385/488dccdb-31dd-401e-9a86-1618db7fa760)

![image](https://github.com/r-gg/vs-ue/assets/90387385/90659c88-33b8-4d4d-b602-05857e02bc7d)

![image](https://github.com/r-gg/vs-ue/assets/90387385/11149a66-75fb-4cae-9078-9b7b5dc09734)

## How to run (Gradle)

### Compile & Test
Gradle is the build tool we are using. Here are some instructions:

Compile the project using the gradle wrapper:
```./gradlew assemble```

Compile and run the tests:
```./gradlew build```

### Run the applications
The gradle config contains several tasks that start application components for you.
You can list them with
```./gradlew tasks --all```
And search for 'Other tasks' starting with `run-`. For example, to run the monitoring server, execute:
```./gradlew --console=plain run-monitoring```
the `--console=plain` flag disables CLI features, like color output, that may break the console output when running a interactive application
