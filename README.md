# Info and Notes on DS UE Assignment 1

## Concurrency and Synchronization "Architecture"
TransferServer:
- 1 AcceptThread
  - n DMTP-Receive-Threads
- 1 BlockingQueue
- m TransferThreads
- 1 Shell

MailboxServer:
- 1 DMTP-AcceptThread
  - n DMTP-Receive-Threads
- 1 DMAP-AcceptThread
  - m DMAP-HandlerThreads
- 1 ConcurrentHashMap<UserName, Pair<Password,Inbox>>
  - Inbox w/ synchronized add(msg)/delete(i)/... methods
- 1 Shell

MonitoringServer
- 1 Shell
- 1 ListenThread

## Using gradle

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
