package dslab.nameserver;

import dslab.util.Config;

import java.io.InputStream;
import java.io.PrintStream;
import java.rmi.AlreadyBoundException;
import java.rmi.NoSuchObjectException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class RootNameserver extends Nameserver implements INameserver, INameserverRemote{

    private Registry registry;

    /**
     * Creates a new server instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config      the component config
     * @param in          the input stream to read console input from
     * @param out         the output stream to write console output to
     */
    public RootNameserver(String componentId, Config config, InputStream in, PrintStream out) {
        super(componentId, config, in, out);
        this.createRegistry();
    }

    private void createRegistry() {
        try {
            registry = LocateRegistry.createRegistry(config.getInt("port"));
            // TODO: Why port = 0? (explain or fix)
            INameserverRemote remoteobject = (INameserverRemote) UnicastRemoteObject.exportObject(this, 0);
            registry.bind(config.getString("root_id"), remoteobject);
        } catch (RemoteException | AlreadyBoundException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void registerSelf(){
    }

    @Override
    public void shutdown() {
        super.shutdown();
        try {
            UnicastRemoteObject.unexportObject(registry, true);
        } catch (NoSuchObjectException e) {
            e.printStackTrace();
        }
    }
}
