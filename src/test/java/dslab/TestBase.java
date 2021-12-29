package dslab;

import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.ErrorCollector;
import org.junit.rules.Timeout;

/**
 * Contains a generic setup for a unit test.
 */
public class TestBase {

    @Rule
    public ErrorCollector err = new ErrorCollector();

    @Rule
    public Timeout timeout = new Timeout(30, TimeUnit.SECONDS); // fail tests that do not terminate after 30 seconds

    protected TestInputStream in;
    protected TestOutputStream out;

    protected TestInputStream monitorIn;
    protected TestOutputStream monitorOut;


    protected TestInputStream transferIn;
    protected TestOutputStream transferOut;

    protected TestInputStream transferIn2;
    protected TestOutputStream transferOut2;

    protected TestInputStream mailboxIn1;
    protected TestOutputStream mailboxOut1;

    protected TestInputStream mailboxIn2;
    protected TestOutputStream mailboxOut2;

    protected TestInputStream messageClientIn;
    protected TestOutputStream messageClientOut;

    @Before
    public void setUpBase() throws Exception {
        in = new TestInputStream();
        out = new TestOutputStream();

        monitorIn = new TestInputStream();
        monitorOut = new TestOutputStream();

        transferIn = new TestInputStream();
        transferOut = new TestOutputStream();

        transferIn2 = new TestInputStream();
        transferOut2 = new TestOutputStream();

        mailboxIn1 = new TestInputStream();
        mailboxOut1 = new TestOutputStream();

        mailboxIn2 = new TestInputStream();
        mailboxOut2 = new TestOutputStream();

        messageClientIn = new TestInputStream();
        messageClientOut = new TestOutputStream();
    }

}
