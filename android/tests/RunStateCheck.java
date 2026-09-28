package at.farfeleder.localupload;

public final class RunStateCheck {
    private RunStateCheck() {}

    public static void main(String[] args) {
        RunState state = new RunState();
        long first = state.start();
        assert state.shouldRun() && state.accepts(first);
        assert state.start() == -1 : "Duplicate launch must be idempotent";
        long stop = state.stop();
        assert !state.shouldRun() && !state.accepts(first) && state.accepts(stop);
        long restart = state.start();
        assert !state.accepts(stop) : "Old shutdown must not stop the new run";
        assert !state.accepts(first) : "Old startup must not publish a stale URL";
        assert state.accepts(restart) && state.shouldRun();
        state.stop();
        assert !state.accepts(restart) && !state.shouldRun();
        System.out.println("Start/stop generation checks passed");
    }
}
