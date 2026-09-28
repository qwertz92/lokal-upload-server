package at.farfeleder.localupload;

/** Main-thread command generations reject callbacks from an earlier start or stop. */
final class RunState {
    private long generation;
    private boolean desired;

    long start() {
        if (desired) return -1;
        desired = true;
        return ++generation;
    }

    long stop() {
        desired = false;
        return ++generation;
    }

    boolean accepts(long command) {
        return generation == command;
    }

    boolean shouldRun() {
        return desired;
    }
}
