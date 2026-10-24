// Validate saved analysis before a deliberately selected script runs read-only.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.util.GhidraProgramUtilities;

public class RusticGuard extends HeadlessScript {
    @Override
    public void run() throws Exception {
        if (!GhidraProgramUtilities.isAnalyzed(currentProgram)) {
            // Abort processing, not just this script: later scripts must not run.
            setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);
            throw new IllegalStateException("program is not already analysed");
        }
        if (!getScriptArgs()[0].equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);
            throw new IllegalStateException("project SHA256 differs from target binary; stale or packed project");
        }
    }
}
